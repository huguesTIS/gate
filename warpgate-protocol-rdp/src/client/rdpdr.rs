//! Target-facing RDPDR ([MS-RDPEFS]/[MS-RDPESC]) client-role backend.
//!
//! Phase 2 of the RDP + Hello smart-card bridge (see `ARCHITECTURE_TECHNIQUE.md` §10):
//! announces a smart card device to the target and answers its I/O requests, proving the
//! target-facing leg independently of the viewer-facing one (Phase 1, `server::rdpdr`).
//!
//! Unlike the server role, `ironrdp-rdpdr` already implements the full client-role state
//! machine (`Rdpdr`) — RDPDR's grammar is "client announces devices, server drives I/O
//! against them," so the client role is the one every embedder needs, upstream included.
//! What's missing (and what this module supplies) is [`RdpdrBackend`]: `ironrdp-rdpdr`
//! decodes each incoming smart-card call and hands it to the backend, but leaves it up to
//! the embedder to decide the answer and push it back out.
//!
//! **Phase 3, real relay:** `EstablishContext`/`ListReaders`/`GetStatusChange` — the "cheap"
//! calls per `ARCHITECTURE_TECHNIQUE.md` §10's build order — are now forwarded to the
//! viewer's real reader via [`ScardRelayState`] when one is wired up (native RDP server front
//! end only; the browser path has no viewer-facing RDPDR channel to relay through, see
//! `lib::connect`'s doc comment). Every other call — and these three when no relay is
//! configured, or the relay comes back empty — still gets Phase 2's synchronous "no card
//! present" answer, so a target never hangs waiting for a call this bridge doesn't cover yet
//! (`Connect`/`Transmit`, the real APDU path, still fail cleanly with `NoSmartcard` — nothing
//! relays those yet, deliberately: they're last in the build order, and only matter once a
//! `Connect` can succeed, which needs `Transmit` relayed too or there's nothing to connect
//! *to*).
//!
//! **Why the response can't just be `handle_scard_call`'s return value**: the trait method
//! returns `PduResult<()>`, not `PduResult<Vec<SvcMessage>>` like the other backend
//! callbacks — deliberately, since a real relay's answer depends on a round trip to the
//! viewer's own reader that hasn't happened yet by the time this call returns. This resolves
//! the "exact async push API" open question noted in `ARCHITECTURE_TECHNIQUE.md` §10: the
//! backend holds an [`UnboundedSender<SvcMessage>`] and pushes the answer whenever it's
//! ready; `client::active_loop` drains the paired receiver on its next iteration and frames
//! it via `ActiveStage::process_svc_processor_messages`, the same shape already used for
//! `ClipboardOut`.

use ironrdp::core::impl_as_any;
use ironrdp::pdu::PduResult;
use ironrdp::rdpdr::backend::RdpdrBackend;
use ironrdp::rdpdr::pdu::RdpdrPdu;
use ironrdp::rdpdr::pdu::efs::{
    DeviceControlRequest, DeviceControlResponse, NtStatus, ServerDeviceAnnounceResponse,
    ServerDriveIoRequest,
};
use ironrdp::rdpdr::pdu::esc::{
    CardProtocol, CardStateFlags, ConnectReturn, EstablishContextReturn, GetStatusChangeReturn,
    ListReadersReturn, LongReturn, ReaderStateCommonCall, ReturnCode, ScardCall, ScardContext,
    ScardHandle, ScardIoCtlCode, rpce,
};
use ironrdp::svc::SvcMessage;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

use crate::ScardRelayState;
use crate::scard_relay::ScardBridgeReply;

/// Device id we announce our (currently synthetic, or relayed — Phase 3) smart card reader
/// under, toward the target. Arbitrary — the target only needs it to be stable and
/// non-conflicting with any other device we announce, and we announce exactly one.
pub(crate) const SMARTCARD_DEVICE_ID: u32 = 1;

/// Context handle handed out for every `EstablishContext` call answered without a relay
/// (Phase 2 fallback). Fine to keep fixed in that case: nothing lets more than one context
/// matter when there's no relay, since `Connect` always fails below it.
const FAKE_CONTEXT: u32 = 1;

/// Target-facing RDPDR backend. See the module doc comment for what it does and doesn't do
/// yet.
#[derive(Debug)]
pub(crate) struct TargetRdpdr {
    out_tx: UnboundedSender<SvcMessage>,
    scard_relay: Option<ScardRelayState>,
}

impl TargetRdpdr {
    pub(crate) fn new(out_tx: UnboundedSender<SvcMessage>, scard_relay: Option<ScardRelayState>) -> Self {
        Self { out_tx, scard_relay }
    }

    /// Push a completed `DeviceControlResponse` out of band. See the module doc comment for
    /// why this can't just be `handle_scard_call`'s return value.
    fn respond(out_tx: &UnboundedSender<SvcMessage>, req: DeviceControlRequest<ScardIoCtlCode>, output: Box<dyn rpce::Encode>) {
        let pdu = RdpdrPdu::DeviceControlResponse(DeviceControlResponse::new(
            req,
            NtStatus::SUCCESS,
            Some(output),
        ));
        // The target-facing session ending races this send; a dropped receiver just means
        // the answer no longer matters.
        let _ = out_tx.send(SvcMessage::from(pdu));
    }

    /// Forward a relay-eligible call to the viewer's real reader and answer with whatever
    /// comes back, falling back to the Phase-2 canned answer if the relay has nothing (no
    /// viewer reader announced yet, the viewer-facing session ended, ...).
    fn relay_call(&self, relay: ScardRelayState, req: DeviceControlRequest<ScardIoCtlCode>, call: ScardCall) {
        let out_tx = self.out_tx.clone();
        tokio::spawn(async move {
            let fallback_call = call.clone();
            let reply_rx = relay.send_request(call);
            let output = match reply_rx.await {
                Ok(ScardBridgeReply::Answered(bytes)) => Box::new(RawScardReturn(bytes)) as Box<dyn rpce::Encode>,
                Ok(ScardBridgeReply::Unavailable) | Err(_) => match canned_output(&fallback_call) {
                    Some(output) => output,
                    // Unreachable: only the three relay-eligible call kinds ever reach
                    // `relay_call`, and `canned_output` answers all three.
                    None => return,
                },
            };
            Self::respond(&out_tx, req, output);
        });
    }
}

impl_as_any!(TargetRdpdr);

impl RdpdrBackend for TargetRdpdr {
    fn handle_server_device_announce_response(
        &mut self,
        pdu: ServerDeviceAnnounceResponse,
    ) -> PduResult<()> {
        info!(?pdu, "RDPDR (target): device announce acknowledged");
        Ok(())
    }

    fn handle_scard_call(
        &mut self,
        req: DeviceControlRequest<ScardIoCtlCode>,
        call: ScardCall,
    ) -> PduResult<()> {
        info!(?call, "RDPDR (target): smart-card call");
        let relay_eligible = matches!(
            call,
            ScardCall::EstablishContextCall(_)
                | ScardCall::ListReadersCall(_)
                | ScardCall::GetStatusChangeCall(_)
        );
        if relay_eligible && let Some(relay) = self.scard_relay.clone() {
            self.relay_call(relay, req, call);
            return Ok(());
        }
        match canned_output(&call) {
            Some(output) => Self::respond(&self.out_tx, req, output),
            None => {
                // Unreachable in Phase 2 as long as `Connect` always fails — nothing
                // upstream of these ever hands out a real handle to call them with. No
                // type-correct reply is built yet for these; warn instead of risking a
                // malformed one that could break the whole RDPDR channel.
                warn!(?call, "RDPDR (target): smart-card call has no answer; not responding");
            }
        }
        Ok(())
    }

    fn handle_drive_io_request(&mut self, _req: ServerDriveIoRequest) -> PduResult<Vec<SvcMessage>> {
        // Never invoked: no drive capability is advertised (`Rdpdr::with_drives` is never
        // called), so the target has nothing to address to a drive device. Required by the
        // trait regardless (no default impl upstream, unlike `handle_printer_io_request`).
        Ok(Vec::new())
    }
}

/// The Phase-2 "no card present" canned answer for a call, if one is defined. `None` means:
/// don't respond at all (see the call sites for why that's safe here).
fn canned_output(call: &ScardCall) -> Option<Box<dyn rpce::Encode>> {
    match call {
        ScardCall::AccessStartedEventCall(_) => Some(Box::new(LongReturn::new(ReturnCode::Success))),
        ScardCall::EstablishContextCall(_) => Some(Box::new(EstablishContextReturn::new(
            ReturnCode::Success,
            ScardContext::new(FAKE_CONTEXT),
        ))),
        ScardCall::ListReadersCall(_) => {
            // No relay yet (or the relay had nothing), so there's truly nothing to list —
            // the same answer a real WinSCard gives when zero readers are configured.
            Some(Box::new(ListReadersReturn::new(
                ReturnCode::NoReadersAvailable,
                Vec::new(),
            )))
        }
        ScardCall::GetStatusChangeCall(call) => {
            // The target indexes the reply array by position against the reader states it
            // sent, so the count must match even though we have nothing real to report —
            // echo one "unknown reader" entry per request rather than risk an
            // out-of-bounds read on the target's side.
            let reader_states = call
                .states
                .iter()
                .map(|_| ReaderStateCommonCall {
                    current_state: CardStateFlags::SCARD_STATE_UNKNOWN,
                    event_state: CardStateFlags::SCARD_STATE_UNKNOWN | CardStateFlags::SCARD_STATE_CHANGED,
                    atr_length: 0,
                    atr: [0; 36],
                })
                .collect();
            Some(Box::new(GetStatusChangeReturn::new(ReturnCode::Success, reader_states)))
        }
        ScardCall::ConnectCall(call) => {
            // No card to connect to yet — fail cleanly rather than hand out a handle
            // nothing backs.
            Some(Box::new(ConnectReturn::new(
                ReturnCode::NoSmartcard,
                ScardHandle::new(call.common.context, 0),
                CardProtocol::SCARD_PROTOCOL_UNDEFINED,
            )))
        }
        ScardCall::ContextCall(_) => {
            // ReleaseContext / IsValidContext / Cancel — nothing real to release or cancel
            // yet, so just acknowledge.
            Some(Box::new(LongReturn::new(ReturnCode::Success)))
        }
        ScardCall::HCardAndDispositionCall(_) => {
            // BeginTransaction / EndTransaction / Disconnect against a handle that
            // `Connect` above never actually granted.
            Some(Box::new(LongReturn::new(ReturnCode::InvalidHandle)))
        }
        ScardCall::TransmitCall(_)
        | ScardCall::StatusCall(_)
        | ScardCall::GetDeviceTypeIdCall(_)
        | ScardCall::ReadCacheCall(_)
        | ScardCall::WriteCacheCall(_)
        | ScardCall::GetReaderIconCall(_)
        | ScardCall::Unsupported => None,
    }
}

/// An `output_buffer` that writes pre-encoded RPCE bytes verbatim — used to relay the
/// viewer's real answer (already correctly RPCE-encoded by whatever produced it: the
/// viewer's own smart-card driver, via the exact same wire format this crate's own
/// `..._Return::encode` types produce) without decoding and re-encoding it. See
/// `scard_relay`'s module doc comment for why a real terminal server can't tell the
/// difference.
#[derive(Debug)]
struct RawScardReturn(Vec<u8>);

impl ironrdp::core::Encode for RawScardReturn {
    fn encode(&self, dst: &mut ironrdp::core::WriteCursor<'_>) -> ironrdp::core::EncodeResult<()> {
        ironrdp::core::ensure_size!(in: dst, size: self.0.len());
        dst.write_slice(&self.0);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawScardReturn"
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl rpce::Encode for RawScardReturn {}
