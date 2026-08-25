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
//! **No real relay to the viewer's physical reader yet — that's Phase 3.** Every reachable
//! call here is answered synchronously with a protocol-valid "no card present" response, so
//! a real smart card holder currently sees an empty reader list on the target, not their own
//! card. This still exercises the real wire format end to end against a real target: the
//! device announcement, the capability/context dance, and (once a real relay exists) the
//! same push-response path `Connect`/`Transmit` will use.
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

/// Device id we announce our (currently synthetic) smart card reader under, toward the
/// target. Arbitrary — the target only needs it to be stable and non-conflicting with any
/// other device we announce, and we announce exactly one.
pub(crate) const SMARTCARD_DEVICE_ID: u32 = 1;

/// Context handle handed out for every `EstablishContext` call. Fine to keep fixed: nothing
/// in Phase 2 lets more than one context matter, since `Connect` always fails below it.
const FAKE_CONTEXT: u32 = 1;

/// Target-facing RDPDR backend. See the module doc comment for what it does and doesn't do
/// yet.
#[derive(Debug)]
pub(crate) struct TargetRdpdr {
    out_tx: UnboundedSender<SvcMessage>,
}

impl TargetRdpdr {
    pub(crate) fn new(out_tx: UnboundedSender<SvcMessage>) -> Self {
        Self { out_tx }
    }

    /// Push a completed `DeviceControlResponse` out of band. See the module doc comment for
    /// why this can't just be `handle_scard_call`'s return value.
    fn respond(&self, req: DeviceControlRequest<ScardIoCtlCode>, output: Box<dyn rpce::Encode>) {
        let pdu = RdpdrPdu::DeviceControlResponse(DeviceControlResponse::new(
            req,
            NtStatus::SUCCESS,
            Some(output),
        ));
        // The target-facing session ending races this send; a dropped receiver just means
        // the answer no longer matters.
        let _ = self.out_tx.send(SvcMessage::from(pdu));
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
        match call {
            ScardCall::AccessStartedEventCall(_) => {
                self.respond(req, Box::new(LongReturn::new(ReturnCode::Success)));
            }
            ScardCall::EstablishContextCall(_) => {
                self.respond(
                    req,
                    Box::new(EstablishContextReturn::new(
                        ReturnCode::Success,
                        ScardContext::new(FAKE_CONTEXT),
                    )),
                );
            }
            ScardCall::ListReadersCall(_) => {
                // No relay yet (Phase 3), so there's truly nothing to list — the same
                // answer a real WinSCard gives when zero readers are configured.
                self.respond(
                    req,
                    Box::new(ListReadersReturn::new(
                        ReturnCode::NoReadersAvailable,
                        Vec::new(),
                    )),
                );
            }
            ScardCall::GetStatusChangeCall(call) => {
                // The target indexes the reply array by position against the reader
                // states it sent, so the count must match even though we have nothing
                // real to report yet — echo one "unknown reader" entry per request
                // rather than risk an out-of-bounds read on the target's side.
                let reader_states = call
                    .states
                    .iter()
                    .map(|_| ReaderStateCommonCall {
                        current_state: CardStateFlags::SCARD_STATE_UNKNOWN,
                        event_state: CardStateFlags::SCARD_STATE_UNKNOWN
                            | CardStateFlags::SCARD_STATE_CHANGED,
                        atr_length: 0,
                        atr: [0; 36],
                    })
                    .collect();
                self.respond(
                    req,
                    Box::new(GetStatusChangeReturn::new(ReturnCode::Success, reader_states)),
                );
            }
            ScardCall::ConnectCall(call) => {
                // No card to connect to yet — fail cleanly rather than hand out a
                // handle nothing backs.
                self.respond(
                    req,
                    Box::new(ConnectReturn::new(
                        ReturnCode::NoSmartcard,
                        ScardHandle::new(call.common.context, 0),
                        CardProtocol::SCARD_PROTOCOL_UNDEFINED,
                    )),
                );
            }
            ScardCall::ContextCall(_) => {
                // ReleaseContext / IsValidContext / Cancel — nothing real to release or
                // cancel yet, so just acknowledge.
                self.respond(req, Box::new(LongReturn::new(ReturnCode::Success)));
            }
            ScardCall::HCardAndDispositionCall(_) => {
                // BeginTransaction / EndTransaction / Disconnect against a handle that
                // `Connect` above never actually granted.
                self.respond(req, Box::new(LongReturn::new(ReturnCode::InvalidHandle)));
            }
            ScardCall::TransmitCall(_)
            | ScardCall::StatusCall(_)
            | ScardCall::GetDeviceTypeIdCall(_)
            | ScardCall::ReadCacheCall(_)
            | ScardCall::WriteCacheCall(_)
            | ScardCall::GetReaderIconCall(_)
            | ScardCall::Unsupported => {
                // Unreachable in Phase 2 as long as `Connect` above always fails —
                // nothing upstream of these ever hands out a real handle to call them
                // with. No type-correct reply is built yet for these; warn instead of
                // risking a malformed one that could break the whole RDPDR channel.
                warn!(?call, "RDPDR (target): smart-card call has no Phase-2 answer; not responding");
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
