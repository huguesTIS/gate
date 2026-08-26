//! Server-role RDPDR ([MS-RDPEFS]) channel processor — completes the
//! device-redirection handshake with a native RDP client and relays smart-card
//! I/O requests to it. Phase 1 (handshake) and Phase 3 (the "cheap calls"
//! relay — `EstablishContext`/`ListReaders`/`GetStatusChange`) of the RDP +
//! Hello smart-card bridge, see `ARCHITECTURE_TECHNIQUE.md` §10.
//!
//! Nothing upstream implements this role: `ironrdp-rdpdr` only has the
//! *client* side (`SvcClientProcessor`), which makes sense — RDPDR's
//! grammar is inherently "client announces devices, server drives I/O
//! against them," so only an embedder terminating the *server* side (us,
//! receiving a real smart card redirected by the connecting native client)
//! ever needs this role.
//!
//! Reuses `ironrdp_rdpdr::pdu`'s wire types for both directions where
//! they're already bidirectional (`SharedHeader`, `CoreCapability`,
//! `CapabilityMessage`, `DeviceIoRequest`, `DeviceIoResponse`, and — load-
//! bearing for the relay below — `ScardContext`'s NDR pointer/value
//! encode+decode), but some incoming PDUs are decoded by hand and some
//! outgoing ones (the smart-card *calls* we issue, Phase 3) are encoded by
//! hand: `ironrdp-rdpdr` only ever needed to decode a call and encode a
//! return (the client role's job), never the reverse (the server role's
//! job, which is what an outgoing relay request is).
//!
//! `VersionAndIdPdu::decode` hardcodes the packet ID
//! `PAKID_CORE_CLIENTID_CONFIRM` (0x4343) to the server-role
//! `ServerClientIdConfirm` kind — but a *server* receives a
//! `ClientAnnounceReply` on that exact same packet ID (the two directions
//! share it per spec), so reusing that function here would mislabel the
//! very first reply we get. Decoded manually instead, using the field
//! layout documented on `VersionAndIdPdu`/`DeviceAnnounceHeader`'s own
//! `encode()` methods as the wire-format reference.
//!
//! **Phase 3 relay design — raw byte pass-through for answers, hand-encoded
//! calls for requests.** See `crate::scard_relay`'s module doc comment for
//! the full reasoning; in short, the viewer's real answer bytes are already
//! in exactly the wire shape the target expects back, so this module never
//! decodes a `..._Return` — only the *calls* it sends out
//! (`encode_establish_context_call`/`encode_list_readers_call`/
//! `encode_get_status_change_call` below), mirroring the field layout
//! `EstablishContextCall`/`ListReadersCall`/`GetStatusChangeCall::headerless_decode`
//! already document, the same way Phase 1's handshake code mirrors
//! `ClientDeviceListAnnounce::encode`. `Connect`/`Transmit` (the real APDU
//! path) are not relayed yet — deliberately last in the build order, see the
//! architecture doc.

use ironrdp::core::{
    DecodeResult, EncodeResult, ReadCursor, WriteCursor, encode_vec, ensure_size, impl_as_any,
};
use ironrdp::pdu::gcc::ChannelName;
use ironrdp::pdu::{PduResult, decode_err, pdu_other_err};
use ironrdp::rdpdr::Rdpdr;
use ironrdp::rdpdr::pdu::efs::{
    CapabilityMessage, CoreCapability, CoreCapabilityKind, DeviceIoRequest, DeviceIoResponse,
    DeviceType, MajorFunction, MinorFunction, NtStatus, VERSION_MAJOR, VERSION_MINOR_12,
    VersionAndIdPdu, VersionAndIdPduKind,
};
use ironrdp::rdpdr::pdu::esc::ndr::{self, Encode as _};
use ironrdp::rdpdr::pdu::esc::{ReaderState, ScardCall, ScardContext, ScardIoCtlCode, Scope, rpce};
use ironrdp::rdpdr::pdu::{Component, PacketId, RdpdrPdu, SharedHeader};
use ironrdp::svc::{CompressionCondition, SvcMessage, SvcProcessor, SvcServerProcessor};
use ironrdp_server::{RdpdrServerFactory, ServerEvent, ServerEventSender};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{info, warn};

use crate::scard_relay::{ScardBridgeReply, ScardBridgeRequest, ScardRelayState};

/// Server-role RDPDR handshake state, per [MS-RDPEFS] 1.3.2's connection
/// sequence, driven from our side instead of a real Windows host.
///
/// `AwaitingCapabilityResponseAndDeviceList` covers *two* client replies
/// (Client Core Capability Response, Client Device List Announce) that can
/// arrive in either order — see the root-cause note on
/// [`RdpdrServerChannel::handle_client_name_request`] for why this can't be
/// two sequential states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingAnnounceReply,
    AwaitingNameRequest,
    AwaitingCapabilityResponseAndDeviceList,
    Done,
}

/// A single, fixed server-assigned client ID handed out in Server Announce
/// Request and echoed back unchanged in Server Client ID Confirm — the spec
/// allows a server to keep the same value throughout, and this processor
/// only ever serves one connection's worth, so there's no need to generate a
/// fresh one per session.
const CLIENT_ID: u32 = 1;

/// Bytes we advertise the viewer may use for its reply on an outgoing relay
/// `DeviceIoRequest` (Phase 3). Generous, not a protocol constant — large enough for a
/// multi-reader `ListReaders_Return` without being unreasonable. The device id to target is
/// *not* a constant — it's whatever the viewer announced its smart card reader under, see
/// [`ScardRelayState::viewer_device_id`].
const RELAY_OUTPUT_BUFFER_LENGTH: u32 = 8192;

#[derive(Debug)]
pub struct RdpdrServerChannel {
    state: State,
    relay: ScardRelayState,
}

impl RdpdrServerChannel {
    pub fn new(relay: ScardRelayState) -> Self {
        Self {
            state: State::AwaitingAnnounceReply,
            relay,
        }
    }

    /// [MS-RDPEFS] 2.2.2.3 Client Announce Reply — always the client's
    /// first message on this channel, replying to our Server Announce
    /// Request. See the module doc comment for why this can't go through
    /// `VersionAndIdPdu::decode`.
    fn handle_client_announce_reply(&mut self, src: &mut ReadCursor<'_>) -> PduResult<Vec<SvcMessage>> {
        fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<(u16, u16, u32)> {
            ensure_size!(in: src, size: 8);
            Ok((src.read_u16(), src.read_u16(), src.read_u32()))
        }
        let (version_major, version_minor, client_id) = decode(src).map_err(|e| decode_err!(e))?;
        info!(
            version_major,
            version_minor, client_id, "RDPDR: received Client Announce Reply"
        );
        self.state = State::AwaitingNameRequest;
        Ok(Vec::new())
    }

    /// [MS-RDPEFS] 2.2.2.9 / 2.2.3.1 Client Device List Announce — the
    /// actual Phase 1 success signal, and where we learn the device id to
    /// target for the Phase 3 relay. No decoder exists in `ironrdp-rdpdr`
    /// (only `encode()`, since the client crate only ever sends this);
    /// decoded here from the same field layout `ClientDeviceListAnnounce`/
    /// `DeviceAnnounceHeader::encode()` document.
    fn handle_device_list_announce(&mut self, src: &mut ReadCursor<'_>) -> PduResult<Vec<SvcMessage>> {
        struct Announced {
            device_type_raw: u32,
            device_id: u32,
            name: String,
        }

        fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Vec<Announced>> {
            ensure_size!(in: src, size: 4);
            let device_count = src.read_u32();
            let mut devices = Vec::with_capacity(device_count as usize);
            for _ in 0..device_count {
                // DeviceType(4) + DeviceId(4) + PreferredDosName(8) + DeviceDataLength(4)
                ensure_size!(in: src, size: 20);
                let device_type_raw = src.read_u32();
                let device_id = src.read_u32();
                let name = String::from_utf8_lossy(src.read_slice(8))
                    .trim_end_matches('\u{0}')
                    .to_owned();
                let device_data_len = src.read_u32() as usize;
                ensure_size!(in: src, size: device_data_len);
                let _device_data = src.read_slice(device_data_len);
                devices.push(Announced {
                    device_type_raw,
                    device_id,
                    name,
                });
            }
            Ok(devices)
        }

        let devices = decode(src).map_err(|e| decode_err!(e))?;
        info!(
            device_count = devices.len(),
            "RDPDR: received Client Device List Announce"
        );
        for d in &devices {
            let device_type = DeviceType::try_from(d.device_type_raw).ok();
            info!(
                device_type = device_type
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| format!("unknown(0x{:08X})", d.device_type_raw)),
                device_id = d.device_id,
                name = %d.name,
                "RDPDR: client announced device"
            );
            if device_type == Some(DeviceType::Smartcard) {
                self.relay.set_viewer_device_id(d.device_id);
                info!(
                    device_id = d.device_id,
                    "RDPDR: smart-card relay now targets this device"
                );
            }
        }

        self.state = State::Done;
        Ok(Vec::new())
    }

    /// [MS-RDPEFS] 2.2.2.9 Client Name Request handler — sends *both*
    /// Server Core Capability Request and Server Client ID Confirm in the
    /// same reply, per the spec's own prose in "Protocol Initialization":
    /// "After sending its Server Core Capability Request message, the
    /// server also sends a Server Client ID Confirm message" — i.e. the
    /// second send is not gated on receiving Client Core Capability
    /// Response first.
    ///
    /// **Root cause of the Phase-1 blocker (25 Aug 2026, see
    /// `ARCHITECTURE_TECHNIQUE.md` §10):** the original code sent Server
    /// Client ID Confirm only *after* receiving Client Core Capability
    /// Response, an ordering the spec doesn't require. A real `mstsc.exe`
    /// never sent that response — it silently abandoned the channel,
    /// confirmed at the `ironrdp_svc`/`ironrdp_acceptor` trace layer (zero
    /// further bytes on the RDPDR channel for the rest of the session).
    /// The likely explanation: the client's own RDPDR state machine holds
    /// off on the capability response until it has the client ID confirmed
    /// — a two-way wait where each side waits on the other, which our
    /// gating created but the client (correctly, per spec) didn't expect.
    /// Sending both messages together, undoing the artificial dependency,
    /// resolves it.
    fn handle_client_name_request(&mut self) -> PduResult<Vec<SvcMessage>> {
        self.state = State::AwaitingCapabilityResponseAndDeviceList;
        let mut messages = self.send_server_capability_request()?;
        messages.extend(self.send_server_client_id_confirm()?);
        Ok(messages)
    }

    /// [MS-RDPEFS] 2.2.2.7 Server Core Capability Request. Advertises
    /// General (mandatory) and Smartcard — the only device class this
    /// bridge cares about; the client's device list announce that follows
    /// only includes device types we've advertised capability for.
    fn send_server_capability_request(&mut self) -> PduResult<Vec<SvcMessage>> {
        let capabilities = vec![
            CapabilityMessage::new_general(1),
            CapabilityMessage::new_smartcard(),
        ];
        let req = RdpdrPdu::CoreCapability(CoreCapability {
            capabilities,
            kind: CoreCapabilityKind::ServerCoreCapabilityRequest,
        });
        info!("RDPDR: sending Server Core Capability Request (General + Smartcard)");
        Ok(vec![SvcMessage::from(req)])
    }

    /// [MS-RDPEFS] 2.2.2.6 Server Client ID Confirm — echoes [`CLIENT_ID`]
    /// back; triggers the client to send its (pre-logon) device list,
    /// which is what unblocks [`Self::handle_device_list_announce`]. Sent
    /// alongside the capability request, not gated on the client's
    /// capability response — see [`Self::handle_client_name_request`].
    fn send_server_client_id_confirm(&mut self) -> PduResult<Vec<SvcMessage>> {
        let req = RdpdrPdu::VersionAndIdPdu(VersionAndIdPdu {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR_12,
            client_id: CLIENT_ID,
            kind: VersionAndIdPduKind::ServerClientIdConfirm,
        });
        info!("RDPDR: sending Server Client ID Confirm");
        Ok(vec![SvcMessage::from(req)])
    }

    /// [MS-RDPEFS] 2.2.1.5 Device I/O Response — here specifically the tail
    /// of a `DeviceControlResponse` (`DR_CONTROL_RSP`) answering a
    /// smart-card call we issued via the relay (Phase 3). No decoder exists
    /// in `ironrdp-rdpdr` for the *whole* PDU (only `encode`, since the
    /// client crate only ever sends this), but the fixed `DeviceIoResponse`
    /// header *is* bidirectional and reused here — the `output_buffer`
    /// bytes that follow are relayed to the target completely unparsed, see
    /// the module doc comment for why that's correct.
    fn handle_device_io_completion(&mut self, src: &mut ReadCursor<'_>) -> PduResult<Vec<SvcMessage>> {
        fn decode_tail(src: &mut ReadCursor<'_>) -> DecodeResult<(DeviceIoResponse, Vec<u8>)> {
            let response = DeviceIoResponse::decode(src)?;
            ensure_size!(in: src, size: 4);
            let output_buffer_length = src.read_u32() as usize;
            ensure_size!(in: src, size: output_buffer_length);
            let output_buffer = src.read_slice(output_buffer_length).to_vec();
            Ok((response, output_buffer))
        }
        let (response, output_buffer) = decode_tail(src).map_err(|e| decode_err!(e))?;
        let output_buffer_length = output_buffer.len();

        info!(
            completion_id = response.completion_id,
            io_status = ?response.io_status,
            output_buffer_length,
            "RDPDR: received DeviceControlResponse (smart-card relay)"
        );

        let outcome = if response.io_status == NtStatus::SUCCESS {
            ScardBridgeReply::Answered(output_buffer)
        } else {
            // An IRP-level failure (not a smart-card-level return code, which would
            // still be `SUCCESS` here with the failure encoded *inside* output_buffer)
            // — nothing meaningful to relay back as `..._Return` bytes.
            ScardBridgeReply::Unavailable
        };
        self.relay.resolve(response.completion_id, outcome);
        Ok(Vec::new())
    }
}

impl_as_any!(RdpdrServerChannel);

impl SvcProcessor for RdpdrServerChannel {
    fn channel_name(&self) -> ChannelName {
        Rdpdr::NAME
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }

    /// [MS-RDPEFS] 2.2.2.2 Server Announce Request — always the first
    /// message on this channel, server-initiated (unlike CLIPRDR).
    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        let req = RdpdrPdu::VersionAndIdPdu(VersionAndIdPdu {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR_12,
            client_id: CLIENT_ID,
            kind: VersionAndIdPduKind::ServerAnnounceRequest,
        });
        info!("RDPDR: sending Server Announce Request");
        Ok(vec![SvcMessage::from(req)])
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        let mut src = ReadCursor::new(payload);
        let header = SharedHeader::decode(&mut src).map_err(|e| decode_err!(e))?;

        match (self.state, header.packet_id) {
            (State::AwaitingAnnounceReply, PacketId::CoreClientidConfirm) => {
                self.handle_client_announce_reply(&mut src)
            }
            (State::AwaitingNameRequest, PacketId::CoreClientName) => {
                info!("RDPDR: received Client Name Request");
                self.handle_client_name_request()
            }
            // These two replies can arrive in either order — see
            // `handle_client_name_request`'s doc comment — so both are
            // accepted throughout this state, and only
            // `CoreDevicelistAnnounce` advances past it.
            (State::AwaitingCapabilityResponseAndDeviceList, PacketId::CoreClientCapability) => {
                let resp = CoreCapability::decode(header, &mut src).map_err(|e| decode_err!(e))?;
                info!(
                    num_capabilities = resp.capabilities.len(),
                    "RDPDR: received Client Core Capability Response"
                );
                Ok(Vec::new())
            }
            (State::AwaitingCapabilityResponseAndDeviceList, PacketId::CoreDevicelistAnnounce) => {
                self.handle_device_list_announce(&mut src)
            }
            // Client Core Capability Response can also land after the
            // device list, for the same either-order reason — tolerate it
            // once `Done` instead of erroring the channel.
            (State::Done, PacketId::CoreClientCapability) => {
                let resp = CoreCapability::decode(header, &mut src).map_err(|e| decode_err!(e))?;
                info!(
                    num_capabilities = resp.capabilities.len(),
                    "RDPDR: received Client Core Capability Response (after device list)"
                );
                Ok(Vec::new())
            }
            // Phase 3: the viewer's answer to a relayed smart-card call.
            (State::Done, PacketId::CoreDeviceIoCompletion) => self.handle_device_io_completion(&mut src),
            (state, packet_id) => {
                warn!(?state, %packet_id, "RDPDR: unexpected packet for current state");
                Err(pdu_other_err!(
                    "RdpdrServerChannel::process",
                    "unexpected packet for current state"
                ))
            }
        }
    }
}

impl SvcServerProcessor for RdpdrServerChannel {}

/// Builds a fresh [`RdpdrServerChannel`] per connection and, once
/// [`ServerEventSender::set_sender`] fires, spawns the task that drains
/// relayed smart-card requests and issues them to the viewer
/// ([`relay_outgoing`]).
#[derive(Debug, Clone)]
pub(super) struct ViewerRdpdr {
    relay: ScardRelayState,
}

impl ViewerRdpdr {
    pub(super) fn new(relay: ScardRelayState) -> Self {
        Self { relay }
    }
}

impl RdpdrServerFactory for ViewerRdpdr {
    fn build_rdpdr_processor(&self) -> Box<dyn SvcServerProcessor> {
        Box::new(RdpdrServerChannel::new(self.relay.clone()))
    }
}

impl ServerEventSender for ViewerRdpdr {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        // `take_request_rx` only ever yields `Some` once per `ScardRelayState` (see its doc
        // comment) — `set_sender` itself is also only ever called once per connection by
        // `ironrdp-server`, so this always fires exactly once in practice, but the `if let`
        // makes "at most once" true even if that assumption ever breaks.
        if let Some(request_rx) = self.relay.take_request_rx() {
            tokio::spawn(relay_outgoing(request_rx, sender, self.relay.clone()));
        }
    }
}

/// Drains smart-card calls forwarded from the target-facing side
/// (`client::rdpdr::TargetRdpdr`) and issues them to the viewer's real
/// reader over the RDPDR channel, via `ServerEvent::Rdpdr` — the only way to
/// push a server-initiated message on this channel from outside the
/// `SvcProcessor` itself (see the vendor patch's own doc comment,
/// `vendor/ironrdp-server/PATCHES.md`). The corresponding answer is
/// resolved elsewhere, in [`RdpdrServerChannel::handle_device_io_completion`]
/// once the viewer's real reader replies — this task's job ends at "message
/// sent."
async fn relay_outgoing(
    mut request_rx: UnboundedReceiver<ScardBridgeRequest>,
    event_tx: UnboundedSender<ServerEvent>,
    relay: ScardRelayState,
) {
    while let Some(ScardBridgeRequest { call, reply }) = request_rx.recv().await {
        let Some(device_id) = relay.viewer_device_id() else {
            // No smart card announced yet (or ever) by the viewer.
            let _ = reply.send(ScardBridgeReply::Unavailable);
            continue;
        };

        let encoded = match call {
            ScardCall::EstablishContextCall(call) => {
                encode_establish_context_call(call.scope).map(|body| (ScardIoCtlCode::EstablishContext, body))
            }
            ScardCall::ListReadersCall(call) => {
                encode_list_readers_call(call.context).map(|body| (ScardIoCtlCode::ListReadersW, body))
            }
            ScardCall::GetStatusChangeCall(call) => {
                encode_get_status_change_call(call.context, call.timeout, &call.states)
                    .map(|body| (ScardIoCtlCode::GetStatusChangeW, body))
            }
            // `TargetRdpdr` only ever forwards the three kinds above.
            other => {
                warn!(?other, "RDPDR relay: unexpected call kind forwarded to the viewer-facing relay");
                let _ = reply.send(ScardBridgeReply::Unavailable);
                continue;
            }
        };
        let (io_control_code, body) = match encoded {
            Ok(pair) => pair,
            Err(error) => {
                warn!(%error, "RDPDR relay: failed to encode outgoing smart-card call");
                let _ = reply.send(ScardBridgeReply::Unavailable);
                continue;
            }
        };

        let completion_id = relay.register(reply);
        let message = match build_device_io_request(device_id, completion_id, io_control_code, &body) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(%error, "RDPDR relay: failed to build outgoing DeviceIoRequest");
                relay.resolve(completion_id, ScardBridgeReply::Unavailable);
                continue;
            }
        };
        if event_tx.send(ServerEvent::Rdpdr(vec![SvcMessage::from(message)])).is_err() {
            // The RDP server thread ended; nothing left to answer this with.
            relay.resolve(completion_id, ScardBridgeReply::Unavailable);
        }
    }
}

/// Builds the full raw bytes of an outgoing `DeviceIoRequest` +
/// `DeviceControlRequest<ScardIoCtlCode>` for the smart-card device —
/// `SharedHeader` + [`DeviceIoRequest::encode`] (both already bidirectional
/// upstream) followed by the `DeviceControlRequest` tail and `call_body`,
/// which upstream never needed to encode (only decode, client-role-only —
/// see the module doc comment).
fn build_device_io_request(
    device_id: u32,
    completion_id: u32,
    io_control_code: ScardIoCtlCode,
    call_body: &[u8],
) -> EncodeResult<Vec<u8>> {
    let header = DeviceIoRequest {
        device_id,
        file_id: 0,
        completion_id,
        major_function: MajorFunction::DeviceControl,
        minor_function: MinorFunction::from(0u32),
    };
    // SharedHeader(4) + DeviceIoRequest(20) + OutputBufferLength(4) + InputBufferLength(4)
    // + IoControlCode(4) + padding(20) + call_body.
    let total_size = 4 + header.size() + 4 + 4 + 4 + 20 + call_body.len();
    let mut buf = vec![0u8; total_size];
    let mut dst = WriteCursor::new(&mut buf);

    dst.write_u16(u16::from(Component::RdpdrCtypCore));
    dst.write_u16(u16::from(PacketId::CoreDeviceIoRequest));
    header.encode(&mut dst)?;
    dst.write_u32(RELAY_OUTPUT_BUFFER_LENGTH);
    dst.write_u32(u32::try_from(call_body.len()).unwrap_or(u32::MAX));
    #[expect(
        clippy::as_conversions,
        reason = "ScardIoCtlCode is #[repr(u32)]; matches the crate's own pattern for its sibling enums"
    )]
    dst.write_u32(io_control_code as u32);
    dst.write_slice(&[0u8; 20]);
    dst.write_slice(call_body);

    Ok(buf)
}

/// [2.2.2.1] EstablishContext_Call — the only field is the scope, matching
/// [`ironrdp::rdpdr::pdu::esc::EstablishContextCall::headerless_decode`]'s
/// single `u32`.
#[derive(Debug)]
struct EstablishContextCallOut {
    scope: Scope,
}

impl rpce::HeaderlessEncode for EstablishContextCallOut {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());
        dst.write_u32(scope_value(self.scope));
        Ok(())
    }

    fn name(&self) -> &'static str {
        "EstablishContext_Call"
    }

    fn size(&self) -> usize {
        size_of::<u32>()
    }
}

fn scope_value(scope: Scope) -> u32 {
    match scope {
        Scope::User => 0,
        Scope::Terminal => 1,
        Scope::System => 2,
    }
}

fn encode_establish_context_call(scope: Scope) -> EncodeResult<Vec<u8>> {
    encode_vec(&rpce::Pdu(EstablishContextCallOut { scope }))
}

/// [2.2.2.4] ListReaders_Call — no reader-group filter (`groups_ptr` null) and no
/// preallocated output buffer (`readers_is_null`), matching
/// [`ironrdp::rdpdr::pdu::esc::ListReadersCall::headerless_decode`]'s field order.
#[derive(Debug)]
struct ListReadersCallOut {
    context: ScardContext,
}

impl rpce::HeaderlessEncode for ListReadersCallOut {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());
        let mut index = 0u32;
        self.context.encode_ptr(&mut index, dst)?;
        dst.write_u32(0); // groups_ptr_length: no group filter
        dst.write_u32(0); // groups_ptr: NULL
        dst.write_u32(1); // readers_is_null: let the reader size the reply itself
        dst.write_u32(0); // readers_size
        self.context.encode_value(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ListReaders_Call"
    }

    fn size(&self) -> usize {
        self.context.size_ptr() + 4 + 4 + 4 + 4 + self.context.size_value()
    }
}

fn encode_list_readers_call(context: ScardContext) -> EncodeResult<Vec<u8>> {
    encode_vec(&rpce::Pdu(ListReadersCallOut { context }))
}

/// [2.2.2.12] GetStatusChangeW_Call — reader names and states passed straight through
/// from the target's own call (`RdpdrServerChannel` doesn't originate these; it only
/// relays what the target asked for), matching
/// [`ironrdp::rdpdr::pdu::esc::GetStatusChangeCall::headerless_decode`]'s field order.
///
/// **NDR string alignment note**: [`ndr::read_string_from_cursor`]'s 4-byte padding is
/// computed against the *absolute* position in the whole decoded RDPDR message, not a
/// position local to this call body. `encode_vec`/`rpce::Pdu::encode` instead encode this
/// struct into its own fresh buffer starting at local position 0 (well, 16, after
/// `rpce::Pdu`'s own `StreamHeader`+`TypeHeader`). This still produces byte-identical
/// output, because every fixed-width field in the real message *before* the first string —
/// `SharedHeader`(4) + `DeviceIoRequest`(20) + `DeviceControlRequest` tail(32) +
/// `StreamHeader`(8) + `TypeHeader`(8) + this struct's own context/timeout/pointer/
/// reader-state fields — is a multiple of 4 bytes, so "pad up to the next multiple of 4"
/// gives the same answer whether measured from true absolute position or from this local
/// buffer's position 0. Verified field-by-field, not just asserted — see the git history
/// for the arithmetic if this ever needs re-deriving.
///
/// [`ndr::read_string_from_cursor`]: ironrdp::rdpdr::pdu::esc::ndr::read_string_from_cursor
#[derive(Debug)]
struct GetStatusChangeCallOut {
    context: ScardContext,
    timeout: u32,
    states: Vec<ReaderState>,
}

impl rpce::HeaderlessEncode for GetStatusChangeCallOut {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());
        let mut index = 0u32;
        let states_len = u32::try_from(self.states.len()).unwrap_or(u32::MAX);

        self.context.encode_ptr(&mut index, dst)?;
        dst.write_u32(self.timeout);
        dst.write_u32(states_len); // states_ptr_length
        ndr::encode_ptr(None, &mut index, dst)?; // states_ptr
        self.context.encode_value(dst)?;
        dst.write_u32(states_len); // states_length (repeated, per the decode side)

        for state in &self.states {
            ndr::encode_ptr(None, &mut index, dst)?; // reader_ptr
            dst.write_u32(state.common.current_state.bits());
            dst.write_u32(state.common.event_state.bits());
            dst.write_u32(state.common.atr_length);
            dst.write_slice(&state.common.atr);
        }
        for state in &self.states {
            write_ndr_string(dst, &state.reader)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "GetStatusChange_Call"
    }

    fn size(&self) -> usize {
        self.context.size_ptr()
            + 4 // timeout
            + 4 // states_ptr_length
            + 4 // states_ptr
            + self.context.size_value()
            + 4 // states_length
            + self.states.len() * (4 + 48) // reader_ptr(4) + ReaderStateCommonCall(48) each
            + self.states.iter().map(|s| ndr_string_size(&s.reader)).sum::<usize>()
    }
}

fn encode_get_status_change_call(context: ScardContext, timeout: u32, states: &[ReaderState]) -> EncodeResult<Vec<u8>> {
    encode_vec(&rpce::Pdu(GetStatusChangeCallOut {
        context,
        timeout,
        states: states.to_vec(),
    }))
}

/// Writes one NDR conformant-varying string exactly as
/// [`ironrdp::rdpdr::pdu::esc::ndr::read_string_from_cursor`] expects to read it back:
/// `length`/`offset`/`length2` header, UTF-16 payload with a null terminator, then padding
/// to the next 4-byte boundary. See [`GetStatusChangeCallOut`]'s doc comment for why using
/// `dst.pos()` here (a genuinely position-aware computation, unlike [`ndr_string_size`]'s
/// closed-form shortcut) is always correct.
fn write_ndr_string(dst: &mut WriteCursor<'_>, value: &str) -> EncodeResult<()> {
    use ironrdp::pdu::utils::{CharacterSet, write_string_to_cursor};

    ensure_size!(in: dst, size: ndr_string_size(value));
    let char_count = u32::try_from(value.encode_utf16().count() + 1).unwrap_or(u32::MAX); // + null terminator
    dst.write_u32(char_count); // length
    dst.write_u32(0); // offset
    dst.write_u32(char_count); // length2
    write_string_to_cursor(dst, value, CharacterSet::Unicode, true)?;
    let pos = dst.pos();
    let padded = pos.div_ceil(4) * 4;
    if padded > pos {
        dst.write_slice(&vec![0u8; padded - pos]);
    }
    Ok(())
}

/// The exact byte length [`write_ndr_string`] produces for `value` — see its doc comment
/// and [`GetStatusChangeCallOut`]'s for why this closed-form (no cursor, no absolute
/// position) always agrees with the position-aware encoder.
fn ndr_string_size(value: &str) -> usize {
    use ironrdp::pdu::utils::{CharacterSet, encoded_str_len};

    let header = 12; // length + offset + length2
    let payload = encoded_str_len(value, CharacterSet::Unicode, true);
    (header + payload).div_ceil(4) * 4
}
