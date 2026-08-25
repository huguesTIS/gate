//! Server-role RDPDR ([MS-RDPEFS]) channel processor — completes the
//! device-redirection handshake with a native RDP client and logs whatever
//! devices it announces. Phase 1 of the RDP + Hello smart-card bridge (see
//! `ARCHITECTURE_TECHNIQUE.md` §10): negotiation only, no `DeviceIoRequest`
//! handling yet — that's Phase 3.
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
//! `CapabilityMessage`), but some incoming PDUs are decoded by hand:
//! `RdpdrPdu::decode_body` only covers what a *client* needs to receive, so
//! it has no arm at all for `PAKID_CORE_DEVICELIST_ANNOUNCE`. Worse,
//! `VersionAndIdPdu::decode` hardcodes the packet ID
//! `PAKID_CORE_CLIENTID_CONFIRM` (0x4343) to the server-role
//! `ServerClientIdConfirm` kind — but a *server* receives a
//! `ClientAnnounceReply` on that exact same packet ID (the two directions
//! share it per spec), so reusing that function here would mislabel the
//! very first reply we get. Decoded manually instead, using the field
//! layout documented on `VersionAndIdPdu`/`DeviceAnnounceHeader`'s own
//! `encode()` methods as the wire-format reference.

use ironrdp::core::{DecodeResult, ReadCursor, ensure_size, impl_as_any};
use ironrdp::pdu::gcc::ChannelName;
use ironrdp::pdu::{PduResult, decode_err, pdu_other_err};
use ironrdp::rdpdr::Rdpdr;
use ironrdp::rdpdr::pdu::efs::{
    CapabilityMessage, CoreCapability, CoreCapabilityKind, DeviceType, VERSION_MAJOR,
    VERSION_MINOR_12, VersionAndIdPdu, VersionAndIdPduKind,
};
use ironrdp::rdpdr::pdu::{PacketId, RdpdrPdu, SharedHeader};
use ironrdp::svc::{CompressionCondition, SvcMessage, SvcProcessor, SvcServerProcessor};
use ironrdp_server::{RdpdrServerFactory, ServerEvent, ServerEventSender};
use tokio::sync::mpsc::UnboundedSender;
use tracing::info;

/// Server-role RDPDR handshake state, per [MS-RDPEFS] 1.3.2's connection
/// sequence, driven from our side instead of a real Windows host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingAnnounceReply,
    AwaitingNameRequest,
    AwaitingCapabilityResponse,
    AwaitingDeviceListAnnounce,
    Done,
}

/// A single, fixed server-assigned client ID handed out in Server Announce
/// Request and echoed back unchanged in Server Client ID Confirm — the spec
/// allows a server to keep the same value throughout, and Phase 1 only ever
/// serves one connection's worth of this processor, so there's no need to
/// generate a fresh one per session.
const CLIENT_ID: u32 = 1;

#[derive(Debug)]
pub struct RdpdrServerChannel {
    state: State,
}

impl RdpdrServerChannel {
    pub fn new() -> Self {
        Self {
            state: State::AwaitingAnnounceReply,
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
    /// actual Phase 1 success signal. No decoder exists in `ironrdp-rdpdr`
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
            let device_type = DeviceType::try_from(d.device_type_raw)
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|_| format!("unknown(0x{:08X})", d.device_type_raw));
            info!(
                device_type,
                device_id = d.device_id,
                name = %d.name,
                "RDPDR: client announced device"
            );
        }

        self.state = State::Done;
        Ok(Vec::new())
    }

    /// [MS-RDPEFS] 2.2.2.7 Server Core Capability Request. Advertises
    /// General (mandatory) and Smartcard — the only device class this
    /// phase cares about; the client's device list announce that follows
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
    /// which is what unblocks [`Self::handle_device_list_announce`].
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
}

impl Default for RdpdrServerChannel {
    fn default() -> Self {
        Self::new()
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
                self.state = State::AwaitingCapabilityResponse;
                self.send_server_capability_request()
            }
            (State::AwaitingCapabilityResponse, PacketId::CoreClientCapability) => {
                let resp = CoreCapability::decode(header, &mut src).map_err(|e| decode_err!(e))?;
                info!(
                    num_capabilities = resp.capabilities.len(),
                    "RDPDR: received Client Core Capability Response"
                );
                self.state = State::AwaitingDeviceListAnnounce;
                self.send_server_client_id_confirm()
            }
            (State::AwaitingDeviceListAnnounce, PacketId::CoreDevicelistAnnounce) => {
                self.handle_device_list_announce(&mut src)
            }
            (state, packet_id) => {
                tracing::warn!(?state, %packet_id, "RDPDR: unexpected packet for current state");
                Err(pdu_other_err!(
                    "RdpdrServerChannel::process",
                    "unexpected packet for current state"
                ))
            }
        }
    }
}

impl SvcServerProcessor for RdpdrServerChannel {}

/// Builds a fresh [`RdpdrServerChannel`] per connection. Phase 1 has no
/// relay logic yet (that's Phase 3), so there's nothing to push
/// asynchronously — `set_sender` is a no-op, kept only because
/// [`RdpdrServerFactory`] requires it, same as `ViewerClipboard`'s shape.
#[derive(Debug, Default)]
pub(super) struct ViewerRdpdr;

impl RdpdrServerFactory for ViewerRdpdr {
    fn build_rdpdr_processor(&self) -> Box<dyn SvcServerProcessor> {
        Box::new(RdpdrServerChannel::new())
    }
}

impl ServerEventSender for ViewerRdpdr {
    fn set_sender(&mut self, _sender: UnboundedSender<ServerEvent>) {}
}
