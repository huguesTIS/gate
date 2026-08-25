use core::fmt;

use ironrdp_core::impl_as_any;
use ironrdp_pdu::PduResult;
use ironrdp_pdu::gcc::ChannelName;
use ironrdp_svc::{CompressionCondition, SvcMessage, SvcProcessor, SvcServerProcessor};

use crate::ServerEventSender;

/// Type-erasing wrapper so [`ironrdp_acceptor::Acceptor::attach_static_channel`]
/// (which requires a concrete, sized `T: SvcServerProcessor`) can host an
/// embedder-supplied RDPDR server-role processor.
///
/// Unlike CLIPRDR, `ironrdp-rdpdr` only implements the *client* role
/// (`SvcClientProcessor`) — RDPDR's grammar is inherently
/// "client announces devices, server drives I/O against them," so nothing
/// upstream needs the server role. The embedder (Warpgate) builds and owns
/// the actual server-role state machine; this wrapper just lets it be
/// attached to the channel set without `ironrdp-server` knowing its concrete
/// type.
pub struct RdpdrServer {
    inner: Box<dyn SvcServerProcessor>,
}

impl RdpdrServer {
    pub fn new(inner: Box<dyn SvcServerProcessor>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for RdpdrServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpdrServer").finish_non_exhaustive()
    }
}

impl_as_any!(RdpdrServer);

impl SvcProcessor for RdpdrServer {
    fn channel_name(&self) -> ChannelName {
        self.inner.channel_name()
    }

    fn compression_condition(&self) -> CompressionCondition {
        self.inner.compression_condition()
    }

    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        self.inner.start()
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        self.inner.process(payload)
    }
}

impl SvcServerProcessor for RdpdrServer {}

/// Builds the RDPDR server-role processor for a connection. Set via
/// [`crate::RdpServerBuilder::with_rdpdr_factory`].
pub trait RdpdrServerFactory: ServerEventSender + Send {
    fn build_rdpdr_processor(&self) -> Box<dyn SvcServerProcessor>;
}
