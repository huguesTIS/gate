//! Shared correlation state for the RDPDR smart-card relay (Phase 3 of the RDP + Hello
//! bridge, `ARCHITECTURE_TECHNIQUE.md` §10).
//!
//! The target-facing side (`client::rdpdr::TargetRdpdr`) receives smart-card calls from the
//! real target and needs an answer it can't produce itself — only the viewer's real reader
//! can. The viewer-facing side (`server::rdpdr`) is the only thing that can talk to that
//! reader, and does so over a *different* RDP connection (a different TCP socket, a
//! different tokio task — for RDPDR's server role, a different OS thread entirely, see
//! `server::rdp::run_on_thread`). [`ScardRelayState`] is the two sides' only shared memory:
//! built once per session in `server::mod::handle_connection` and handed to both.
//!
//! **Design: raw byte pass-through, not decode-then-re-encode.** Once the viewer's reader
//! answers a call, the bytes it produces (`EstablishContext_Return`, `ListReaders_Return`,
//! ...) are already in exactly the wire shape the target expects back — a real Windows
//! terminal server doesn't care which "client" produced them. So the relay never decodes a
//! `..._Return`, only a `..._Call` (see `server::rdpdr`'s hand-written encoders) going the
//! other way, which the crate doesn't provide an encoder for since upstream only implements
//! the client role. This halves the hand-rolled wire code and removes an entire class of
//! "decoded correctly but re-encoded wrong" bugs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use ironrdp::rdpdr::pdu::esc::ScardCall;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;

/// A smart-card call the target issued, forwarded from `TargetRdpdr` to the viewer-facing
/// relay. `reply` resolves once the viewer's reader has answered (or the relay gives up).
pub(crate) struct ScardBridgeRequest {
    pub call: ScardCall,
    pub reply: oneshot::Sender<ScardBridgeReply>,
}

/// The relay's answer to a [`ScardBridgeRequest`].
pub(crate) enum ScardBridgeReply {
    /// The raw RPCE-encoded `..._Return` bytes the viewer's reader produced, copied
    /// verbatim — see the module doc comment for why a copy (not a decode/re-encode) is
    /// correct here.
    Answered(Vec<u8>),
    /// No viewer smart card to relay to (not announced yet, or the RDPDR channel/session
    /// ended), or the viewer's answer indicated failure at the IRP level (`NtStatus` other
    /// than `SUCCESS`) rather than a smart-card-level return code the target can interpret
    /// as `..._Return` bytes.
    Unavailable,
}

/// Shared, per-session RDPDR relay state — cheap to clone (all fields are `Arc`), built once
/// in `server::mod::handle_connection` and handed to both the target-facing connector
/// (`client::connect`, which only needs [`Self::send_request`] — see
/// `client::rdpdr::TargetRdpdr`) and the viewer-facing RDPDR channel (`server::rdpdr`, both
/// the factory that owns the outgoing relay task, fed by [`Self::take_request_rx`], and the
/// processor that resolves replies via [`Self::resolve`]).
#[derive(Clone)]
pub struct ScardRelayState {
    request_tx: UnboundedSender<ScardBridgeRequest>,
    request_rx: Arc<Mutex<Option<UnboundedReceiver<ScardBridgeRequest>>>>,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<ScardBridgeReply>>>>,
    next_completion_id: Arc<AtomicU32>,
    /// Device id the viewer announced its smart card reader under (`Client Device List
    /// Announce`, Phase 1's `handle_device_list_announce`) — `None` until that arrives, or
    /// permanently if the connecting client has no reader at all.
    viewer_device_id: Arc<Mutex<Option<u32>>>,
}

impl std::fmt::Debug for ScardRelayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScardRelayState").finish_non_exhaustive()
    }
}

impl ScardRelayState {
    pub(crate) fn new() -> Self {
        let (request_tx, request_rx) = unbounded_channel();
        Self {
            request_tx,
            request_rx: Arc::new(Mutex::new(Some(request_rx))),
            pending: Arc::default(),
            next_completion_id: Arc::default(),
            viewer_device_id: Arc::default(),
        }
    }

    /// Send a call to the viewer-facing relay and return a receiver for its answer. Called
    /// from `TargetRdpdr::handle_scard_call` for the call kinds it forwards instead of
    /// answering itself.
    pub(crate) fn send_request(&self, call: ScardCall) -> oneshot::Receiver<ScardBridgeReply> {
        let (reply, reply_rx) = oneshot::channel();
        // A closed receiver (session tearing down) just means the reply is never read; the
        // caller's own `reply_rx.await` failing is how it finds out.
        let _ = self.request_tx.send(ScardBridgeRequest { call, reply });
        reply_rx
    }

    /// Take the request receiver, once. Called from `ViewerRdpdr::set_sender` to hand it to
    /// the spawned outgoing-relay task; returns `None` on any call after the first (or if
    /// called before `new()`, which cannot happen since `new()` always populates it).
    pub(crate) fn take_request_rx(&self) -> Option<UnboundedReceiver<ScardBridgeRequest>> {
        self.request_rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Record the viewer's announced smart card device id. Called once, from
    /// `RdpdrServerChannel::handle_device_list_announce`.
    pub(crate) fn set_viewer_device_id(&self, device_id: u32) {
        *self
            .viewer_device_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(device_id);
    }

    pub(crate) fn viewer_device_id(&self) -> Option<u32> {
        *self
            .viewer_device_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Allocate a completion id for an outgoing request and register `reply` against it.
    /// Called from the viewer-facing relay task just before it sends the request out.
    pub(crate) fn register(&self, reply: oneshot::Sender<ScardBridgeReply>) -> u32 {
        let completion_id = self.next_completion_id.fetch_add(1, Ordering::Relaxed);
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(completion_id, reply);
        completion_id
    }

    /// Resolve a pending request once the viewer has answered (or the connection is closing
    /// and everything outstanding must be given up on). A `completion_id` with no matching
    /// entry is silently ignored — already resolved, or never ours (e.g. a stray completion
    /// for a device/IRP we didn't request).
    pub(crate) fn resolve(&self, completion_id: u32, outcome: ScardBridgeReply) {
        if let Some(reply) = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&completion_id)
        {
            let _ = reply.send(outcome);
        }
    }
}
