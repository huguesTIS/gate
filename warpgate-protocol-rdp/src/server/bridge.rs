//! Target-side bridging: once auth succeeds, dial the target, pump its framebuffer to the
//! viewer-facing RDP server, and record the session.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use warpgate_common::TargetRdpOptions;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{
    DesktopEvent, DesktopState, Services, TargetAuthorization, WarpgateServerHandle,
};

use super::BackendBridge;
use super::protocol::Input as ServerInput;

/// How long [`connect_backend`] waits to see the target either connect or fail before giving
/// up and treating it as rejected — mirrors `client::HANDSHAKE_TIMEOUT`, since this is the
/// same handshake, just observed from the event stream instead of driving it directly.
const DIAL_OUTCOME_TIMEOUT: Duration = Duration::from_secs(30);

/// Why [`connect_backend`] failed to bring the target up.
pub(super) enum DialError {
    /// The target itself rejected the connection (bad credentials, refused, etc.) — a
    /// Requester-mode caller can show this to the viewer and let them retry with a
    /// different password rather than ending the session outright.
    Rejected(String),
    /// Anything else (recording setup, DB, session bookkeeping) — not meaningfully
    /// retryable by reprompting for a password, so callers should end the session.
    Fatal(anyhow::Error),
}

impl From<anyhow::Error> for DialError {
    fn from(error: anyhow::Error) -> Self {
        Self::Fatal(error)
    }
}

impl From<warpgate_common::WarpgateError> for DialError {
    fn from(error: warpgate_common::WarpgateError) -> Self {
        Self::Fatal(error.into())
    }
}

/// Bridge target-side desktop events to the viewer-facing RDP server. Every framebuffer
/// update is a delta rectangle, so none may be dropped — a lost tile leaves that region
/// stale until it next changes. `server_in` is bounded, so a slow viewer applies
/// backpressure here, which propagates to the target via IronRDP's frame acknowledgements
/// (the target paces to the slowest consumer instead of us discarding pixels).
///
/// Recording runs on its own task so its (serialising) `write_event` never gates live frame
/// delivery — `DesktopEvent` clones are cheap (`RawImage` holds ref-counted `Bytes`). The
/// recorder is also shared with `control_loop` (viewer input); the recording finalises once
/// every handle drops.
async fn frame_bridge(
    mut event_rx: tokio::sync::mpsc::Receiver<DesktopEvent>,
    server_in: Sender<ServerInput>,
    recorder: Option<Arc<DesktopRecorder>>,
) {
    let record_tx = recorder.map(|recorder| {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DesktopEvent>(256);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(error) = recorder.write_event(&event).await {
                    warn!(%error, "Failed to record RDP desktop event");
                }
            }
        });
        tx
    });

    while let Some(event) = event_rx.recv().await {
        if let Some(record_tx) = &record_tx {
            // Best-effort: recording must never stall the live path, so drop under overload.
            let _ = record_tx.try_send(event.clone());
        }

        let message = match event {
            DesktopEvent::Resize { width, height } => ServerInput::Resize { width, height },
            DesktopEvent::RawImage { rect, data } => ServerInput::Frame {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
                // `data` is ref-counted `Bytes` — moved into the frame, no framebuffer copy.
                data,
            },
            DesktopEvent::Clipboard(text) => ServerInput::Clipboard(text),
            DesktopEvent::State(DesktopState::Disconnected) => {
                let _ = server_in.send(ServerInput::Shutdown).await;
                return;
            }
            DesktopEvent::Error(message) => {
                warn!(%message, "RDP target reported an error");
                continue;
            }
            DesktopEvent::State(state @ (DesktopState::Connecting | DesktopState::Connected)) => {
                info!(?state, "RDP target");
                continue;
            }
            // The client never emits the remaining framebuffer variants
            _ => continue,
        };

        if server_in.send(message).await.is_err() {
            return;
        }
    }
}

/// Connect to the target and start bridging its framebuffer, once auth is complete.
///
/// Waits to see the target actually come up (`DesktopState::Connected`) before committing to
/// the bridge — a target-side rejection (bad Requester credential, refused connection, ...)
/// arrives as an early `DesktopEvent::Error`/`Disconnected` on the same stream, which is
/// reported as [`DialError::Rejected`] instead of silently starting a bridge to a dead
/// connection. Events before that point are otherwise discarded: IronRDP only starts sending
/// framebuffer data after `Connected`, so nothing display-relevant is lost.
pub(super) async fn connect_backend(
    services: &Services,
    server_handle: &Arc<Mutex<WarpgateServerHandle>>,
    server_in_tx: &Sender<ServerInput>,
    authorization: TargetAuthorization,
    options: TargetRdpOptions,
    screen: warpgate_desktop_ui::Screen,
    scard_relay: crate::ScardRelayState,
) -> Result<BackendBridge, DialError> {
    let (user_info, target) = authorization.into_parts();
    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }
    info!(target=%target.name, "Authorized");

    let session_id = server_handle.lock().await.id();
    let recorder = warpgate_desktop_auth::start_recording(services, &session_id, "rdp")
        .await
        .map(Arc::new);

    let crate::RdpClientHandles {
        mut event_rx,
        input_tx,
        abort_tx,
    } = crate::connect(options, (screen.width, screen.height), Some(scard_relay));

    let outcome = tokio::time::timeout(DIAL_OUTCOME_TIMEOUT, async {
        loop {
            match event_rx.recv().await {
                Some(DesktopEvent::State(DesktopState::Connected)) => return Ok(()),
                Some(DesktopEvent::Error(message)) => return Err(message),
                Some(DesktopEvent::State(DesktopState::Disconnected)) => {
                    return Err("The target closed the connection".to_owned());
                }
                Some(_) => continue,
                None => return Err("The target connection ended unexpectedly".to_owned()),
            }
        }
    })
    .await;

    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(message)) => {
            abort_tx.send(()).ok();
            return Err(DialError::Rejected(message));
        }
        Err(_) => {
            abort_tx.send(()).ok();
            return Err(DialError::Rejected(
                "Timed out waiting for the target to respond".to_owned(),
            ));
        }
    }

    let frame_bridge = tokio::spawn(frame_bridge(
        event_rx,
        server_in_tx.clone(),
        recorder.clone(),
    ));
    Ok(BackendBridge {
        input_tx,
        abort_tx,
        frame_bridge,
        recorder,
        dialed_at: Some(screen),
    })
}
