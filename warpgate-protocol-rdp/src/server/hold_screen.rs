//! The interactive second-factor "holding screen": rendered to the RDP viewer after a
//! valid password (NLA) when the credential policy still needs a TOTP or web approval.
//! Collects that factor over the live RDP session before the target is dialed.

use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_core::{DesktopInput, Scancode, Services};
use warpgate_desktop_auth::{
    Deadline, HoldEvent, HoldFrame, HoldInputSource, HoldPainter as HoldPainterExt,
    InteractiveAuth, OtpAction, TextFieldAction, TextKeyboard,
    key_text_action, run_hold_screen as run_hold_screen_driver,
};
use warpgate_desktop_ui as ui;

use super::protocol::{Event as ServerEvent, Input as ServerInput};

/// How often the holding screen repaints (spinner animation cadence).
const HOLD_RENDER_INTERVAL: Duration = Duration::from_millis(100);

/// Render a holding screen to the viewer and collect the interactive second factor — a
/// TOTP typed on the viewer's keyboard, or an out-of-band web approval — until the auth
/// state is fully accepted. Returns the authenticated user on success, `None` on failure
/// or viewer disconnect. Input events are read from the same channel as the main control
/// loop, so it hands us `&mut events` for the duration.
pub(super) async fn run_hold_screen(
    services: &Services,
    interactive: &InteractiveAuth,
    events: &mut UnboundedReceiver<ServerEvent>,
    server_in_tx: &Sender<ServerInput>,
    screen: &mut ui::Screen,
) -> Result<Option<AuthStateUserInfo>> {
    // A resize can arrive mid-hold (a viewer window drag, or mstsc's initial Display Control
    // layout): the input reader records it here and the painter follows it. Shared behind a
    // lock because the reader and the painter are separate objects (so the driver can await
    // input and paint without aliasing one `&mut` across its `select!`); the lock is never
    // held across an await, which keeps the reader cancel-safe.
    let shared_screen = Arc::new(Mutex::new(*screen));
    let mut input = RdpHoldInput {
        events,
        screen: shared_screen.clone(),
    };
    let mut painter = RdpHoldPainter {
        inner: HoldPainter::new(*screen),
        server_in_tx: server_in_tx.clone(),
        screen: shared_screen.clone(),
    };

    let result = run_hold_screen_driver(
        services,
        interactive.state_id,
        crate::PROTOCOL_NAME,
        &interactive.username,
        interactive.remote_ip,
        &mut input,
        &mut painter,
        Deadline::until_auth_state_expires(),
    )
    .await;

    // Hand the negotiated size back to the caller so it dials the target at it.
    *screen = *shared_screen.lock().unwrap_or_else(PoisonError::into_inner);
    result
}

/// Reads RDP viewer input for the hold screen, mapping scancodes / Unicode keys to OTP
/// actions and tracking the viewer's negotiated size.
struct RdpHoldInput<'a> {
    events: &'a mut UnboundedReceiver<ServerEvent>,
    screen: Arc<Mutex<ui::Screen>>,
}

impl HoldInputSource for RdpHoldInput<'_> {
    async fn next(&mut self) -> HoldEvent {
        match self.events.recv().await {
            None => HoldEvent::Disconnected,
            Some(ServerEvent::Input(DesktopInput::Key {
                keysym,
                scancode,
                down: true,
            })) => {
                let action = scancode
                    .and_then(scancode_otp_action)
                    .or_else(|| keysym.and_then(key_otp_action));
                tracing::debug!(?scancode, ?keysym, ?action, "MFA hold screen key event");
                action.map_or(HoldEvent::Other, HoldEvent::Otp)
            }
            Some(
                ServerEvent::Size { width, height } | ServerEvent::ResizeRequest { width, height },
            ) => {
                *self.screen.lock().unwrap_or_else(PoisonError::into_inner) =
                    ui::Screen { width, height };
                HoldEvent::Other
            }
            Some(_) => HoldEvent::Other,
        }
    }
}

/// Paints the RDP hold screen: renders the UI to RGB, converts to BGRA and pushes a
/// full-screen frame via the shared [`HoldPainter`].
struct RdpHoldPainter {
    inner: HoldPainter,
    server_in_tx: Sender<ServerInput>,
    screen: Arc<Mutex<ui::Screen>>,
}

impl HoldPainterExt for RdpHoldPainter {
    async fn paint(&mut self, frame: HoldFrame<'_>) -> Result<()> {
        self.inner
            .set_screen(*self.screen.lock().unwrap_or_else(PoisonError::into_inner));
        match frame {
            HoldFrame::Prompt(prompt) => {
                self.inner
                    .paint(&self.server_in_tx, |screen, tick| {
                        ui::render_authentication(screen, tick, prompt)
                    })
                    .await
            }
            HoldFrame::Connecting => {
                self.inner
                    .paint(&self.server_in_tx, ui::render_connecting)
                    .await
            }
        }
    }

    fn render_interval(&self) -> Duration {
        HOLD_RENDER_INTERVAL
    }
}

/// Show the login banner and block until the viewer acknowledges it with any key or click.
/// Returns `false` if the viewer disconnected instead. Like [`run_hold_screen`], it tracks
/// the viewer's negotiated size in `screen` while it holds the event stream.
pub(super) async fn run_banner_screen(
    banner: &str,
    events: &mut UnboundedReceiver<ServerEvent>,
    server_in_tx: &Sender<ServerInput>,
    screen: &mut ui::Screen,
) -> Result<bool> {
    let mut painter = HoldPainter::new(*screen);
    let mut ticker = tokio::time::interval(HOLD_RENDER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    return Ok(false);
                };
                match event {
                    ServerEvent::Input(DesktopInput::Key { down: true, .. }) => return Ok(true),
                    // Any button press
                    ServerEvent::Input(DesktopInput::Pointer { buttons, .. }) if buttons != 0 => {
                        return Ok(true);
                    }
                    ServerEvent::Size { width, height }
                    | ServerEvent::ResizeRequest { width, height } => {
                        *screen = ui::Screen { width, height };
                        painter.set_screen(*screen);
                    }
                    _ => (),
                }
            },
            _ = ticker.tick() => {
                painter
                    .paint(server_in_tx, |screen, tick| ui::render_banner(screen, tick, banner))
                    .await?;
            },
        }
    }
}

/// Longest password this screen will accept from the viewer — bounds memory from a
/// stuck/malicious viewer, well past any real target password.
const MAX_CREDENTIAL_LEN: usize = 256;

/// Show an in-session password prompt for a Requester-mode RDP target and collect what the
/// viewer types. `username` (already resolved via the access policy's login template, mirrors
/// `SSHTargetAuth::Requester`) is only displayed, never editable here — this screen collects
/// the password alone. `error`, when set, is shown above the field: the reason a previous
/// attempt with this same login name was rejected, so a retry isn't a guess. Returns `None` if
/// the viewer disconnected before submitting. Like [`run_banner_screen`], tracks the viewer's
/// negotiated size in `screen`.
///
/// See `ARCHITECTURE_TECHNIQUE.md` §10 ("RDP + Requester par écran de saisie in-session").
pub(super) async fn run_credential_screen(
    events: &mut UnboundedReceiver<ServerEvent>,
    server_in_tx: &Sender<ServerInput>,
    screen: &mut ui::Screen,
    username: &str,
    keyboard_layout: u32,
    error: Option<&str>,
) -> Result<Option<String>> {
    let mut password = String::new();
    let mut revealed = false;
    let mut ctrl_down = false;
    // Set only by an explicit Ctrl+V *inside this screen*, and consumed by the very next
    // `Clipboard` event. The CLIPRDR channel auto-syncs the viewer's clipboard the instant it
    // changes — `on_remote_copy` in `clipboard.rs` requests the data unconditionally, with no
    // signal that anything actually wants to paste — so without this gate, whatever text
    // happened to already be on the viewer's clipboard (e.g. their portal password, copied at
    // any earlier point) silently fills the password field before they type anything.
    let mut expecting_paste = false;
    // Owns Shift/CapsLock state across key events the way a real keyboard driver would — RDP
    // delivers press and release as separate scancode events, not a modifier bitmask. Prefers a
    // real compiled `xkbcommon` keymap for `keyboard_layout` (see `TextKeyboard`'s docs), so
    // typing isn't scrambled on any keyboard `xkeyboard-config` knows, not just the ones this
    // screen was originally tested against.
    let mut keyboard = TextKeyboard::new(keyboard_layout);
    let mut painter = HoldPainter::new(*screen);
    let mut ticker = tokio::time::interval(HOLD_RENDER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Recomputed on resize (`ServerEvent::Size`) — the single source of truth `render_credential`
    // also draws from, so a click can never land somewhere the button isn't actually drawn.
    let mut layout = ui::credential_layout(*screen);
    let mut left_button_down = false;

    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    return Ok(None);
                };
                match event {
                    ServerEvent::Input(DesktopInput::Key {
                        scancode: Some(scancode),
                        down,
                        ..
                    }) => {
                        // F1 (0x3b) toggles the plaintext reveal — intercepted before the
                        // keyboard translator so it never types into the password itself.
                        if scancode.code == 0x3b && !scancode.extended {
                            if down {
                                revealed = !revealed;
                            }
                            continue;
                        }
                        // Left (0x1d) or right (extended 0x1d) Ctrl — tracked so a Ctrl+<key>
                        // shortcut (Ctrl+V above all) doesn't also type that key's plain
                        // character into the password.
                        if scancode.code == 0x1d {
                            ctrl_down = down;
                        } else if scancode.code == 0x2f
                            && !scancode.extended
                            && down
                            && ctrl_down
                        {
                            expecting_paste = true;
                        }

                        let action = keyboard.key_action(scancode, down);
                        tracing::debug!(
                            ?scancode,
                            down,
                            ?action,
                            "Requester credential screen key event"
                        );
                        if !ctrl_down
                            && let Some(action) = action
                            && apply_credential_action(&mut password, action)
                        {
                            return Ok(Some(password));
                        }
                    }
                    ServerEvent::Input(DesktopInput::Key {
                        keysym: Some(keysym),
                        down: true,
                        ..
                    }) => {
                        if let Some(action) = key_text_action(keysym)
                            && apply_credential_action(&mut password, action)
                        {
                            return Ok(Some(password));
                        }
                    }
                    // The viewer pasted (Ctrl+V) — arrives over CLIPRDR, not as key events, so
                    // it needs its own arm. Only applied if `expecting_paste` was just armed by
                    // an explicit Ctrl+V above — see its docs for why that gate exists. Same
                    // length bound as typed characters.
                    ServerEvent::Input(DesktopInput::Clipboard(text)) => {
                        if expecting_paste {
                            expecting_paste = false;
                            for c in text.chars() {
                                if password.len() >= MAX_CREDENTIAL_LEN {
                                    break;
                                }
                                password.push(c);
                            }
                        }
                    }
                    ServerEvent::Size { width, height } => {
                        *screen = ui::Screen { width, height };
                        painter.set_screen(*screen);
                        layout = ui::credential_layout(*screen);
                    }
                    ServerEvent::Input(DesktopInput::Pointer { x, y, buttons }) => {
                        let is_left_down = buttons & 1 != 0;
                        if is_left_down && !left_button_down {
                            let (px, py) = (i32::from(x), i32::from(y));
                            if layout.show.contains(px, py) {
                                revealed = !revealed;
                            } else if layout.cancel.contains(px, py) {
                                close_with_message(server_in_tx, screen, "Cancelled.").await;
                                return Ok(None);
                            } else if layout.login.contains(px, py)
                                && apply_credential_action(&mut password, TextFieldAction::Submit)
                            {
                                return Ok(Some(password));
                            }
                        }
                        left_button_down = is_left_down;
                    }
                    _ => (),
                }
            },
            _ = ticker.tick() => {
                painter
                    .paint(server_in_tx, |screen, tick| {
                        ui::render_authentication(
                            screen,
                            tick,
                            &ui::AuthPrompt::Credential {
                                username: username.to_owned(),
                                password: password.clone(),
                                revealed,
                                error: error.map(ToOwned::to_owned),
                            },
                        )
                    })
                    .await?;
            },
        }
    }
}

/// How long the closing message stays on screen before the connection actually drops —
/// long enough to read, short enough not to feel like a hang.
const CLOSING_MESSAGE_DURATION: Duration = Duration::from_secs(3);

/// Show a final message, then end the session. Without this, the viewer's last frame is
/// whatever the previous screen happened to say (often a stale retry prompt), and the
/// connection just drops under it — mstsc's own generic disconnect dialog then appears to
/// stack on top of an unrelated message instead of explaining why the session actually ended.
/// Best-effort throughout: a viewer that has already gone away just doesn't see it, which is
/// fine — there's no one to show it to.
pub(super) async fn close_with_message(
    server_in_tx: &Sender<ServerInput>,
    screen: &mut ui::Screen,
    message: &str,
) {
    let mut painter = HoldPainter::new(*screen);
    let _ = painter
        .paint(server_in_tx, |screen, tick| {
            ui::render_closing(screen, tick, message)
        })
        .await;
    tokio::time::sleep(CLOSING_MESSAGE_DURATION).await;
    let _ = server_in_tx.send(ServerInput::Shutdown).await;
}

/// Apply one text-field action to the password buffer. Returns `true` once the viewer
/// submits a non-empty password. `NextField` is a no-op — this screen has only one field.
fn apply_credential_action(password: &mut String, action: TextFieldAction) -> bool {
    match action {
        TextFieldAction::Char(c) => {
            if password.len() < MAX_CREDENTIAL_LEN {
                password.push(c);
            }
            false
        }
        TextFieldAction::Backspace => {
            password.pop();
            false
        }
        TextFieldAction::NextField => false,
        TextFieldAction::Submit => !password.is_empty(),
    }
}

/// Paints the full-screen hold-screen UI to the RDP viewer, owning the spinner tick and
/// keeping the RDP server's desktop in step with the negotiated size. `paint` takes a UI
/// render function (`ui::render_*`) so the prompt and "Connecting" screens go through one
/// code path.
struct HoldPainter {
    tick: u64,
    screen: ui::Screen,
    /// The size the RDP server was last told to run at.
    server_screen: ui::Screen,
}

impl HoldPainter {
    const fn new(screen: ui::Screen) -> Self {
        Self {
            tick: 0,
            screen,
            server_screen: screen,
        }
    }

    const fn set_screen(&mut self, screen: ui::Screen) {
        self.screen = screen;
    }

    /// Render one frame with `render_frame(tick)` (RGB888), convert it to the BGRA the RDP
    /// server expects, and push it as a full-screen frame. Advances the spinner tick.
    ///
    /// A changed size is pushed to the server first, so it never sees a frame larger than
    /// its desktop. Pre-dial there is no target to consult, so a viewer's resize request is
    /// granted as-is (a size the server already runs at is ignored by it). This happens here
    /// rather than where the resize event is read because the input reader is polled inside
    /// the driver's `select!` and can be dropped mid-await, whereas `paint` runs to completion.
    async fn paint(
        &mut self,
        server_in_tx: &Sender<ServerInput>,
        render_frame: impl FnOnce(ui::Screen, u64) -> Result<Vec<u8>, Infallible>,
    ) -> Result<()> {
        if self.screen != self.server_screen {
            Self::send(
                server_in_tx,
                ServerInput::Resize {
                    width: self.screen.width,
                    height: self.screen.height,
                },
            )
            .await?;
            self.server_screen = self.screen;
        }

        let rgb = render_frame(self.screen, self.tick).unwrap_or_default();
        self.tick = self.tick.wrapping_add(1);

        let mut bgra = Vec::with_capacity(rgb.len() / 3 * 4);
        for px in rgb.as_chunks::<3>().0 {
            if let Some(&[r, g, b]) = px.first_chunk::<3>() {
                bgra.extend_from_slice(&[b, g, r, 255]);
            }
        }
        Self::send(
            server_in_tx,
            ServerInput::Frame {
                x: 0,
                y: 0,
                width: self.screen.width,
                height: self.screen.height,
                data: bgra.into(),
            },
        )
        .await
    }

    async fn send(server_in_tx: &Sender<ServerInput>, input: ServerInput) -> Result<()> {
        server_in_tx
            .send(input)
            .await
            .map_err(|_| anyhow!("RDP server channel closed"))
    }
}

/// Map a PC/AT set-1 scancode (what mstsc/FreeRDP send) to an OTP action.
fn scancode_otp_action(scancode: Scancode) -> Option<OtpAction> {
    let Scancode { code, extended } = scancode;
    // The nav cluster shares its make codes with the keypad and is told apart only by the
    // E0 prefix, so without this an arrow key would type a digit. Numpad Enter is the one
    // extended key that still means something here.
    if extended && code != 0x1c {
        return None;
    }
    Some(match code {
        0x02..=0x0a => OtpAction::Digit(char::from(b'1' + (code - 0x02))), // top row 1..9
        0x0b | 0x52 => OtpAction::Digit('0'),                              // keypad 0
        0x4f => OtpAction::Digit('1'),
        0x50 => OtpAction::Digit('2'),
        0x51 => OtpAction::Digit('3'),
        0x4b => OtpAction::Digit('4'),
        0x4c => OtpAction::Digit('5'),
        0x4d => OtpAction::Digit('6'),
        0x47 => OtpAction::Digit('7'),
        0x48 => OtpAction::Digit('8'),
        0x49 => OtpAction::Digit('9'),
        0x0e => OtpAction::Backspace,
        0x1c => OtpAction::Submit, // Enter (main + keypad)
        _ => return None,
    })
}

/// Map a Unicode keypress (viewers that send `Key` instead of scancodes) to an OTP action.
fn key_otp_action(keysym: u32) -> Option<OtpAction> {
    Some(match keysym {
        0x30..=0x39 => OtpAction::Digit(char::from(u8::try_from(keysym).ok()?)), // '0'..'9'
        0x08 => OtpAction::Backspace,
        0x0d | 0x0a => OtpAction::Submit, // CR / LF
        _ => return None,
    })
}

#[cfg(test)]
mod otp_input_tests {
    use super::{OtpAction, Scancode, key_otp_action, scancode_otp_action};

    fn digit(action: Option<OtpAction>) -> Option<char> {
        match action {
            Some(OtpAction::Digit(c)) => Some(c),
            _ => None,
        }
    }

    fn plain(code: u8) -> Option<OtpAction> {
        scancode_otp_action(Scancode {
            code,
            extended: false,
        })
    }

    fn e0(code: u8) -> Option<OtpAction> {
        scancode_otp_action(Scancode {
            code,
            extended: true,
        })
    }

    #[test]
    fn scancode_number_row() {
        // 0x02..=0x0a is the '1'..'9' row (computed, so guard the ends), 0x0b is '0'.
        assert_eq!(digit(plain(0x02)), Some('1'));
        assert_eq!(digit(plain(0x0a)), Some('9'));
        assert_eq!(digit(plain(0x0b)), Some('0'));
    }

    #[test]
    fn scancode_keypad() {
        for (code, expected) in [
            (0x52u8, '0'),
            (0x4f, '1'),
            (0x50, '2'),
            (0x51, '3'),
            (0x4b, '4'),
            (0x4c, '5'),
            (0x4d, '6'),
            (0x47, '7'),
            (0x48, '8'),
            (0x49, '9'),
        ] {
            assert_eq!(digit(plain(code)), Some(expected), "scancode {code:#x}");
        }
    }

    /// The nav cluster repeats the keypad's make codes under an E0 prefix; pressing an
    /// arrow must not enter a digit.
    #[test]
    fn scancode_nav_cluster_is_not_a_digit() {
        for code in [0x47u8, 0x48, 0x49, 0x4b, 0x4d, 0x4f, 0x50, 0x51, 0x52] {
            assert!(e0(code).is_none(), "extended scancode {code:#x}");
        }
        assert!(matches!(e0(0x1c), Some(OtpAction::Submit))); // numpad Enter
    }

    #[test]
    fn scancode_control_and_unmapped() {
        assert!(matches!(plain(0x0e), Some(OtpAction::Backspace)));
        assert!(matches!(plain(0x1c), Some(OtpAction::Submit)));
        assert!(plain(0x3b).is_none()); // F1 — not an OTP key
        assert!(plain(0x00).is_none());
    }

    #[test]
    fn keysym_digits_control_and_unmapped() {
        for d in 0..=9u8 {
            let c = char::from(b'0' + d);
            assert_eq!(digit(key_otp_action(u32::from(c))), Some(c));
        }
        assert!(matches!(key_otp_action(0x08), Some(OtpAction::Backspace)));
        assert!(matches!(key_otp_action(0x0d), Some(OtpAction::Submit)));
        assert!(matches!(key_otp_action(0x0a), Some(OtpAction::Submit)));
        assert!(key_otp_action(u32::from('A')).is_none());
        assert!(key_otp_action(u32::from(' ')).is_none());
    }
}

/// Drives [`run_credential_screen`] through fake `ServerEvent`/`ServerInput` channels, the
/// way the real control loop feeds it — no `Services`/DB involved, since this screen never
/// touches auth state. Exercises what the pure `text_entry` mapping-function tests can't: the
/// shift-state bookkeeping and the `tokio::select!` loop itself.
#[cfg(test)]
mod credential_screen_tests {
    use tokio::sync::mpsc::{channel, unbounded_channel};
    use tokio::time::{Duration, timeout};

    use super::*;

    fn key(code: u8, down: bool) -> ServerEvent {
        ServerEvent::Input(DesktopInput::Key {
            keysym: None,
            scancode: Some(Scancode {
                code,
                extended: false,
            }),
            down,
        })
    }

    fn pointer(x: u16, y: u16, buttons: u8) -> ServerEvent {
        ServerEvent::Input(DesktopInput::Pointer { x, y, buttons })
    }

    const LEFT_SHIFT: u8 = 0x2a;
    const ENTER: u8 = 0x1c;
    const BACKSPACE: u8 = 0x0e;
    const LEFT_BUTTON: u8 = 1;

    /// Spawns `run_credential_screen` against a fresh pair of channels and a generously
    /// buffered `server_in` (frames are painted every 100ms; the test channel just needs to
    /// outlast the test, not be drained).
    fn spawn_screen() -> (
        tokio::sync::mpsc::UnboundedSender<ServerEvent>,
        tokio::task::JoinHandle<anyhow::Result<Option<String>>>,
    ) {
        let (events_tx, mut events_rx) = unbounded_channel::<ServerEvent>();
        let (server_in_tx, mut server_in_rx) = channel::<ServerInput>(256);
        // Keeps the receiver alive for the screen's whole run — dropping it would make
        // `HoldPainter::paint`'s send fail on the first render tick and end the screen with
        // an error instead of letting it keep reading input. Exits on its own once the
        // screen task ends and drops `server_in_tx`.
        tokio::spawn(async move { while server_in_rx.recv().await.is_some() {} });
        let handle = tokio::spawn(async move {
            let mut screen = ui::Screen {
                width: 800,
                height: 600,
            };
            run_credential_screen(&mut events_rx, &server_in_tx, &mut screen, "someuser", 0, None)
                .await
        });
        (events_tx, handle)
    }

    #[tokio::test]
    async fn types_with_shift_and_submits() {
        let (events_tx, handle) = spawn_screen();

        // Shift+h, i, Shift+1, Enter -> "Hi!" — exercises shift tracked across separate
        // press/release events, not just a single `scancode_text_action` call.
        for event in [
            key(LEFT_SHIFT, true),
            key(0x23, true), // h -> 'H' while shifted
            key(0x23, false),
            key(LEFT_SHIFT, false),
            key(0x17, true), // i -> 'i' unshifted
            key(0x17, false),
            key(LEFT_SHIFT, true),
            key(0x02, true), // 1 -> '!' while shifted
            key(0x02, false),
            key(LEFT_SHIFT, false),
            key(ENTER, true),
        ] {
            events_tx.send(event).expect("screen task still running");
        }

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), Some("Hi!".to_owned()));
    }

    /// Clicking "Login" is equivalent to pressing Enter — same `Submit` action, just via the
    /// pointer. Coordinates are computed for `spawn_screen`'s 800x600 test screen from
    /// `ui::credential_layout`'s formulas: cx=400, field_y=484, login rect x0..x1=252..392,
    /// y0..y1=544..584 — (300, 560) sits inside it.
    #[tokio::test]
    async fn clicking_login_submits_like_enter() {
        let (events_tx, handle) = spawn_screen();
        for event in [
            key(0x1e, true), // a
            key(0x1e, false),
            pointer(300, 560, LEFT_BUTTON), // press inside the Login button
        ] {
            events_tx.send(event).expect("screen task still running");
        }

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), Some("a".to_owned()));
    }

    /// Clicking "Cancel" ends the screen with `None`, same as a disconnect — but only after
    /// `close_with_message` paints a closing frame and holds it for
    /// `CLOSING_MESSAGE_DURATION`, hence the generous timeout. Coordinates: cancel rect
    /// x0..x1=408..548, y0..y1=544..584 — (450, 560) sits inside it.
    #[tokio::test]
    async fn clicking_cancel_ends_the_screen_with_none() {
        let (events_tx, handle) = spawn_screen();
        events_tx
            .send(pointer(450, 560, LEFT_BUTTON))
            .expect("screen task still running");

        let result = timeout(CLOSING_MESSAGE_DURATION + Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), None);
    }

    /// Clicking "Show" toggles plaintext reveal — same effect as F1, just via the pointer; not
    /// directly observable from `run_credential_screen`'s return value, so this only checks
    /// that a click there does *not* submit or cancel the screen (a wrong hit-test would).
    /// Coordinates: show rect x0..x1=509..579, y0..y1=484..524 — (540, 500) sits inside it.
    #[tokio::test]
    async fn clicking_show_does_not_submit_or_cancel() {
        let (events_tx, handle) = spawn_screen();
        for event in [
            key(0x1e, true), // a
            key(0x1e, false),
            pointer(540, 500, LEFT_BUTTON), // press inside the Show button
            key(ENTER, true),
        ] {
            events_tx.send(event).expect("screen task still running");
        }

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), Some("a".to_owned()));
    }

    #[tokio::test]
    async fn backspace_removes_the_last_character() {
        let (events_tx, handle) = spawn_screen();
        for event in [
            key(0x1e, true), // a
            key(0x1e, false),
            key(BACKSPACE, true),
            key(0x1f, true), // s
            key(0x1f, false),
            key(ENTER, true),
        ] {
            events_tx.send(event).expect("screen task still running");
        }

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), Some("s".to_owned()));
    }

    const LEFT_CTRL: u8 = 0x1d;
    const V: u8 = 0x2f;

    /// Reproduces a real bug: the CLIPRDR channel auto-syncs the viewer's clipboard the
    /// instant it changes, independent of any explicit paste — so without gating on Ctrl+V,
    /// whatever text was already on the clipboard (e.g. the viewer's portal password, copied
    /// at any earlier point) silently filled this field before they typed anything.
    #[tokio::test]
    async fn clipboard_content_is_ignored_without_an_explicit_ctrl_v() {
        let (events_tx, handle) = spawn_screen();
        events_tx
            .send(ServerEvent::Input(DesktopInput::Clipboard(
                "totopass123".to_owned(),
            )))
            .unwrap();
        events_tx.send(key(0x1e, true)).unwrap(); // a
        events_tx.send(key(0x1e, false)).unwrap();
        events_tx.send(key(ENTER, true)).unwrap();

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), Some("a".to_owned()));
    }

    #[tokio::test]
    async fn ctrl_v_pastes_clipboard_content() {
        let (events_tx, handle) = spawn_screen();
        for event in [
            key(LEFT_CTRL, true),
            key(V, true),
            key(V, false),
            key(LEFT_CTRL, false),
        ] {
            events_tx.send(event).unwrap();
        }
        events_tx
            .send(ServerEvent::Input(DesktopInput::Clipboard(
                "hunter2".to_owned(),
            )))
            .unwrap();
        events_tx.send(key(ENTER, true)).unwrap();

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), Some("hunter2".to_owned()));
    }

    #[tokio::test]
    async fn submitting_an_empty_password_does_not_end_the_screen() {
        let (events_tx, handle) = spawn_screen();
        events_tx.send(key(ENTER, true)).unwrap();
        events_tx.send(key(0x1e, true)).unwrap(); // a
        events_tx.send(key(0x1e, false)).unwrap();
        events_tx.send(key(ENTER, true)).unwrap();

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), Some("a".to_owned()));
    }

    #[tokio::test]
    async fn viewer_disconnect_ends_the_screen_with_none() {
        let (events_tx, handle) = spawn_screen();
        drop(events_tx);

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("screen task timed out")
            .expect("screen task panicked");
        assert_eq!(result.unwrap(), None);
    }
}
