//! Renders the "connecting" / auth screens shown to a native desktop viewer (RDP or VNC)
#![allow(clippy::cast_precision_loss, clippy::suboptimal_flops)]

mod bouncy_ball;
mod framebuffer;
mod logo;

use std::convert::Infallible;
use std::fmt::Write;

use embedded_graphics::image::Image;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::FONT_10X20;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{CornerRadii, PrimitiveStyle, Rectangle, RoundedRectangle};
use embedded_graphics::text::{Alignment, Text};
use framebuffer::Framebuffer;
use warpgate_common::helpers::otp::OTP_DIGITS;

/// Framebuffer size assumed before a viewer or target reports its own.
pub const DEFAULT_SCREEN_W: u16 = 1024;
pub const DEFAULT_SCREEN_H: u16 = 768;
pub const DEFAULT_SIZE: (u16, u16) = (DEFAULT_SCREEN_W, DEFAULT_SCREEN_H);

pub use self::{DEFAULT_SCREEN_H as SCREEN_H, DEFAULT_SCREEN_W as SCREEN_W};
use crate::char_boxes::{draw_char_boxes, draw_field_box};
use crate::logo::logo;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Screen {
    pub width: u16,
    pub height: u16,
}

impl Default for Screen {
    fn default() -> Self {
        Self {
            width: SCREEN_W,
            height: SCREEN_H,
        }
    }
}

const BG: Rgb888 = Rgb888::new(0x14, 0x14, 0x1a);
const FG: Rgb888 = Rgb888::new(0xc1, 0xc9, 0xe4);

pub fn render_connecting(screen: Screen, tick: u64) -> Result<Vec<u8>, Infallible> {
    render(screen, tick, "Connecting", None)
}

/// The login banner, shown until the viewer acknowledges it with any key or click.
pub fn render_banner(screen: Screen, tick: u64, banner: &str) -> Result<Vec<u8>, Infallible> {
    render(
        screen,
        tick,
        &format!("{banner}\n\nPress any key to continue"),
        None,
    )
}

/// A final message shown briefly before the session ends (too many failed attempts, an
/// internal error, ...). Without this, the viewer's last frame is whatever the previous screen
/// happened to say — often a stale retry prompt — and the connection just drops under it, so
/// mstsc's own generic disconnect dialog appears to stack on top of an unrelated message
/// instead of explaining why the session actually ended.
pub fn render_closing(screen: Screen, tick: u64, message: &str) -> Result<Vec<u8>, Infallible> {
    let cleaned = strip_source_annotations(message);
    let max_chars = usize::from(screen.width / 10).saturating_sub(6).max(20);
    render(screen, tick, &wrap_text(&cleaned, max_chars), None)
}

/// An axis-aligned pixel rectangle, half-open (`x1`/`y1` excluded) — matches how
/// [`credential_layout`] hands out click regions and how a pointer event's `(x, y)` is
/// hit-tested against them.
#[derive(Clone, Copy, Debug)]
pub struct ClickRect {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
}

impl ClickRect {
    #[must_use]
    pub const fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.x0 && x < self.x1 && y >= self.y0 && y < self.y1
    }
}

/// The credential screen's clickable regions, in the same pixel space as the viewer's pointer
/// events. [`credential_layout`] is the single source of truth both [`render_credential`] (to
/// draw them) and the caller (to hit-test clicks) consult, so the two can never drift apart.
#[derive(Clone, Copy, Debug)]
pub struct CredentialButtons {
    pub show: ClickRect,
    pub login: ClickRect,
    pub cancel: ClickRect,
}

const FIELD_BOX_W: i32 = 280;
const SHOW_BUTTON_W: i32 = 70;
const BUTTON_GAP: i32 = 8;
const FIELD_ROW_H: i32 = 40;
const LOGIN_BUTTON_W: i32 = 140;
const CANCEL_BUTTON_W: i32 = 140;
const BUTTON_ROW_GAP: i32 = 16;
const LINE_H: i32 = 26;
/// Lines reserved for the (possibly wrapped) error message, regardless of its actual length —
/// keeps the field and buttons at a fixed position instead of shifting with error length, which
/// is what let [`credential_layout`] be a pure function of `screen` alone.
const ERROR_LINES: i32 = 3;

/// Pure geometry for the credential screen — no drawing, just where things go. Fixed relative
/// to `screen` alone (a reserved-height block absorbs the error text instead of reflowing
/// everything below it), so a click can be hit-tested without re-deriving whatever the last
/// frame's error text happened to be.
#[must_use]
pub fn credential_layout(screen: Screen) -> CredentialButtons {
    let (w, h) = (i32::from(screen.width), i32::from(screen.height));
    let cx = w / 2;
    let cy = h / 2 - 24;

    let field_y = cy + 88 + LINE_H + LINE_H * ERROR_LINES + 16;
    let field_row_w = FIELD_BOX_W + BUTTON_GAP + SHOW_BUTTON_W;
    let field_x0 = cx - field_row_w / 2;
    let show_x0 = field_x0 + FIELD_BOX_W + BUTTON_GAP;
    let show = ClickRect {
        x0: show_x0,
        y0: field_y,
        x1: show_x0 + SHOW_BUTTON_W,
        y1: field_y + FIELD_ROW_H,
    };

    let button_y = field_y + FIELD_ROW_H + 20;
    let button_row_w = LOGIN_BUTTON_W + BUTTON_ROW_GAP + CANCEL_BUTTON_W;
    let login_x0 = cx - button_row_w / 2;
    let cancel_x0 = login_x0 + LOGIN_BUTTON_W + BUTTON_ROW_GAP;
    let login = ClickRect {
        x0: login_x0,
        y0: button_y,
        x1: login_x0 + LOGIN_BUTTON_W,
        y1: button_y + FIELD_ROW_H,
    };
    let cancel = ClickRect {
        x0: cancel_x0,
        y0: button_y,
        x1: cancel_x0 + CANCEL_BUTTON_W,
        y1: button_y + FIELD_ROW_H,
    };

    CredentialButtons {
        show,
        login,
        cancel,
    }
}

/// Renders the Requester credential prompt: username, a fixed-height reserved error block,
/// the password field with an inline "Show"/"Hide" button, and a Login/Cancel button row —
/// laid out by [`credential_layout`], which callers use to hit-test pointer clicks against the
/// same regions drawn here.
pub fn render_credential(
    screen: Screen,
    tick: u64,
    username: &str,
    password: &str,
    revealed: bool,
    error: Option<&str>,
) -> Result<Vec<u8>, Infallible> {
    let (w, h) = (i32::from(screen.width), i32::from(screen.height));
    let mut fb = Framebuffer::new(u32::from(screen.width), u32::from(screen.height), BG);
    let cx = w / 2;
    let cy = h / 2 - 24;

    let image = logo();
    let x0 = (w - image.size().width.cast_signed()) / 2;
    let logo_y = LOGO_Y
        .min(cy - image.size().height.cast_signed() - LOGO_GAP)
        .max(0);
    Image::new(image, Point::new(x0, logo_y)).draw(&mut fb)?;

    let style = MonoTextStyle::new(&FONT_10X20, FG);
    Text::with_alignment(
        username,
        Point::new(cx, cy + 88),
        style,
        Alignment::Center,
    )
    .draw(&mut fb)?;

    if let Some(error) = error {
        let cleaned = strip_source_annotations(error);
        let max_chars = usize::from(screen.width / 10).saturating_sub(6).max(20);
        let wrapped = wrap_text(&cleaned, max_chars);
        #[allow(clippy::cast_sign_loss)]
        for (i, line) in wrapped.lines().take(ERROR_LINES as usize).enumerate() {
            #[allow(clippy::cast_possible_wrap)]
            let y = cy + 88 + LINE_H + (i as i32) * LINE_H;
            Text::with_alignment(line, Point::new(cx, y), style, Alignment::Center).draw(&mut fb)?;
        }
    }

    let layout = credential_layout(screen);

    // Password field — same masked/blinking-cursor content as before, drawn narrower now that
    // the "Show" button sits beside it instead of being keyboard-only.
    let content = if revealed {
        password.to_owned()
    } else {
        "*".repeat(password.chars().count())
    };
    let field_content = if tick % 10 < 5 {
        format!("{content}_")
    } else {
        content
    };
    draw_field_box(
        &mut fb,
        layout.show.x0 - BUTTON_GAP - FIELD_BOX_W,
        layout.show.y0,
        FIELD_BOX_W,
        &field_content,
        style,
    );

    draw_button(&mut fb, layout.show, if revealed { "Hide" } else { "Show" });
    draw_button(&mut fb, layout.login, "Login");
    draw_button(&mut fb, layout.cancel, "Cancel");

    let ball_y = layout.login.y1 + 30;
    bouncy_ball::bouncy_ball(tick, cx, ball_y)
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(&mut fb)?;

    Ok(fb.take_pixels())
}

/// Draw one rectangular button: a filled `FG` box (so it reads as "pressable" the way the
/// stroke-only password field reads as "typeable"), with its label in `BG` for contrast — the
/// same fill/text-color inversion `draw_char_boxes` already uses for the OTP slots.
fn draw_button(fb: &mut Framebuffer, rect: ClickRect, label: &str) {
    let w = u32::try_from(rect.x1 - rect.x0).unwrap_or(0);
    let h = u32::try_from(rect.y1 - rect.y0).unwrap_or(0);
    let _ = RoundedRectangle::new(
        Rectangle::new(Point::new(rect.x0, rect.y0), Size::new(w, h)),
        CornerRadii::new(Size::new_equal(4)),
    )
    .into_styled(PrimitiveStyle::with_fill(FG))
    .draw(fb);
    let style = MonoTextStyle::new(&FONT_10X20, BG);
    let cx = (rect.x0 + rect.x1) / 2;
    let cy = (rect.y0 + rect.y1) / 2 + 6;
    let _ = Text::with_alignment(label, Point::new(cx, cy), style, Alignment::Center).draw(fb);
}

pub enum AuthPrompt {
    WebApproval {
        url: Option<String>,
        security_key: String,
    },
    Otp {
        entered: String,
    },
    /// A target-side credential prompt for a Requester-mode connection (see
    /// `ARCHITECTURE_TECHNIQUE.md` §10, "RDP + Requester par écran de saisie in-session").
    /// The login name is already resolved via the access policy's login template, so this
    /// only asks for the password. `password` is masked to `*` unless `revealed` is set (the
    /// viewer toggled the F1 "show password" hint) — plaintext only reaches this renderer at
    /// all when the viewer explicitly asked to see it.
    /// `error`, when set, is the reason the previous attempt with this login name was
    /// rejected (by the target or by Warpgate) — shown so the viewer can retry informed
    /// instead of guessing why the screen came back.
    Credential {
        username: String,
        password: String,
        revealed: bool,
        error: Option<String>,
    },
}

pub fn render_authentication(
    screen: Screen,
    tick: u64,
    prompt: &AuthPrompt,
) -> Result<Vec<u8>, Infallible> {
    match prompt {
        AuthPrompt::WebApproval { url, security_key } => {
            let mut text = String::new();
            match url {
                Some(url) => {
                    let _ = write!(
                        text,
                        "Approve this session at:\n{url}\n(has been copied to your clipboard)"
                    );
                }
                None => text.push_str("Please approve this session in Warpgate first"),
            }
            let boxes = CharBoxes {
                text: security_key,
                slots: security_key.chars().count(),
            };
            text.push_str("\n\nSecurity key:");
            render(screen, tick, &text, Some(Decoration::Chars(boxes)))
        }
        AuthPrompt::Otp { entered } => render(
            screen,
            tick,
            "MFA\n\nOne-time password:",
            Some(Decoration::Chars(CharBoxes {
                text: entered,
                slots: OTP_DIGITS,
            })),
        ),
        AuthPrompt::Credential {
            username,
            password,
            revealed,
            error,
        } => render_credential(
            screen,
            tick,
            username,
            password,
            *revealed,
            error.as_deref(),
        ),
    }
}

/// Strips `[label @ file.rs:NN]` source-location annotations — emitted by ironrdp's
/// `custom_err!`/`general_err!` macros — from an error message before it's shown to someone
/// typing a password. They're internal debugging detail, not just verbose: left in, a long
/// file path routinely pushed the actual reason (e.g. "wrong password") off the edge of the
/// screen. A bracket without an `@` (e.g. an NTSTATUS code like `[0xc000006d]`) is left alone.
fn strip_source_annotations(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(start) = rest.find('[') {
        out.push_str(&rest[..start]);
        let Some(end_rel) = rest[start..].find(']') else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let end = start + end_rel;
        if rest[start + 1..end].contains('@') {
            rest = rest[end + 1..].strip_prefix(' ').unwrap_or(&rest[end + 1..]);
        } else {
            out.push_str(&rest[start..=end]);
            rest = &rest[end + 1..];
        }
    }
    out.push_str(rest);
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Greedily word-wraps `text` to at most `max_chars` per line, so a long message (an error
/// especially) breaks across lines instead of running off the edge of the screen. Doesn't
/// split individual words — a single word longer than `max_chars` is left on its own line.
fn wrap_text(text: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(text.len());
    let mut line_len = 0usize;
    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if line_len > 0 && line_len + 1 + word_len > max_chars {
            out.push('\n');
            line_len = 0;
        } else if line_len > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += word_len;
    }
    out
}

struct CharBoxes<'a> {
    text: &'a str,
    slots: usize,
}

/// What [`render`] draws under the prompt text, if anything: a row of small per-slot boxes
/// (OTP digits, the security key).
enum Decoration<'a> {
    Chars(CharBoxes<'a>),
}

/// Vertical gap kept between the logo and the ball once the screen is too short for
/// [`LOGO_Y`], below which the logo is pinned to the top edge.
const LOGO_GAP: i32 = 40;
/// Logo offset from the top on a screen with room to spare.
const LOGO_Y: i32 = 60;

fn render(
    screen: Screen,
    tick: u64,
    text: &str,
    decoration: Option<Decoration>,
) -> Result<Vec<u8>, Infallible> {
    let (w, h) = (i32::from(screen.width), i32::from(screen.height));
    let mut fb = Framebuffer::new(u32::from(screen.width), u32::from(screen.height), BG);

    let cx = w / 2;
    let cy = h / 2 - 24;

    let image = logo();
    let x0 = (w - image.size().width.cast_signed()) / 2;
    // Sits at a fixed offset when there's room, and slides up (never off) when there isn't.
    let logo_y = LOGO_Y
        .min(cy - image.size().height.cast_signed() - LOGO_GAP)
        .max(0);
    Image::new(image, Point::new(x0, logo_y)).draw(&mut fb)?;

    bouncy_ball::bouncy_ball(tick, cx, cy)
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(&mut fb)?;

    let style = MonoTextStyle::new(&FONT_10X20, FG);
    let mut y = cy + 88;
    for line in text.split('\n') {
        Text::with_alignment(line, Point::new(cx, y), style, Alignment::Center).draw(&mut fb)?;
        y += 26;
    }

    if let Some(Decoration::Chars(boxes)) = decoration {
        let box_style = MonoTextStyle::new(&FONT_10X20, BG);
        draw_char_boxes(&mut fb, cx, y + 8, boxes.text, boxes.slots, box_style);
    }

    Ok(fb.take_pixels())
}

mod char_boxes {
    use super::*;

    const OTP_BOX_W: i32 = 30;
    const OTP_BOX_H: i32 = 40;
    const OTP_BOX_GAP: i32 = 8;

    /// Draw a centred row of `slots` rounded boxes, filling each with the matching character of
    /// `text` (left to right); boxes past the end of `text` are left empty.
    pub fn draw_char_boxes(
        fb: &mut Framebuffer,
        cx: i32,
        y: i32,
        text: &str,
        slots: usize,
        style: MonoTextStyle<'_, Rgb888>,
    ) {
        #[allow(clippy::cast_possible_wrap)]
        let slots = slots as i32;
        let total_w = slots * OTP_BOX_W + (slots - 1) * OTP_BOX_GAP;
        let mut x = cx - total_w / 2;
        for i in 0..slots {
            let _ = RoundedRectangle::new(
                Rectangle::new(
                    Point::new(x, y),
                    Size::new(OTP_BOX_W as u32, OTP_BOX_H as u32),
                ),
                CornerRadii::new(Size::new_equal(3)),
            )
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(fb);
            if let Some(ch) = text.chars().nth(i as usize) {
                let _ = Text::with_alignment(
                    &ch.to_string(),
                    Point::new(x + OTP_BOX_W / 2 - 1, y + OTP_BOX_H / 2 + 6),
                    style,
                    Alignment::Center,
                )
                .draw(fb);
            }
            x += OTP_BOX_W + OTP_BOX_GAP;
        }
    }

    const FIELD_BOX_H: i32 = 40;
    const FIELD_PAD_X: i32 = 12;

    /// Draw a single bordered field box at `x0`/`y`, `width` wide — an input-style highlight so
    /// the credential screen's password isn't just floating text — showing the tail of
    /// `content` that fits (like a real password field, typing past the visible width scrolls
    /// instead of overflowing).
    pub fn draw_field_box(
        fb: &mut Framebuffer,
        x0: i32,
        y: i32,
        width: i32,
        content: &str,
        style: MonoTextStyle<'_, Rgb888>,
    ) {
        let rect = Rectangle::new(Point::new(x0, y), Size::new(width as u32, FIELD_BOX_H as u32));
        let _ = RoundedRectangle::new(rect, CornerRadii::new(Size::new_equal(4)))
            .into_styled(PrimitiveStyle::with_stroke(FG, 2))
            .draw(fb);

        // FONT_10X20 glyphs are 10px wide; leave padding on both sides of the box.
        let max_chars = usize::try_from((width - FIELD_PAD_X * 2) / 10).unwrap_or(0);
        let visible_start = content.chars().count().saturating_sub(max_chars);
        let visible: String = content.chars().skip(visible_start).collect();

        let _ = Text::with_alignment(
            &visible,
            Point::new(x0 + FIELD_PAD_X, y + FIELD_BOX_H / 2 + 6),
            style,
            Alignment::Left,
        )
        .draw(fb);
    }
}
