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
    render(screen, tick, "Connecting", None, BallPosition::AboveText)
}

/// The login banner, shown until the viewer acknowledges it with any key or click.
pub fn render_banner(screen: Screen, tick: u64, banner: &str) -> Result<Vec<u8>, Infallible> {
    render(
        screen,
        tick,
        &format!("{banner}\n\nPress any key to continue"),
        None,
        BallPosition::AboveText,
    )
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
            render(
                screen,
                tick,
                &text,
                Some(Decoration::Chars(boxes)),
                BallPosition::AboveText,
            )
        }
        AuthPrompt::Otp { entered } => render(
            screen,
            tick,
            "MFA\n\nOne-time password:",
            Some(Decoration::Chars(CharBoxes {
                text: entered,
                slots: OTP_DIGITS,
            })),
            BallPosition::AboveText,
        ),
        AuthPrompt::Credential {
            username,
            password,
            revealed,
            error,
        } => {
            let hint = if *revealed {
                "Press Enter to connect (F1 to hide)"
            } else {
                "Press Enter to connect (F1 to show)"
            };
            let mut text = format!("{username}\n\n{hint}");
            if let Some(error) = error {
                let cleaned = strip_source_annotations(error);
                let max_chars = usize::from(screen.width / 10).saturating_sub(6).max(20);
                let _ = write!(text, "\n\n{}", wrap_text(&cleaned, max_chars));
            }
            // `FONT_10X20` is ASCII-only (no bullet glyph) — a non-ASCII mask character
            // renders as a literal `?` box instead of masking anything.
            let content = if *revealed {
                password.clone()
            } else {
                "*".repeat(password.chars().count())
            };
            // Blinks rather than always showing — a permanently-drawn cursor on an otherwise
            // empty field reads as a stray leftover character someone has to delete before
            // typing, not an empty field waiting for input.
            let field = if tick % 10 < 5 {
                format!("{content}_")
            } else {
                content
            };
            render(
                screen,
                tick,
                &text,
                Some(Decoration::Field(&field)),
                BallPosition::BelowText,
            )
        }
    }
}

/// Where [`render`] draws the bouncy-ball spinner relative to the prompt text: above it (the
/// default, between the logo and the message — fine for short, fixed-length prompts) or below
/// it (for prompts whose length varies, like [`AuthPrompt::Credential`] with an error shown —
/// keeping the ball above would put it between the logo and a growing block of text instead of
/// acting as a stable "still working" indicator under the input).
#[derive(Clone, Copy, PartialEq, Eq)]
enum BallPosition {
    AboveText,
    BelowText,
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

/// What [`render`] draws under the prompt text, if anything: either a row of small per-slot
/// boxes (OTP digits, the security key) or a single bordered field (the Requester credential
/// screen's password — unbounded length, so one box showing a scrolling tail suits it better
/// than one slot per character).
enum Decoration<'a> {
    Chars(CharBoxes<'a>),
    Field(&'a str),
}

/// Height in pixels of either decoration kind, used to keep the spinner clear of it when drawn
/// below the text (`BallPosition::BelowText`).
const DECORATION_H: i32 = 40;

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
    ball_position: BallPosition,
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

    let draw_ball = |fb: &mut Framebuffer, y: i32| {
        bouncy_ball::bouncy_ball(tick, cx, y)
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(fb)
    };

    if ball_position == BallPosition::AboveText {
        draw_ball(&mut fb, cy)?;
    }

    let style = MonoTextStyle::new(&FONT_10X20, FG);
    let mut y = cy + 88;
    for line in text.split('\n') {
        Text::with_alignment(line, Point::new(cx, y), style, Alignment::Center).draw(&mut fb)?;
        y += 26;
    }

    let has_decoration = decoration.is_some();
    match decoration {
        Some(Decoration::Chars(boxes)) => {
            let box_style = MonoTextStyle::new(&FONT_10X20, BG);
            draw_char_boxes(&mut fb, cx, y + 8, boxes.text, boxes.slots, box_style);
        }
        Some(Decoration::Field(content)) => {
            let field_style = MonoTextStyle::new(&FONT_10X20, FG);
            draw_field_box(&mut fb, cx, y + 8, content, field_style);
        }
        None => {}
    }

    if ball_position == BallPosition::BelowText {
        let ball_y = if has_decoration {
            y + 8 + DECORATION_H + 20
        } else {
            y + 30
        };
        draw_ball(&mut fb, ball_y)?;
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

    const FIELD_BOX_W: i32 = 360;
    const FIELD_BOX_H: i32 = 40;
    const FIELD_PAD_X: i32 = 12;

    /// Draw a single bordered field box — an input-style highlight so the credential screen's
    /// password isn't just floating text — showing the tail of `content` that fits (like a
    /// real password field, typing past the visible width scrolls instead of overflowing).
    pub fn draw_field_box(
        fb: &mut Framebuffer,
        cx: i32,
        y: i32,
        content: &str,
        style: MonoTextStyle<'_, Rgb888>,
    ) {
        let rect = Rectangle::new(
            Point::new(cx - FIELD_BOX_W / 2, y),
            Size::new(FIELD_BOX_W as u32, FIELD_BOX_H as u32),
        );
        let _ = RoundedRectangle::new(rect, CornerRadii::new(Size::new_equal(4)))
            .into_styled(PrimitiveStyle::with_stroke(FG, 2))
            .draw(fb);

        // FONT_10X20 glyphs are 10px wide; leave padding on both sides of the box.
        let max_chars = usize::try_from((FIELD_BOX_W - FIELD_PAD_X * 2) / 10).unwrap_or(0);
        let visible_start = content.chars().count().saturating_sub(max_chars);
        let visible: String = content.chars().skip(visible_start).collect();

        let _ = Text::with_alignment(
            &visible,
            Point::new(cx - FIELD_BOX_W / 2 + FIELD_PAD_X, y + FIELD_BOX_H / 2 + 6),
            style,
            Alignment::Left,
        )
        .draw(fb);
    }
}
