//! Stateful keyboard translation for the RDP Requester credential screen, backed by a real
//! compiled `xkbcommon` keymap when possible instead of a hand-rolled per-layout table.
//!
//! [`text_entry`](crate::text_entry)'s `KeyboardLayout`/`scancode_text_action` started as the
//! fix for a real AZERTY-vs-QWERTY password-scrambling bug (see that module's docs), covering
//! exactly the two layouts tested against. Every additional keyboard needs another hand-written
//! scancode table there — bounded, and wrong (silently) for anyone not on the list. `xkbcommon`
//! ships `xkeyboard-config`'s actual layout database, so compiling a real keymap for the
//! viewer's negotiated layout covers virtually every keyboard Windows can be configured with,
//! not just the ones we thought to test. See `ARCHITECTURE_TECHNIQUE.md` §10.
//!
//! Known gap even with a real keymap: only the physical Shift/CapsLock modifiers are tracked
//! (`AltGr`/Right Alt arrives E0-extended and isn't fed into the xkb state), so a password
//! containing an AltGr-only character (`@` on a German keyboard, for example) still won't type
//! correctly. This is the same boundary the hand-rolled tables already had, not a regression.
//!
//! Falls back to the [`text_entry`](crate::text_entry) tables when no keymap could be compiled
//! (unknown KLID not in [`xkb_rmlvo_for_klid`], or `xkeyboard-config`'s data files aren't present
//! in this deployment) — the plain-table path this replaced is a real, already-verified safety
//! net, not a stub.

use warpgate_core::Scancode;
use xkbcommon::xkb;

use crate::text_entry::{
    KeyboardLayout, TextFieldAction, is_shift_scancode, numpad_text_action, scancode_text_action,
};

/// Windows KLID (low word — the LANGID) -> xkb RMLVO `(layout, variant)`. Not exhaustive: an
/// unlisted KLID falls back to `("us", "")`, same default `KeyboardLayout::from_klid` already
/// used before this existed. Extending coverage is now just adding a line here — the actual
/// per-key character mapping comes from `xkeyboard-config`, not from code in this repo.
fn xkb_rmlvo_for_klid(klid: u32) -> (&'static str, &'static str) {
    match klid & 0xffff {
        0x0409 => ("us", ""),          // English (US)
        0x0809 => ("gb", ""),          // English (UK)
        0x040c => ("fr", ""),          // French (France)
        0x080c | 0x0813 => ("be", ""), // French/Dutch (Belgium) — one shared keyboard layout
        0x100c => ("ch", "fr"),        // French (Switzerland)
        0x0407 => ("de", ""),          // German (Germany)
        0x0807 => ("ch", "de"),        // German (Switzerland)
        0x0c07 => ("at", ""),          // German (Austria)
        0x0410 => ("it", ""),          // Italian (Italy)
        0x0810 => ("ch", "it"),        // Italian (Switzerland)
        0x040a | 0x0c0a => ("es", ""), // Spanish (Spain)
        0x080a => ("latam", ""),       // Spanish (Latin America)
        0x0413 => ("nl", ""),          // Dutch (Netherlands)
        0x0816 => ("pt", ""),          // Portuguese (Portugal)
        0x0416 => ("br", ""),          // Portuguese (Brazil)
        0x041d => ("se", ""),          // Swedish
        0x0406 => ("dk", ""),          // Danish
        0x040b => ("fi", ""),          // Finnish
        0x0414 => ("no", ""),          // Norwegian
        0x0415 => ("pl", ""),          // Polish
        0x0419 => ("ru", ""),          // Russian
        0x0408 => ("gr", ""),          // Greek
        0x041f => ("tr", ""),          // Turkish
        0x0405 => ("cz", ""),          // Czech
        0x040e => ("hu", ""),          // Hungarian
        0x0418 => ("ro", ""),          // Romanian
        0x041b => ("sk", ""),          // Slovak
        _ => ("us", ""),
    }
}

/// Stateful per-session keyboard translator: prefers a compiled `xkbcommon` keymap for the
/// viewer's negotiated layout, falling back to the [`text_entry`](crate::text_entry) tables if
/// none could be compiled. Owns modifier state (Shift, CapsLock, ...) across calls the same way
/// a real keyboard driver would — construct one per credential-screen session, not per keystroke.
pub struct TextKeyboard {
    backend: Backend,
}

enum Backend {
    Xkb {
        state: SendXkbState,
        // Non-extended scancodes we currently believe are physically held. RDP resends
        // `Pressed` for a key auto-repeating while held (observed in practice for Shift held
        // across several typed letters) — feeding `xkb::State::update_key` a `Down` for a key
        // it already considers down risks leaving that modifier stuck depressed for the rest
        // of the session (reproduced: Shift held through a few letters, released, and every
        // later letter still came out uppercase). Tracking our own held-set and only calling
        // `update_key` on an actual transition makes repeat events a no-op instead.
        held: std::collections::HashSet<u8>,
    },
    Legacy { layout: KeyboardLayout, shift: bool },
}

/// Wraps `xkb::State` to make it `Send`. The crate doesn't derive `Send` for its raw-pointer FFI
/// handle, but libxkbcommon's own documented model for context/keymap/state objects is exactly
/// "single owner at a time, may move between threads, never accessed concurrently" — already
/// guaranteed here by Rust's ownership rules: `TextKeyboard` is only ever reached through
/// `&mut self`, so an async runtime moving the enclosing task between worker threads between
/// polls (the reason this needs to be `Send` at all) never means two threads touch it at once.
struct SendXkbState(xkb::State);
unsafe impl Send for SendXkbState {}

impl TextKeyboard {
    /// Builds a translator for the viewer's negotiated Windows keyboard layout identifier
    /// (`AcceptorResult::keyboard_layout`, `0` if the client didn't announce one).
    #[must_use]
    pub fn new(klid: u32) -> Self {
        match Self::compile(klid) {
            Some(state) => Self {
                backend: Backend::Xkb {
                    state: SendXkbState(state),
                    held: std::collections::HashSet::new(),
                },
            },
            None => Self {
                backend: Backend::Legacy {
                    layout: KeyboardLayout::from_klid(klid),
                    shift: false,
                },
            },
        }
    }

    fn compile(klid: u32) -> Option<xkb::State> {
        let (layout, variant) = xkb_rmlvo_for_klid(klid);
        let context = xkb::Context::new(xkb::CONTEXT_NO_FLAGS);
        let keymap = xkb::Keymap::new_from_names(
            &context,
            "evdev",
            "pc105",
            layout,
            variant,
            None,
            xkb::COMPILE_NO_FLAGS,
        )?;
        Some(xkb::State::new(&keymap))
    }

    /// Feed one key event (press or release). Returns the text-field action for a *press* that
    /// types or controls something; always `None` for a release — but a release still has to be
    /// passed in on the xkb path, to keep Shift/CapsLock state correct for the next press.
    pub fn key_action(&mut self, scancode: Scancode, down: bool) -> Option<TextFieldAction> {
        // Numeric keypad digits/operators are the same physical layout worldwide regardless of
        // the compiled keymap, and aren't fed into xkb state at all (see `numpad_text_action`).
        if let Some(action) = numpad_text_action(scancode) {
            return down.then_some(action);
        }
        match &mut self.backend {
            Backend::Xkb {
                state: SendXkbState(state),
                held,
            } => {
                let action = down.then(|| Self::xkb_text_action(state, scancode)).flatten();
                let Scancode { code, extended } = scancode;
                if extended {
                    // `xkb_update_key` already no-ops on extended codes; nothing to dedup —
                    // and tracking them in `held` (keyed on `code` alone) would risk colliding
                    // with an unrelated non-extended code sharing the same byte value.
                } else {
                    let was_down = held.contains(&code);
                    if down != was_down {
                        if down {
                            held.insert(code);
                        } else {
                            held.remove(&code);
                        }
                        Self::xkb_update_key(state, scancode, down);
                    }
                }
                action
            }
            Backend::Legacy { layout, shift } => {
                if is_shift_scancode(scancode) {
                    *shift = down;
                    None
                } else if down {
                    scancode_text_action(scancode, *shift, *layout)
                } else {
                    None
                }
            }
        }
    }

    /// Translate one key press to a text-field action using the compiled keymap's *current*
    /// modifier state — called before [`Self::xkb_update_key`] applies this same event, per
    /// `xkb_state_update_key`'s documented usage (a key's own press shouldn't affect its own
    /// translation).
    fn xkb_text_action(state: &xkb::State, scancode: Scancode) -> Option<TextFieldAction> {
        let Scancode { code, extended } = scancode;
        if extended {
            // Nav cluster, Right Ctrl/Alt, etc. — not modeled in xkb state, not meaningful on
            // this screen. Numpad Enter/divide are handled above, before this is reached.
            return None;
        }
        match code {
            0x0e => return Some(TextFieldAction::Backspace),
            0x0f => return Some(TextFieldAction::NextField),
            0x1c => return Some(TextFieldAction::Submit),
            _ => {}
        }
        let keycode = xkb::Keycode::new(u32::from(code) + EVDEV_OFFSET);
        state.key_get_utf8(keycode).chars().next().map(TextFieldAction::Char)
    }

    /// Apply one key event to the compiled keymap's modifier state (Shift, CapsLock, ...) —
    /// called for every event, not just presses, so a missed release can't leave a modifier
    /// stuck. Extended (E0) keys aren't modeled (see [`Self::xkb_text_action`]) and are skipped.
    fn xkb_update_key(state: &mut xkb::State, scancode: Scancode, down: bool) {
        let Scancode { code, extended } = scancode;
        if extended {
            return;
        }
        let keycode = xkb::Keycode::new(u32::from(code) + EVDEV_OFFSET);
        let direction = if down {
            xkb::KeyDirection::Down
        } else {
            xkb::KeyDirection::Up
        };
        state.update_key(keycode, direction);
    }
}

/// xkb (X11-derived) keycodes are Linux evdev keycodes offset by a fixed `8` — a historical X11
/// convention `xkbcommon` inherits, documented on `xkb::Keycode`. Linux's own evdev `KEY_*`
/// numbering for the base (non-extended) key block was in turn assigned to match the PC/AT
/// Set-1 scan code numbers directly, so no separate scancode->evdev lookup table is needed here:
/// `Scancode.code` *is* the evdev code for every non-extended key this screen cares about.
const EVDEV_OFFSET: u32 = 8;

#[cfg(test)]
mod tests {
    use super::*;

    fn code(c: u8) -> Scancode {
        Scancode {
            code: c,
            extended: false,
        }
    }

    #[test]
    fn us_layout_types_plain_letters() {
        let mut kb = TextKeyboard::new(0x0000_0409);
        assert_eq!(
            kb.key_action(code(0x1e), true),
            Some(TextFieldAction::Char('a'))
        );
        kb.key_action(code(0x1e), false);
    }

    #[test]
    fn shift_uppercases_through_xkb_state() {
        let mut kb = TextKeyboard::new(0x0000_0409);
        assert_eq!(kb.key_action(code(0x2a), true), None); // Shift down
        assert_eq!(
            kb.key_action(code(0x1e), true),
            Some(TextFieldAction::Char('A'))
        );
        kb.key_action(code(0x1e), false);
        assert_eq!(kb.key_action(code(0x2a), false), None); // Shift up
        assert_eq!(
            kb.key_action(code(0x1e), true),
            Some(TextFieldAction::Char('a'))
        );
    }

    /// Reproduces a real bug seen against an actual RDP client: holding Shift while typing
    /// several letters made mstsc auto-repeat-resend `Pressed` for Shift itself (several
    /// `down=true` events, then a single `down=false`). Left uppercase permanently stuck for
    /// the rest of the session once this happened once. `held`-set deduping in `key_action`
    /// fixes it by only forwarding actual transitions to `xkb::State::update_key`.
    #[test]
    fn repeated_shift_press_events_do_not_stick_shift_on() {
        let mut kb = TextKeyboard::new(0x0000_0409);
        // Shift auto-repeats three times while a letter is typed under it, exactly like the
        // real client did.
        assert_eq!(kb.key_action(code(0x2a), true), None);
        assert_eq!(kb.key_action(code(0x2a), true), None);
        assert_eq!(kb.key_action(code(0x2a), true), None);
        assert_eq!(
            kb.key_action(code(0x1e), true),
            Some(TextFieldAction::Char('A'))
        );
        kb.key_action(code(0x1e), false);
        // A single release should still fully clear Shift, no matter how many redundant
        // presses preceded it.
        assert_eq!(kb.key_action(code(0x2a), false), None);
        assert_eq!(
            kb.key_action(code(0x1f), true),
            Some(TextFieldAction::Char('s'))
        );
    }

    #[test]
    fn control_keys_bypass_xkb() {
        let mut kb = TextKeyboard::new(0x0000_0409);
        assert_eq!(
            kb.key_action(code(0x0e), true),
            Some(TextFieldAction::Backspace)
        );
        assert_eq!(
            kb.key_action(code(0x1c), true),
            Some(TextFieldAction::Submit)
        );
    }

    #[test]
    fn numpad_still_works_alongside_xkb() {
        let mut kb = TextKeyboard::new(0x0000_0409);
        assert_eq!(
            kb.key_action(code(0x47), true),
            Some(TextFieldAction::Char('7'))
        );
    }

    #[test]
    fn unknown_klid_falls_back_to_us() {
        // 0xffff isn't a real LANGID; either a real "us"-equivalent xkb keymap compiles for it
        // (xkb_rmlvo_for_klid's default) or the whole thing falls back to the legacy Qwerty
        // table — either way a plain letter still types as itself.
        let mut kb = TextKeyboard::new(0x0000_ffff);
        assert_eq!(
            kb.key_action(code(0x1e), true),
            Some(TextFieldAction::Char('a'))
        );
    }
}
