//! Free-text field input for the RDP/VNC holding screens, for prompts that need more than
//! [`crate::otp::OtpAction`]'s digits-only alphabet — e.g. a target credential typed
//! in-session instead of a numeric second factor. See `ARCHITECTURE_TECHNIQUE.md` §10 ("RDP +
//! Requester par écran de saisie in-session").
//!
//! Mirrors `otp.rs`'s split: mapping a raw key event to a [`TextFieldAction`] is
//! protocol-specific (RDP scancodes need shift state and [`KeyboardLayout`] tracked across
//! calls; a viewer that sends resolved Unicode keys, e.g. over the web, needs neither),
//! accumulating actions into fields is shared here via [`CredentialFields`].

use warpgate_core::Scancode;

/// One key event's effect on a multi-field text form. Protocol code maps its own raw input to
/// this; [`CredentialFields::apply`] does the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFieldAction {
    Char(char),
    Backspace,
    /// Tab — move focus to the next field.
    NextField,
    Submit,
}

/// Which field currently has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialField {
    Username,
    Password,
}

/// Long enough for any real account name or password; short enough to bound memory from a
/// viewer that never stops sending keys.
const MAX_FIELD_LEN: usize = 256;

/// Username + password captured a keystroke at a time over the holding screen.
pub struct CredentialFields {
    username: String,
    password: String,
    focus: CredentialField,
}

impl CredentialFields {
    pub const fn new() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            focus: CredentialField::Username,
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub const fn focus(&self) -> CredentialField {
        self.focus
    }

    /// Apply one key action to the focused field. Returns `true` once the viewer has
    /// submitted a non-empty password — the caller should then [`Self::take`] the result.
    /// Submitting an empty username or password just moves focus to (or stays on) the field
    /// that still needs typing, mirroring how a normal login form treats Enter.
    pub fn apply(&mut self, action: TextFieldAction) -> bool {
        match action {
            TextFieldAction::Char(c) => {
                let field = self.focused_field_mut();
                if field.len() < MAX_FIELD_LEN {
                    field.push(c);
                }
                false
            }
            TextFieldAction::Backspace => {
                self.focused_field_mut().pop();
                false
            }
            TextFieldAction::NextField => {
                self.focus = match self.focus {
                    CredentialField::Username => CredentialField::Password,
                    CredentialField::Password => CredentialField::Username,
                };
                false
            }
            TextFieldAction::Submit => match self.focus {
                CredentialField::Username if !self.username.is_empty() => {
                    self.focus = CredentialField::Password;
                    false
                }
                CredentialField::Password if !self.password.is_empty() => true,
                _ => false,
            },
        }
    }

    fn focused_field_mut(&mut self) -> &mut String {
        match self.focus {
            CredentialField::Username => &mut self.username,
            CredentialField::Password => &mut self.password,
        }
    }

    /// Take the captured credential. Meant to be called once [`Self::apply`] has returned
    /// `true`; harmless (just yields whatever has been typed so far) if called earlier.
    pub fn take(&mut self) -> (String, String) {
        (
            std::mem::take(&mut self.username),
            std::mem::take(&mut self.password),
        )
    }
}

impl Default for CredentialFields {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a scancode is one of the two shift keys. Stateless per call like the rest of this
/// module — the holding-screen driver tracks shift-down state across `Key { down }` events
/// itself and passes it into [`scancode_text_action`].
pub const fn is_shift_scancode(scancode: Scancode) -> bool {
    !scancode.extended && matches!(scancode.code, 0x2a | 0x36)
}

/// Keyboard layouts this screen knows how to map scancodes for. Selected from the client's
/// negotiated layout — `AcceptorResult::keyboard_layout`, surfaced by `ironrdp-server`'s
/// `warpgate.patch` (see `vendor/ironrdp-server/PATCHES.md`) — so a correctly-typed password
/// isn't scrambled by a physical-key/character mismatch. Reproduced with a French AZERTY
/// client: scancodes are layout-independent physical positions, so without this, letters and
/// the digit row (shifted on AZERTY, not on QWERTY) come out as different characters than what
/// the viewer actually typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardLayout {
    Qwerty,
    /// French AZERTY (Windows KLID `0x0000_040C`).
    AzertyFr,
}

impl KeyboardLayout {
    /// Picks a layout from a client's negotiated Windows keyboard layout identifier (the low
    /// word of its locale ID; `0` if the client didn't announce one). Unrecognised values fall
    /// back to `Qwerty` — an incomplete layout list beats guessing wrong, and QWERTY at least
    /// keeps ASCII digits/letters typeable on a client whose real layout just isn't covered
    /// yet, since a mismatched but *unlisted* layout is no worse off than before this existed.
    #[must_use]
    pub const fn from_klid(klid: u32) -> Self {
        match klid {
            0x0000_040c => Self::AzertyFr,
            _ => Self::Qwerty,
        }
    }
}

/// Map a PC/AT set-1 scancode (what mstsc/FreeRDP send) to a text-field action, for the
/// viewer's negotiated `layout`. See [`KeyboardLayout`] for which layouts are covered and why
/// this exists at all — scancodes name a physical key position, not a character, so getting
/// this wrong doesn't fail loudly, it silently types the wrong password.
pub fn scancode_text_action(scancode: Scancode, shift: bool, layout: KeyboardLayout) -> Option<TextFieldAction> {
    if let Some(action) = numpad_text_action(scancode) {
        return Some(action);
    }
    match layout {
        KeyboardLayout::Qwerty => scancode_text_action_qwerty(scancode, shift),
        KeyboardLayout::AzertyFr => scancode_text_action_azerty(scancode, shift),
    }
}

/// The numeric keypad's digits and operators sit at the same physical positions and mean the
/// same thing regardless of the viewer's main-alphabet layout (AZERTY, QWERTY, ...), so they're
/// handled once here instead of duplicated in every per-layout table. Mirrors the nav-cluster
/// disambiguation `scancode_otp_action` (in `warpgate-protocol-rdp`) already relies on: the nav
/// cluster's dedicated Home/End/arrow keys arrive E0-extended, the keypad's own physical keys do
/// not — Num Lock state isn't tracked (or needed) here, mstsc's own driver already resolves it
/// into which scancode form gets sent.
pub(crate) const fn numpad_text_action(scancode: Scancode) -> Option<TextFieldAction> {
    let Scancode { code, extended } = scancode;
    if extended {
        return match code {
            0x1c => Some(TextFieldAction::Submit), // numpad Enter
            0x35 => Some(TextFieldAction::Char('/')), // numpad divide
            _ => None,
        };
    }
    Some(TextFieldAction::Char(match code {
        0x47 => '7',
        0x48 => '8',
        0x49 => '9',
        0x4a => '-', // numpad minus
        0x4b => '4',
        0x4c => '5',
        0x4d => '6',
        0x4e => '+', // numpad plus
        0x4f => '1',
        0x50 => '2',
        0x51 => '3',
        0x52 => '0',
        0x53 => '.', // numpad decimal
        0x37 => '*', // numpad multiply
        _ => return None,
    }))
}

fn scancode_text_action_qwerty(scancode: Scancode, shift: bool) -> Option<TextFieldAction> {
    let Scancode { code, extended } = scancode;
    if extended {
        // Nav cluster, numpad Enter, right Alt/Ctrl, etc. — none of these type a character
        // on this screen.
        return None;
    }
    let (lower, upper) = match code {
        0x02 => ('1', '!'),
        0x03 => ('2', '@'),
        0x04 => ('3', '#'),
        0x05 => ('4', '$'),
        0x06 => ('5', '%'),
        0x07 => ('6', '^'),
        0x08 => ('7', '&'),
        0x09 => ('8', '*'),
        0x0a => ('9', '('),
        0x0b => ('0', ')'),
        0x0c => ('-', '_'),
        0x0d => ('=', '+'),
        0x0e => return Some(TextFieldAction::Backspace),
        0x0f => return Some(TextFieldAction::NextField),
        0x10 => ('q', 'Q'),
        0x11 => ('w', 'W'),
        0x12 => ('e', 'E'),
        0x13 => ('r', 'R'),
        0x14 => ('t', 'T'),
        0x15 => ('y', 'Y'),
        0x16 => ('u', 'U'),
        0x17 => ('i', 'I'),
        0x18 => ('o', 'O'),
        0x19 => ('p', 'P'),
        0x1a => ('[', '{'),
        0x1b => (']', '}'),
        0x1c => return Some(TextFieldAction::Submit),
        0x1e => ('a', 'A'),
        0x1f => ('s', 'S'),
        0x20 => ('d', 'D'),
        0x21 => ('f', 'F'),
        0x22 => ('g', 'G'),
        0x23 => ('h', 'H'),
        0x24 => ('j', 'J'),
        0x25 => ('k', 'K'),
        0x26 => ('l', 'L'),
        0x27 => (';', ':'),
        0x28 => ('\'', '"'),
        0x29 => ('`', '~'),
        0x2b => ('\\', '|'),
        0x2c => ('z', 'Z'),
        0x2d => ('x', 'X'),
        0x2e => ('c', 'C'),
        0x2f => ('v', 'V'),
        0x30 => ('b', 'B'),
        0x31 => ('n', 'N'),
        0x32 => ('m', 'M'),
        0x33 => (',', '<'),
        0x34 => ('.', '>'),
        0x35 => ('/', '?'),
        0x39 => (' ', ' '),
        _ => return None,
    };
    Some(TextFieldAction::Char(if shift { upper } else { lower }))
}

/// Same physical scancodes as [`scancode_text_action_qwerty`], mapped to what a French AZERTY
/// keyboard actually produces at each position. Covers letters and the digit row accurately
/// (the two that matter most for a password); punctuation reachable only via `AltGr` on a real
/// French keyboard (`@`, `#`, `{`, `}`, ...) isn't representable here since Warpgate only sees
/// a plain shift flag, not a full modifier state — same boundary the QWERTY table already has
/// for anything outside its own alphabet.
fn scancode_text_action_azerty(scancode: Scancode, shift: bool) -> Option<TextFieldAction> {
    let Scancode { code, extended } = scancode;
    if extended {
        return None;
    }
    let (lower, upper) = match code {
        0x02 => ('&', '1'),
        0x03 => ('é', '2'),
        0x04 => ('"', '3'),
        0x05 => ('\'', '4'),
        0x06 => ('(', '5'),
        0x07 => ('-', '6'),
        0x08 => ('è', '7'),
        0x09 => ('_', '8'),
        0x0a => ('ç', '9'),
        0x0b => ('à', '0'),
        0x0c => (')', '°'),
        0x0d => ('=', '+'),
        0x0e => return Some(TextFieldAction::Backspace),
        0x0f => return Some(TextFieldAction::NextField),
        0x10 => ('a', 'A'),
        0x11 => ('z', 'Z'),
        0x12 => ('e', 'E'),
        0x13 => ('r', 'R'),
        0x14 => ('t', 'T'),
        0x15 => ('y', 'Y'),
        0x16 => ('u', 'U'),
        0x17 => ('i', 'I'),
        0x18 => ('o', 'O'),
        0x19 => ('p', 'P'),
        0x1a => ('^', '¨'),
        0x1b => ('$', '£'),
        0x1c => return Some(TextFieldAction::Submit),
        0x1e => ('q', 'Q'),
        0x1f => ('s', 'S'),
        0x20 => ('d', 'D'),
        0x21 => ('f', 'F'),
        0x22 => ('g', 'G'),
        0x23 => ('h', 'H'),
        0x24 => ('j', 'J'),
        0x25 => ('k', 'K'),
        0x26 => ('l', 'L'),
        0x27 => ('m', 'M'),
        0x28 => ('ù', '%'),
        0x29 => ('²', '²'),
        0x2b => ('*', 'µ'),
        0x2c => ('w', 'W'),
        0x2d => ('x', 'X'),
        0x2e => ('c', 'C'),
        0x2f => ('v', 'V'),
        0x30 => ('b', 'B'),
        0x31 => ('n', 'N'),
        0x32 => (',', '?'),
        0x33 => (';', '.'),
        0x34 => (':', '/'),
        0x35 => ('!', '§'),
        0x39 => (' ', ' '),
        _ => return None,
    };
    Some(TextFieldAction::Char(if shift { upper } else { lower }))
}

/// Map a Unicode keypress (viewers that send `Key` with a resolved keysym instead of a
/// scancode, e.g. over the web) to a text-field action. No shift tracking needed — the viewer
/// already resolved the character.
pub fn key_text_action(keysym: u32) -> Option<TextFieldAction> {
    Some(match keysym {
        0x09 => TextFieldAction::NextField, // Tab
        0x08 => TextFieldAction::Backspace,
        0x0d | 0x0a => TextFieldAction::Submit, // CR / LF
        0x20..=0x7e => TextFieldAction::Char(char::from_u32(keysym)?), // printable ASCII
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialField, CredentialFields, KeyboardLayout, Scancode, TextFieldAction,
        is_shift_scancode, key_text_action, scancode_text_action,
    };

    fn plain(code: u8) -> Option<TextFieldAction> {
        scancode_text_action(
            Scancode {
                code,
                extended: false,
            },
            false,
            KeyboardLayout::Qwerty,
        )
    }

    fn shifted(code: u8) -> Option<TextFieldAction> {
        scancode_text_action(
            Scancode {
                code,
                extended: false,
            },
            true,
            KeyboardLayout::Qwerty,
        )
    }

    fn plain_azerty(code: u8) -> Option<TextFieldAction> {
        scancode_text_action(
            Scancode {
                code,
                extended: false,
            },
            false,
            KeyboardLayout::AzertyFr,
        )
    }

    fn shifted_azerty(code: u8) -> Option<TextFieldAction> {
        scancode_text_action(
            Scancode {
                code,
                extended: false,
            },
            true,
            KeyboardLayout::AzertyFr,
        )
    }

    #[test]
    fn letters_and_shift() {
        assert_eq!(plain(0x1e), Some(TextFieldAction::Char('a')));
        assert_eq!(shifted(0x1e), Some(TextFieldAction::Char('A')));
    }

    #[test]
    fn number_row_and_symbols() {
        assert_eq!(plain(0x02), Some(TextFieldAction::Char('1')));
        assert_eq!(shifted(0x02), Some(TextFieldAction::Char('!')));
        assert_eq!(plain(0x0c), Some(TextFieldAction::Char('-')));
        assert_eq!(shifted(0x0c), Some(TextFieldAction::Char('_')));
    }

    #[test]
    fn control_keys() {
        assert_eq!(plain(0x0e), Some(TextFieldAction::Backspace));
        assert_eq!(plain(0x0f), Some(TextFieldAction::NextField));
        assert_eq!(plain(0x1c), Some(TextFieldAction::Submit));
    }

    /// Extended (E0-prefixed) codes never type a character on this screen, even when they
    /// share a make code with a mapped key (mirrors the OTP entry's nav-cluster guard) —
    /// except numpad Enter (0x1c) and numpad divide (0x35), which are extended but do map
    /// (see [`numpad_enter_and_divide_are_extended`]).
    #[test]
    fn extended_scancodes_are_not_mapped() {
        assert_eq!(
            scancode_text_action(
                Scancode {
                    code: 0x48, // Up arrow — shares its make code with numpad 8
                    extended: true
                },
                false,
                KeyboardLayout::Qwerty,
            ),
            None
        );
    }

    #[test]
    fn azerty_letters_are_shifted_relative_to_physical_qwerty_position() {
        // Scancode 0x10 sits under 'Q' on a physical QWERTY-labelled key, but a French
        // AZERTY layout reads that same physical position as 'A'.
        assert_eq!(plain_azerty(0x10), Some(TextFieldAction::Char('a')));
        assert_eq!(shifted_azerty(0x10), Some(TextFieldAction::Char('A')));
        // And vice versa: the physical 'A' position (0x1e) reads as 'Q' on AZERTY.
        assert_eq!(plain_azerty(0x1e), Some(TextFieldAction::Char('q')));
    }

    #[test]
    fn azerty_digit_row_is_shifted_unlike_qwerty() {
        // AZERTY's top row types symbols unshifted and digits *with* shift — the opposite
        // of QWERTY, and the exact mismatch that scrambled a real password during testing.
        assert_eq!(plain_azerty(0x02), Some(TextFieldAction::Char('&')));
        assert_eq!(shifted_azerty(0x02), Some(TextFieldAction::Char('1')));
    }

    #[test]
    fn klid_selects_azerty_only_for_the_french_klid() {
        assert_eq!(KeyboardLayout::from_klid(0x0000_040c), KeyboardLayout::AzertyFr);
        assert_eq!(KeyboardLayout::from_klid(0x0000_0409), KeyboardLayout::Qwerty);
        assert_eq!(KeyboardLayout::from_klid(0), KeyboardLayout::Qwerty);
    }

    #[test]
    fn numpad_digits_are_layout_independent() {
        for (code, expected) in [
            (0x47u8, '7'),
            (0x48, '8'),
            (0x49, '9'),
            (0x4b, '4'),
            (0x4c, '5'),
            (0x4d, '6'),
            (0x4f, '1'),
            (0x50, '2'),
            (0x51, '3'),
            (0x52, '0'),
            (0x53, '.'),
            (0x37, '*'),
            (0x4a, '-'),
            (0x4e, '+'),
        ] {
            assert_eq!(
                scancode_text_action(
                    Scancode {
                        code,
                        extended: false
                    },
                    false,
                    KeyboardLayout::Qwerty,
                ),
                Some(TextFieldAction::Char(expected)),
                "scancode {code:#x}"
            );
            // Same result under AZERTY — the keypad doesn't follow the main-alphabet layout.
            assert_eq!(
                scancode_text_action(
                    Scancode {
                        code,
                        extended: false
                    },
                    false,
                    KeyboardLayout::AzertyFr,
                ),
                Some(TextFieldAction::Char(expected)),
                "scancode {code:#x} (azerty)"
            );
        }
    }

    #[test]
    fn numpad_enter_and_divide_are_extended() {
        assert_eq!(
            scancode_text_action(
                Scancode {
                    code: 0x1c,
                    extended: true
                },
                false,
                KeyboardLayout::Qwerty,
            ),
            Some(TextFieldAction::Submit)
        );
        assert_eq!(
            scancode_text_action(
                Scancode {
                    code: 0x35,
                    extended: true
                },
                false,
                KeyboardLayout::Qwerty,
            ),
            Some(TextFieldAction::Char('/'))
        );
    }

    #[test]
    fn shift_scancode_detection() {
        assert!(is_shift_scancode(Scancode {
            code: 0x2a,
            extended: false
        }));
        assert!(is_shift_scancode(Scancode {
            code: 0x36,
            extended: false
        }));
        assert!(!is_shift_scancode(Scancode {
            code: 0x1e,
            extended: false
        }));
    }

    #[test]
    fn keysym_printable_and_control() {
        assert_eq!(key_text_action(u32::from('a')), Some(TextFieldAction::Char('a')));
        assert_eq!(key_text_action(0x08), Some(TextFieldAction::Backspace));
        assert_eq!(key_text_action(0x09), Some(TextFieldAction::NextField));
        assert_eq!(key_text_action(0x0d), Some(TextFieldAction::Submit));
    }

    #[test]
    fn credential_fields_flow() {
        let mut fields = CredentialFields::new();
        for c in "jdoe".chars() {
            assert!(!fields.apply(TextFieldAction::Char(c)));
        }
        assert_eq!(fields.username(), "jdoe");
        assert_eq!(fields.focus(), CredentialField::Username);

        // Enter on a non-empty username moves focus instead of submitting.
        assert!(!fields.apply(TextFieldAction::Submit));
        assert_eq!(fields.focus(), CredentialField::Password);

        for c in "hunter2".chars() {
            assert!(!fields.apply(TextFieldAction::Char(c)));
        }

        assert!(fields.apply(TextFieldAction::Submit));
        let (username, password) = fields.take();
        assert_eq!(username, "jdoe");
        assert_eq!(password, "hunter2");
        assert_eq!(fields.username(), "");
        assert_eq!(fields.password(), "");
    }

    #[test]
    fn backspace_and_tab_cycle_focus() {
        let mut fields = CredentialFields::new();
        fields.apply(TextFieldAction::Char('x'));
        fields.apply(TextFieldAction::Backspace);
        assert_eq!(fields.username(), "");

        fields.apply(TextFieldAction::NextField);
        assert_eq!(fields.focus(), CredentialField::Password);
        fields.apply(TextFieldAction::NextField);
        assert_eq!(fields.focus(), CredentialField::Username);
    }
}
