use std::fmt::Debug;

use crate::Secret;
use crate::consts::TICKET_SELECTOR_PREFIX;

pub enum AuthSelector {
    User {
        username: String,
        target_name: String,
    },
    Ticket {
        secret: Secret<String>,
    },
}

impl<T: AsRef<str>> From<T> for AuthSelector {
    fn from(selector: T) -> Self {
        if let Some(secret) = selector.as_ref().strip_prefix(TICKET_SELECTOR_PREFIX) {
            let secret = Secret::new(secret.into());
            return Self::Ticket { secret };
        }

        // `:` is the default (`username:target`); `#` is the escape used when a username or
        // target itself contains a literal `:` (e.g. an IPv6 target name). `+` is accepted
        // purely for connection-string compatibility with tools that use that convention
        // (Netwrix Privilege Secure among them) — checked last, only when the selector has
        // neither of the other two, so it can never change how an existing `:`- or
        // `#`-delimited selector parses even if it happens to also contain a `+`.
        let separator = if selector.as_ref().contains('#') {
            '#'
        } else if selector.as_ref().contains(':') {
            ':'
        } else if selector.as_ref().contains('+') {
            '+'
        } else {
            ':'
        };

        let mut parts = selector.as_ref().splitn(2, separator);
        let username = parts.next().unwrap_or("").to_string();
        let target_name = parts.next().unwrap_or("").to_string();
        Self::User {
            username,
            target_name,
        }
    }
}

impl Debug for AuthSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User {
                username,
                target_name,
            } => write!(f, "<{username} for {target_name}>"),
            Self::Ticket { .. } => write!(f, "<ticket>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(selector: &str) -> (String, String) {
        match AuthSelector::from(selector) {
            AuthSelector::User {
                username,
                target_name,
            } => (username, target_name),
            AuthSelector::Ticket { .. } => panic!("expected a User selector"),
        }
    }

    #[test]
    fn colon_is_the_default_separator() {
        assert_eq!(
            user("toto:dc-test1"),
            ("toto".to_owned(), "dc-test1".to_owned())
        );
    }

    #[test]
    fn hash_escapes_a_colon_in_username_or_target() {
        // An IPv6 target name would otherwise be unparseable with `:` as the separator.
        assert_eq!(
            user("toto#::1"),
            ("toto".to_owned(), "::1".to_owned())
        );
    }

    #[test]
    fn plus_is_accepted_for_netwrix_style_connection_strings() {
        assert_eq!(
            user("toto+dc-test1"),
            ("toto".to_owned(), "dc-test1".to_owned())
        );
    }

    /// A `+` inside a `:`-delimited selector must not change how it parses — `+` is only
    /// consulted when the selector has neither `#` nor `:` at all.
    #[test]
    fn plus_inside_a_colon_selector_is_left_alone() {
        assert_eq!(
            user("toto:my+target"),
            ("toto".to_owned(), "my+target".to_owned())
        );
    }
}
