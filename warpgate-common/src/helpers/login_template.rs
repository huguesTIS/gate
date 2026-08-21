//! Login account name templating for Requester/Managed access policies.
//!
//! Modeled on Netwrix Privilege Secure's "Login Account Template" (public docs,
//! see `ARCHITECTURE_TECHNIQUE.md` §10): a small fixed set of presets plus a
//! free-form custom format, not a general placeholder engine. The domain is a
//! literal configured on the template, not resolved per-user — Warpgate's `User`
//! model has no canonical domain/email attribute to resolve one from.

use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum LoginNameTemplate {
    /// The portal username, unchanged.
    #[serde(rename = "sam_account_name")]
    SamAccountName(SamAccountNameTemplate),
    /// `{domain}\{username}`.
    #[serde(rename = "domain_sam_account_name")]
    DomainSamAccountName(DomainSamAccountNameTemplate),
    /// `{username}@{domain}`.
    #[serde(rename = "upn")]
    Upn(DomainTemplate),
    /// Free-form format string; `{username}` is replaced with the portal username.
    #[serde(rename = "custom")]
    Custom(CustomTemplate),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object, Default)]
pub struct SamAccountNameTemplate {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct DomainTemplate {
    pub domain: String,
}

/// Structurally identical to [`DomainTemplate`], kept as a separate type rather than reused
/// for both `DomainSamAccountName` and `Upn`: `#[oai(one_of)]` needs one distinct schema per
/// discriminated variant, and sharing a single schema between two `kind` values confused the
/// generated OpenAPI discriminator mapping (the generated TypeScript client's `kind` field for
/// the shared schema only carried one of the two literal values, so the discriminated union
/// lost its other member and `tsc` failed on the `switch (value['kind'])` in the generated
/// `LoginNameTemplateToJSONTyped` — reproduced 2026-08-20 regenerating the admin API client).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct DomainSamAccountNameTemplate {
    pub domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct CustomTemplate {
    pub format: String,
}

impl LoginNameTemplate {
    /// Renders the effective target login name for `username`. Infallible: a
    /// `Custom` template with no `{username}` placeholder just yields the literal
    /// format string, which is a valid (if probably wrong) admin choice, not an
    /// error this layer should reject.
    pub fn render(&self, username: &str) -> String {
        match self {
            Self::SamAccountName(_) => username.to_owned(),
            Self::DomainSamAccountName(DomainSamAccountNameTemplate { domain }) => {
                format!("{domain}\\{username}")
            }
            Self::Upn(DomainTemplate { domain }) => format!("{username}@{domain}"),
            Self::Custom(CustomTemplate { format }) => format.replace("{username}", username),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_each_preset() {
        assert_eq!(
            LoginNameTemplate::SamAccountName(SamAccountNameTemplate {}).render("jdoe"),
            "jdoe"
        );
        assert_eq!(
            LoginNameTemplate::DomainSamAccountName(DomainSamAccountNameTemplate {
                domain: "CORP".into()
            })
            .render("jdoe"),
            "CORP\\jdoe"
        );
        assert_eq!(
            LoginNameTemplate::Upn(DomainTemplate {
                domain: "corp.example".into()
            })
            .render("jdoe"),
            "jdoe@corp.example"
        );
        assert_eq!(
            LoginNameTemplate::Custom(CustomTemplate {
                format: "ext-{username}-01".into()
            })
            .render("jdoe"),
            "ext-jdoe-01"
        );
    }

    #[test]
    fn custom_template_without_placeholder_is_the_literal_format() {
        assert_eq!(
            LoginNameTemplate::Custom(CustomTemplate {
                format: "svc_shared".into()
            })
            .render("jdoe"),
            "svc_shared"
        );
    }
}
