use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use delegate::delegate;
use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseFromJSON, ToJSON};
use serde::{Deserialize, Serialize};

use crate::Secret;
use crate::encryption::{
    EncryptionError, VAULT_REF_PREFIX, idempotent_maybe_decrypt, idempotent_maybe_encrypt_secret,
    is_envelope, is_vault_reference,
};

/// Implemented by whatever backs `Target.options.auth` externally — today
/// `warpgate-vault`'s OpenBao client (see `ARCHITECTURE_TECHNIQUE.md` §10).
/// `warpgate-common` only knows this trait, never the concrete backend: the
/// backend crate depends on `warpgate-common` (for `Secret`/`EncryptionError`),
/// so `warpgate-common` cannot depend back on it without a cycle. The resolver is
/// installed once at startup via `install_vault_resolver`, mirroring the
/// `env_keyring()`/`OnceLock` pattern already used for the encryption-at-rest key.
#[async_trait]
pub trait VaultSecretResolver: Send + Sync {
    /// Store `value` in the vault and return a backend-specific reference to it.
    async fn store(&self, value: Secret<String>) -> Result<String, EncryptionError>;
    /// Resolve a reference previously returned by `store`.
    async fn resolve(&self, reference: &str) -> Result<Secret<String>, EncryptionError>;
}

static VAULT_RESOLVER: OnceLock<Arc<dyn VaultSecretResolver>> = OnceLock::new();

/// Called once at startup if a vault is configured. A later call is a no-op — there
/// is no legitimate reason to swap the resolver mid-process, so this mirrors
/// `OnceLock::set`'s own semantics rather than silently overwriting.
pub fn install_vault_resolver(resolver: Arc<dyn VaultSecretResolver>) {
    let _ = VAULT_RESOLVER.set(resolver);
}

fn vault_resolver() -> Option<&'static Arc<dyn VaultSecretResolver>> {
    VAULT_RESOLVER.get()
}

/// Vault-backed alternative to `idempotent_maybe_encrypt_secret`, used on the
/// write path for secrets being migrated to an external vault. When a resolver is
/// installed, hands the plaintext to it and stores only a reference; otherwise
/// falls back to the existing envelope-encryption path (dev, or before a vault is
/// configured for this deployment). Idempotent: an existing reference or envelope
/// passes through unchanged rather than being wrapped again.
pub async fn externalize_secret(value: &str) -> Result<String, EncryptionError> {
    if is_vault_reference(value) || is_envelope(value) {
        return Ok(value.to_owned());
    }
    match vault_resolver() {
        Some(resolver) => {
            let reference = resolver.store(Secret::new(value.to_owned())).await?;
            Ok(format!("{VAULT_REF_PREFIX}{reference}"))
        }
        None => idempotent_maybe_encrypt_secret(value),
    }
}

/// Resolves a raw stored value that may be a vault reference, an envelope-encrypted
/// blob, or plaintext. The shared core of `StoredSecret::reveal`, exposed as a free
/// function so it's reusable by fields that aren't wrapped in `StoredSecret` — e.g.
/// `LdapServer.bind_password` (plain `String` column) or the base64-bridged TOTP
/// seed (see `helpers::otp`) — without duplicating the vault-reference branch.
pub async fn resolve_stored_secret(raw: &str) -> Result<Secret<String>, EncryptionError> {
    if let Some(reference) = raw.strip_prefix(VAULT_REF_PREFIX) {
        let resolver = vault_resolver().ok_or_else(|| {
            EncryptionError::VaultError(
                "this credential is stored in a vault, but no vault resolver is configured on this node".into(),
            )
        })?;
        return resolver.resolve(reference).await;
    }
    idempotent_maybe_decrypt(raw).map(Secret::new)
}

/// A wrapper for a (maybe) encrypted, or vault-referenced, credential
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StoredSecret(Secret<String>);

impl StoredSecret {
    /// Wraps a value in whatever form it already has.
    /// Encryption happens when saving, not here
    pub const fn new(value: Secret<String>) -> Self {
        Self(value)
    }

    /// Decrypted (or vault-resolved) credential value. Async because a vault
    /// reference needs a network round-trip — see `VaultSecretResolver`.
    pub async fn reveal(&self) -> Result<Secret<String>, EncryptionError> {
        resolve_stored_secret(self.0.expose_secret()).await
    }
}

impl Default for StoredSecret {
    fn default() -> Self {
        Self::new(Secret::new(String::new()))
    }
}

impl From<String> for StoredSecret {
    fn from(v: String) -> Self {
        Self::new(Secret::new(v))
    }
}

impl Debug for StoredSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<secret>")
    }
}

impl poem_openapi::types::Type for StoredSecret {
    const IS_REQUIRED: bool = <Secret<String> as poem_openapi::types::Type>::IS_REQUIRED;
    type RawValueType = <Secret<String> as poem_openapi::types::Type>::RawValueType;
    type RawElementValueType = <Secret<String> as poem_openapi::types::Type>::RawElementValueType;

    fn name() -> Cow<'static, str> {
        Secret::<String>::name()
    }
    fn schema_ref() -> MetaSchemaRef {
        Secret::<String>::schema_ref()
    }
    fn register(registry: &mut Registry) {
        Secret::<String>::register(registry);
    }

    delegate! {
        to self.0 {
            fn as_raw_value(&self) -> Option<&Self::RawValueType>;
            fn raw_element_iter(
                &'_ self,
            ) -> Box<dyn Iterator<Item = &'_ Self::RawElementValueType> + '_>;
            fn is_empty(&self) -> bool;
            fn is_none(&self) -> bool;
        }
    }
}

impl ParseFromJSON for StoredSecret {
    fn parse_from_json(value: Option<serde_json::Value>) -> poem_openapi::types::ParseResult<Self> {
        Secret::<String>::parse_from_json(value)
            .map(Self::new)
            .map_err(|e| poem_openapi::types::ParseError::custom(e.into_message()))
    }
}

impl ToJSON for StoredSecret {
    fn to_json(&self) -> Option<serde_json::Value> {
        self.0.to_json()
    }
}
