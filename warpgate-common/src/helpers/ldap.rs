//! Vault/envelope resolution for `LdapServer.bind_password`.
//!
//! This can't live in `warpgate-ldap` itself: the dependency runs the other way
//! (`warpgate-common` already depends on `warpgate-ldap`, for
//! `WarpgateError::Ldap`), so `warpgate-ldap` cannot depend back on
//! `warpgate-common` for `resolve_stored_secret` without a cycle. Every caller
//! that builds a `warpgate_ldap::LdapConfig` from a stored `LdapServer` row must
//! call `resolve_ldap_bind_password` on it before connecting — `warpgate-ldap`'s
//! own functions (`connect`/`test_connection`/`discover_base_dns`/...) take the
//! password as-is and have no notion of vault references or envelopes.

use crate::encryption::EncryptionError;
use crate::resolve_stored_secret;

/// Resolves `config.bind_password` in place if it's a vault reference or an
/// envelope-encrypted value; leaves a plaintext (or already-migrated legacy) value
/// untouched.
pub async fn resolve_ldap_bind_password(
    config: &mut warpgate_ldap::LdapConfig,
) -> Result<(), EncryptionError> {
    config.bind_password = resolve_stored_secret(&config.bind_password)
        .await?
        .expose_secret()
        .clone();
    Ok(())
}
