//! Minimal OpenBao (Vault-compatible) KV v2 client — see `ARCHITECTURE_TECHNIQUE.md` §10.
//!
//! Scope is deliberately narrow: read/write/delete a single secret value by path.
//! Nothing here decides *what* goes in OpenBao — callers (e.g. the `managed_accounts`
//! admin endpoints) own that; this crate only speaks the KV v2 HTTP API.
//!
//! Config is read from the environment (`OPENBAO_ADDR`/`OPENBAO_TOKEN`/`OPENBAO_MOUNT`)
//! for now — dev-only wiring, matches the throwaway `bao server -dev` container used to
//! build this. Production config should move into `WarpgateConfig` once this proves out
//! (not done here to avoid touching the config schema/loader for an unproven path).

use async_trait::async_trait;
use serde_json::json;
use warpgate_common::encryption::EncryptionError;
use warpgate_common::{Secret, VaultSecretResolver, WarpgateError};

/// `reqwest` is built with `rustls-no-provider` (see workspace `Cargo.toml`) — the
/// app must install a crypto provider before any TLS-capable client is used, even
/// for plain `http://` requests (the client's TLS stack is still initialized).
/// Idempotent and safe to call from every entry point — matches the
/// `let _ = ...install_default();` pattern used throughout the rest of the
/// workspace (e.g. `warpgate-tls/src/rustls_helpers.rs`), rather than assuming a
/// caller (like `warpgate/src/main.rs`) already did it — `warpgate-vault`'s own
/// tests don't go through that binary.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub struct VaultConfig {
    pub address: String,
    pub token: Secret<String>,
    pub mount: String,
}

impl VaultConfig {
    pub fn from_env() -> Result<Self, WarpgateError> {
        let address = std::env::var("OPENBAO_ADDR")
            .map_err(|_| WarpgateError::InconsistentState("OPENBAO_ADDR not set".into()))?;
        let token = std::env::var("OPENBAO_TOKEN")
            .map_err(|_| WarpgateError::InconsistentState("OPENBAO_TOKEN not set".into()))?;
        let mount = std::env::var("OPENBAO_MOUNT").unwrap_or_else(|_| "secret".into());
        Ok(Self {
            address,
            token: Secret::new(token),
            mount,
        })
    }

    fn data_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/data/{}",
            self.address.trim_end_matches('/'),
            self.mount,
            path.trim_start_matches('/')
        )
    }

    fn metadata_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{}",
            self.address.trim_end_matches('/'),
            self.mount,
            path.trim_start_matches('/')
        )
    }
}

/// Writes `value` as the secret at `path` (KV v2 — creates a new version if one
/// already exists; OpenBao keeps prior versions per its own retention policy).
pub async fn write_secret_value(
    config: &VaultConfig,
    path: &str,
    value: &Secret<String>,
) -> Result<(), WarpgateError> {
    ensure_crypto_provider();
    let client = reqwest::Client::new();
    let response = client
        .post(config.data_url(path))
        .header("X-Vault-Token", config.token.expose_secret())
        .json(&json!({ "data": { "value": value.expose_secret() } }))
        .send()
        .await
        .map_err(|e| WarpgateError::InconsistentState(format!("OpenBao request failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(WarpgateError::InconsistentState(format!(
            "OpenBao write to {path} failed: {status} {body}"
        )));
    }
    Ok(())
}

/// Reads the secret at `path`. `Ok(None)` if nothing is stored there (a 404 from
/// OpenBao) — distinguished from a real error so callers can tell "not configured
/// yet" apart from "OpenBao is unreachable/misconfigured".
pub async fn read_secret_value(
    config: &VaultConfig,
    path: &str,
) -> Result<Option<Secret<String>>, WarpgateError> {
    ensure_crypto_provider();
    let client = reqwest::Client::new();
    let response = client
        .get(config.data_url(path))
        .header("X-Vault-Token", config.token.expose_secret())
        .send()
        .await
        .map_err(|e| WarpgateError::InconsistentState(format!("OpenBao request failed: {e}")))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(WarpgateError::InconsistentState(format!(
            "OpenBao read from {path} failed: {status} {body}"
        )));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| WarpgateError::InconsistentState(format!("OpenBao response parse failed: {e}")))?;
    let value = body
        .get("data")
        .and_then(|d| d.get("data"))
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str());
    Ok(value.map(|v| Secret::new(v.to_owned())))
}

/// Purges every version of the secret at `path` (KV v2 metadata delete — not the
/// soft-delete `DELETE .../data/...` endpoint, which only marks the latest version
/// deleted but keeps it recoverable).
pub async fn delete_secret(config: &VaultConfig, path: &str) -> Result<(), WarpgateError> {
    ensure_crypto_provider();
    let client = reqwest::Client::new();
    let response = client
        .delete(config.metadata_url(path))
        .header("X-Vault-Token", config.token.expose_secret())
        .send()
        .await
        .map_err(|e| WarpgateError::InconsistentState(format!("OpenBao request failed: {e}")))?;

    if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(WarpgateError::InconsistentState(format!(
            "OpenBao delete of {path} failed: {status} {body}"
        )));
    }
    Ok(())
}

/// `warpgate_common::VaultSecretResolver` backed by this OpenBao client — the
/// concrete implementation installed at startup via
/// `warpgate_common::install_vault_resolver` when `OPENBAO_ADDR` is set. Kept
/// separate from the bare `read_secret_value`/`write_secret_value` functions above
/// so those stay usable directly (as `managed_accounts`' `SecretApi` does) without
/// going through the trait.
pub struct OpenBaoResolver {
    config: VaultConfig,
}

impl OpenBaoResolver {
    pub fn from_env() -> Result<Self, WarpgateError> {
        Ok(Self {
            config: VaultConfig::from_env()?,
        })
    }
}

#[async_trait]
impl VaultSecretResolver for OpenBaoResolver {
    async fn store(&self, value: Secret<String>) -> Result<String, EncryptionError> {
        let path = format!("target-secrets/{}", uuid::Uuid::new_v4());
        write_secret_value(&self.config, &path, &value)
            .await
            .map_err(|e| EncryptionError::VaultError(e.to_string()))?;
        Ok(path)
    }

    async fn resolve(&self, reference: &str) -> Result<Secret<String>, EncryptionError> {
        read_secret_value(&self.config, reference)
            .await
            .map_err(|e| EncryptionError::VaultError(e.to_string()))?
            .ok_or_else(|| {
                EncryptionError::VaultError(format!("no secret found at vault path {reference}"))
            })
    }
}

#[cfg(test)]
mod tests {
    //! Integration tests against a real OpenBao — `#[ignore]`d by default since
    //! `cargo test` shouldn't require live infra. Run explicitly with a dev server
    //! up (see ARCHITECTURE_TECHNIQUE.md §10 / CLAUDE.md backlog):
    //!
    //! ```sh
    //! docker run -d --name warpgate-openbao-dev -p 8200:8200 --cap-add=IPC_LOCK \
    //!   -e 'BAO_DEV_ROOT_TOKEN_ID=devroot' openbao/openbao:latest \
    //!   server -dev -dev-listen-address=0.0.0.0:8200
    //! OPENBAO_ADDR=http://localhost:8200 OPENBAO_TOKEN=devroot \
    //!   cargo test -p warpgate-vault -- --ignored
    //! ```

    use super::*;

    #[tokio::test]
    #[ignore = "needs a live OpenBao — see module docs"]
    async fn round_trips_a_secret_through_a_real_openbao() {
        let config = VaultConfig::from_env().expect("OPENBAO_ADDR/OPENBAO_TOKEN must be set");
        let path = format!("warpgate-vault-test/{}", uuid_like_suffix());

        assert!(
            read_secret_value(&config, &path).await.unwrap().is_none(),
            "path should start out empty"
        );

        write_secret_value(&config, &path, &Secret::new("s3cret".into()))
            .await
            .unwrap();

        let read_back = read_secret_value(&config, &path).await.unwrap().unwrap();
        assert_eq!(read_back.expose_secret(), "s3cret");

        delete_secret(&config, &path).await.unwrap();
        assert!(read_secret_value(&config, &path).await.unwrap().is_none());
    }

    fn uuid_like_suffix() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{nanos}")
    }
}
