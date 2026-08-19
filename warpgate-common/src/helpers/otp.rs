use std::time::SystemTime;

use data_encoding::BASE64;
use rand::RngExt;
use totp_rs::{Algorithm, TOTP};

use super::rng::get_crypto_rng;
use crate::encryption::{EncryptionError, is_envelope, is_vault_reference};
use crate::types::{Secret, externalize_secret, resolve_stored_secret};

pub type OtpExposedSecretKey = Vec<u8>;
pub type OtpSecretKey = Secret<OtpExposedSecretKey>;

pub const OTP_DIGITS: usize = 6;

pub fn generate_key() -> OtpSecretKey {
    Secret::new(get_crypto_rng().random::<[u8; 32]>().into())
}

pub fn generate_setup_url(key: &OtpSecretKey, label: &str) -> Secret<String> {
    let totp = get_totp(key, Some(label));
    Secret::new(totp.get_url())
}

fn get_totp(key: &OtpSecretKey, label: Option<&str>) -> TOTP {
    TOTP {
        algorithm: Algorithm::SHA1,
        digits: OTP_DIGITS,
        skew: 1,
        step: 30,
        secret: key.expose_secret().clone(),
        issuer: Some("Warpgate".to_string()),
        account_name: label.unwrap_or("").to_string(),
    }
}

pub fn verify_totp(code: &str, key: &OtpSecretKey) -> bool {
    #[allow(clippy::unwrap_used)]
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    get_totp(key, None).check(code, time)
}

/// Prepares a TOTP seed for storage — same vault-or-envelope externalization as
/// `StoredSecret`, bridged through base64 since the seed is raw bytes and
/// `externalize_secret` is string-shaped. The `credentials_otp.secret_key` column
/// stays `Vec<u8>` (no migration needed): a migrated row holds the resulting
/// UTF-8 reference/envelope string as bytes.
pub async fn externalize_otp_key(key: &OtpSecretKey) -> Result<Vec<u8>, EncryptionError> {
    let encoded = BASE64.encode(key.expose_secret());
    let stored = externalize_secret(&encoded).await?;
    Ok(stored.into_bytes())
}

/// Resolves a stored TOTP seed, transparently handling rows that predate this
/// externalization: those hold the raw seed directly, with no wrapping at all
/// (`credentials_otp` had no encryption of any kind before this). Distinguishing
/// the two: a migrated row is valid UTF-8 starting with a recognized prefix; a
/// genuine random 32-byte seed doing the same is vanishingly unlikely (< 2^-96),
/// the same class of assumption `is_envelope`'s prefix match already relies on.
pub async fn resolve_otp_key(raw: &[u8]) -> Result<OtpSecretKey, EncryptionError> {
    if let Ok(text) = std::str::from_utf8(raw)
        && (is_vault_reference(text) || is_envelope(text))
    {
        let resolved = resolve_stored_secret(text).await?;
        let decoded = BASE64
            .decode(resolved.expose_secret().as_bytes())
            .map_err(|_| EncryptionError::Corrupt)?;
        return Ok(Secret::new(decoded));
    }
    Ok(Secret::new(raw.to_vec()))
}
