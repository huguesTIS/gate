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

/// Resolves a stored TOTP seed. Three cases, tried in order:
/// 1. A vault reference or envelope-encrypted blob — resolve it, then base64-decode (mirrors
///    `externalize_otp_key`, which always base64-encodes before wrapping).
/// 2. Bare base64 text, unwrapped — what `externalize_otp_key` actually produces when neither
///    a vault nor an encryption key is configured: `externalize_secret`'s no-op passthrough
///    leaves the base64 encoding it applied sitting in the column with no recognizable prefix.
///    Found the hard way: a TOTP code that verifies correctly against the *raw base64 text*
///    bytes (not the seed they encode) never matches what a real authenticator app computes —
///    every login fails silently, no error, just always "incorrect one-time password".
/// 3. Anything else — a row that predates this externalization entirely, holding the raw seed
///    directly with no wrapping at all (`credentials_otp` had no encryption of any kind before
///    it existed).
///
/// Distinguishing 2 and 3 from a genuine legacy seed: a random 32-byte seed being *also* valid
/// UTF-8 and *also* entirely within the base64 alphabet is vanishingly unlikely — the same class
/// of assumption `is_envelope`'s prefix match already relies on.
pub async fn resolve_otp_key(raw: &[u8]) -> Result<OtpSecretKey, EncryptionError> {
    let Ok(text) = std::str::from_utf8(raw) else {
        return Ok(Secret::new(raw.to_vec()));
    };
    if is_vault_reference(text) || is_envelope(text) {
        let resolved = resolve_stored_secret(text).await?;
        let decoded = BASE64
            .decode(resolved.expose_secret().as_bytes())
            .map_err(|_| EncryptionError::Corrupt)?;
        return Ok(Secret::new(decoded));
    }
    if let Ok(decoded) = BASE64.decode(text.as_bytes()) {
        return Ok(Secret::new(decoded));
    }
    Ok(Secret::new(raw.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces a real bug: with no vault and no encryption key configured (the common case
    /// for a bare test/dev deployment), `externalize_otp_key` still base64-encodes the seed
    /// before calling `externalize_secret` — whose no-op passthrough then leaves that base64
    /// text sitting in the column unwrapped. Before this fix, `resolve_otp_key` had no way to
    /// tell that apart from a genuine legacy raw seed, so it used the *base64 text's bytes* as
    /// the TOTP key instead of decoding it — every code a real authenticator app computed then
    /// failed to verify, silently, forever, regardless of what was typed.
    #[tokio::test]
    async fn round_trips_through_externalize_and_resolve_with_no_vault_configured() {
        let key = generate_key();
        let stored = externalize_otp_key(&key).await.expect("externalize");
        let resolved = resolve_otp_key(&stored).await.expect("resolve");
        assert_eq!(resolved.expose_secret(), key.expose_secret());
    }

    /// A code computed against the original key must still verify after the seed has been
    /// through a full store/resolve round trip — the actual failure mode this bug caused.
    #[tokio::test]
    async fn a_code_valid_for_the_original_key_verifies_after_round_trip() {
        let key = generate_key();
        let stored = externalize_otp_key(&key).await.expect("externalize");
        let resolved = resolve_otp_key(&stored).await.expect("resolve");

        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = get_totp(&key, None).generate(time);

        assert!(verify_totp(&code, &resolved));
    }

    /// A row that predates externalization (a raw random seed, no wrapping at all) must still
    /// resolve to itself unchanged — the fallback this fix must not regress.
    #[tokio::test]
    async fn a_legacy_unwrapped_raw_seed_is_returned_unchanged() {
        // Fixed rather than random so it can't coincidentally be valid UTF-8/base64 and take
        // the wrong branch, which would make this test flaky.
        let raw: Vec<u8> = vec![0xff, 0x00, 0xfe, 0x01, 0xfd, 0x02, 0xfc, 0x03];
        let resolved = resolve_otp_key(&raw).await.expect("resolve legacy seed");
        assert_eq!(resolved.expose_secret(), &raw);
    }
}
