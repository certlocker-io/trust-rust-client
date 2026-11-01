// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use pkcs8::DecodePrivateKey;
use serde::Serialize;

use crate::error::TrustClientError;

/// Device / machine issuer (`iss`) for enrolled laptop and VPS JWTs.
///
/// Matches Trust `OidcAudiences.DEVICE_ISSUER`.
pub const DEVICE_ISSUER: &str = "https://trust.certlocker.io/oidc/device";

/// Default short-lived JWT lifetime used when minting for exchange.
pub const DEFAULT_TTL_MINUTES: u32 = 5;

/// Inputs for a device OIDC mint and Gateway exchange.
///
/// Provide either a private key path or a private key PEM string. When both
/// are set, the path is used. `key_id` is optional unless the enrolled
/// principal has a key id that must match the JWT `kid`.
///
/// The private key stays on the machine. Do not check it into source control.
#[derive(Debug, Clone)]
pub struct DeviceOidcConfig {
    /// Per-account audience, for example `https://trust.certlocker.io/oidc/<accountId>`.
    pub audience: String,
    /// Enrolled `device_id` claim value.
    pub device_id: String,
    /// Path to the PKCS#8 Ed25519 private key PEM from enroll.
    pub private_key_path: Option<PathBuf>,
    /// PKCS#8 Ed25519 private key PEM. Ignored when [`Self::private_key_path`] is set.
    pub private_key_pem: Option<String>,
    /// Optional JWT `kid`. Must match the enrolled principal `keyId` when that field is set.
    pub key_id: Option<String>,
    /// JWT `iss`. Defaults to [`DEVICE_ISSUER`].
    pub issuer: String,
    /// JWT lifetime in minutes. Values below 1 are treated as [`DEFAULT_TTL_MINUTES`].
    pub ttl_minutes: u32,
}

impl DeviceOidcConfig {
    /// Starts a builder.
    pub fn builder() -> DeviceOidcConfigBuilder {
        DeviceOidcConfigBuilder::default()
    }

    pub(crate) fn load_key(&self) -> Result<SigningKey, TrustClientError> {
        if let Some(path) = &self.private_key_path {
            load_private_key_from_file(path)
        } else {
            load_private_key_from_pem(self.private_key_pem.as_deref().unwrap_or(""))
        }
    }
}

/// Builder for [`DeviceOidcConfig`].
#[derive(Debug, Clone, Default)]
pub struct DeviceOidcConfigBuilder {
    audience: Option<String>,
    device_id: Option<String>,
    private_key_path: Option<PathBuf>,
    private_key_pem: Option<String>,
    key_id: Option<String>,
    issuer: Option<String>,
    ttl_minutes: Option<u32>,
}

impl DeviceOidcConfigBuilder {
    /// Sets the per-account audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Sets the enrolled device id.
    pub fn device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    /// Sets the private key path. A blank path clears it.
    pub fn private_key_path(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let text = path.to_string_lossy();
        self.private_key_path = if text.trim().is_empty() {
            None
        } else {
            Some(path)
        };
        self
    }

    /// Sets the PKCS#8 PEM string.
    pub fn private_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.private_key_pem = Some(pem.into());
        self
    }

    /// Sets the optional JWT `kid`.
    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Overrides the JWT issuer. The default is [`DEVICE_ISSUER`].
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets the JWT lifetime in minutes.
    pub fn ttl_minutes(mut self, ttl_minutes: u32) -> Self {
        self.ttl_minutes = Some(ttl_minutes);
        self
    }

    /// Validates required fields and builds the config.
    pub fn build(self) -> Result<DeviceOidcConfig, TrustClientError> {
        let audience = required(self.audience, "audience must not be blank")?;
        let device_id = required(self.device_id, "deviceId must not be blank")?;
        let has_path = self.private_key_path.is_some();
        let has_pem = self
            .private_key_pem
            .as_deref()
            .is_some_and(|pem| !pem.trim().is_empty());
        if !has_path && !has_pem {
            return Err(TrustClientError::config(
                "privateKeyPath or privateKeyPem is required",
            ));
        }
        let issuer = match self.issuer {
            Some(issuer) if !issuer.trim().is_empty() => issuer,
            _ => DEVICE_ISSUER.to_owned(),
        };
        let ttl_minutes = match self.ttl_minutes {
            Some(minutes) if minutes > 0 => minutes,
            _ => DEFAULT_TTL_MINUTES,
        };
        Ok(DeviceOidcConfig {
            audience,
            device_id,
            private_key_path: self.private_key_path,
            private_key_pem: self.private_key_pem,
            key_id: self.key_id.filter(|value| !value.trim().is_empty()),
            issuer,
            ttl_minutes,
        })
    }
}

fn required(value: Option<String>, message: &str) -> Result<String, TrustClientError> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(TrustClientError::config(message)),
    }
}

/// Builds the per-account audience URL `https://trust.certlocker.io/oidc/<accountId>`.
pub fn audience_for_account(account_id: &str) -> Result<String, TrustClientError> {
    if account_id.trim().is_empty() {
        return Err(TrustClientError::config("accountId is required"));
    }
    Ok(format!(
        "https://trust.certlocker.io/oidc/{}",
        account_id.trim()
    ))
}

/// Builds the JWT `sub` claim for a device id (`device:<deviceId>`).
pub fn subject_for_device(device_id: &str) -> Result<String, TrustClientError> {
    if device_id.trim().is_empty() {
        return Err(TrustClientError::config("deviceId is required"));
    }
    Ok(format!("device:{}", device_id.trim()))
}

/// Loads an Ed25519 private key from a PKCS#8 PEM file.
pub fn load_private_key_from_file(path: impl AsRef<Path>) -> Result<SigningKey, TrustClientError> {
    let path = path.as_ref();
    let pem = fs::read_to_string(path).map_err(|err| {
        TrustClientError::request(
            format!(
                "Failed to read DEVICE private key from {}: {err}",
                path.display()
            ),
            err,
        )
    })?;
    load_private_key_from_pem(&pem)
}

/// Loads an Ed25519 private key from a PKCS#8 PEM string
/// (`-----BEGIN PRIVATE KEY-----`).
///
/// OpenSSH and encrypted PEM files are rejected.
pub fn load_private_key_from_pem(pem: &str) -> Result<SigningKey, TrustClientError> {
    if pem.trim().is_empty() {
        return Err(TrustClientError::message(
            "DEVICE private key PEM is required",
        ));
    }
    if !pem.contains("BEGIN PRIVATE KEY") {
        return Err(TrustClientError::message(
            "DEVICE private key must be PKCS#8 PEM (-----BEGIN PRIVATE KEY-----); OpenSSL/encrypted or OpenSSH formats are not supported",
        ));
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(strip_pem(pem))
        .map_err(|err| {
            TrustClientError::message(format!("Invalid DEVICE private key PEM: {err}"))
        })?;
    SigningKey::from_pkcs8_der(&der).map_err(|err| {
        TrustClientError::message(format!(
            "Invalid DEVICE private key PEM: {err}. DEVICE private key must be Ed25519 PKCS#8"
        ))
    })
}

/// Mints a device JWT with [`DEFAULT_TTL_MINUTES`].
pub fn mint(
    audience: &str,
    device_id: &str,
    private_key: &SigningKey,
    key_id: Option<&str>,
) -> Result<String, TrustClientError> {
    mint_with_ttl(
        audience,
        device_id,
        private_key,
        key_id,
        DEFAULT_TTL_MINUTES,
    )
}

/// Mints a device JWT using [`DEVICE_ISSUER`].
pub fn mint_with_ttl(
    audience: &str,
    device_id: &str,
    private_key: &SigningKey,
    key_id: Option<&str>,
    ttl_minutes: u32,
) -> Result<String, TrustClientError> {
    mint_with_issuer(
        DEVICE_ISSUER,
        audience,
        device_id,
        private_key,
        key_id,
        ttl_minutes,
    )
}

/// Mints a short-lived device JWT (`alg=EdDSA`).
///
/// Claims match Trust `DeviceOidcVerifier`: `iss`, per-account `aud`,
/// `sub = device:<deviceId>`, `device_id`, `iat`, `exp`, and `jti`.
/// `kid` is set when `key_id` is non-blank.
pub fn mint_with_issuer(
    issuer: &str,
    audience: &str,
    device_id: &str,
    private_key: &SigningKey,
    key_id: Option<&str>,
    ttl_minutes: u32,
) -> Result<String, TrustClientError> {
    if issuer.trim().is_empty() {
        return Err(TrustClientError::message("DEVICE issuer is required"));
    }
    if audience.trim().is_empty() {
        return Err(TrustClientError::message("DEVICE audience is required"));
    }
    if device_id.trim().is_empty() {
        return Err(TrustClientError::message("deviceId is required"));
    }
    let ttl = ttl_minutes.max(1);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            TrustClientError::message(format!("System clock is before the unix epoch: {err}"))
        })?
        .as_secs() as i64;
    let subject = subject_for_device(device_id)?;
    let claims = Claims {
        iss: issuer.trim(),
        aud: audience.trim(),
        sub: &subject,
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now,
        exp: now + i64::from(ttl) * 60,
        device_id: device_id.trim(),
    };
    let payload = serde_json::to_string(&claims)
        .map_err(|err| TrustClientError::message(format!("Failed to mint DEVICE JWT: {err}")))?;
    let header = match key_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(kid) => {
            let kid = serde_json::to_string(kid).map_err(|err| {
                TrustClientError::message(format!("Failed to mint DEVICE JWT: {err}"))
            })?;
            format!(r#"{{"alg":"EdDSA","kid":{kid}}}"#)
        }
        None => r#"{"alg":"EdDSA"}"#.to_owned(),
    };
    let signing_input = format!("{}.{}", b64(header.as_bytes()), b64(payload.as_bytes()));
    let signature = private_key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64(&signature.to_bytes())))
}

/// Loads the private key from `private_key_path` and mints a device JWT.
pub fn mint_from_file(
    audience: &str,
    device_id: &str,
    private_key_path: impl AsRef<Path>,
    key_id: Option<&str>,
    ttl_minutes: u32,
) -> Result<String, TrustClientError> {
    let key = load_private_key_from_file(private_key_path)?;
    mint_with_ttl(audience, device_id, &key, key_id, ttl_minutes)
}

/// Loads the private key from a PEM string and mints a device JWT.
pub fn mint_from_pem(
    audience: &str,
    device_id: &str,
    private_key_pem: &str,
    key_id: Option<&str>,
    ttl_minutes: u32,
) -> Result<String, TrustClientError> {
    let key = load_private_key_from_pem(private_key_pem)?;
    mint_with_ttl(audience, device_id, &key, key_id, ttl_minutes)
}

pub(crate) fn mint_from_config(config: &DeviceOidcConfig) -> Result<String, TrustClientError> {
    let key = config.load_key()?;
    mint_with_issuer(
        &config.issuer,
        &config.audience,
        &config.device_id,
        &key,
        config.key_id.as_deref(),
        config.ttl_minutes,
    )
}

fn strip_pem(pem: &str) -> String {
    pem.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect()
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    jti: String,
    iat: i64,
    exp: i64,
    device_id: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    const DOGFOOD_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIF9AaYYFhQwyap4byHSJdP10An9RnSyjIs7938lU7Sm/\n-----END PRIVATE KEY-----\n";

    const DOGFOOD_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAWSHYSlK7bRVNfnJZkuuPdvt8YVdUc4YQlsLB1DfEV3U=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn mints_an_eddsa_jwt_matching_trust_claims() {
        let private_key = load_private_key_from_pem(DOGFOOD_PRIVATE_PEM).unwrap();
        let audience = audience_for_account("acct-dogfood").unwrap();
        let jwt = mint_with_ttl(
            &audience,
            "laptop-dogfood-1",
            &private_key,
            Some("trust-device-dexta"),
            5,
        )
        .unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value = decode_part(parts[0]);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], "trust-device-dexta");

        let claims: serde_json::Value = decode_part(parts[1]);
        assert_eq!(claims["iss"], DEVICE_ISSUER);
        assert_eq!(claims["aud"], audience);
        assert_eq!(claims["sub"], "device:laptop-dogfood-1");
        assert_eq!(claims["device_id"], "laptop-dogfood-1");
        assert!(claims["jti"].as_str().unwrap().len() > 8);
        let exp = claims["exp"].as_i64().unwrap();
        let iat = claims["iat"].as_i64().unwrap();
        assert_eq!(exp - iat, 5 * 60);

        let public_key = load_public(DOGFOOD_PUBLIC_PEM);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap();
        let signature = Signature::from_slice(&sig_bytes).unwrap();
        public_key
            .verify(signing_input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn loads_a_private_key_from_a_file() {
        let path = std::env::temp_dir().join(format!("trust-device-{}.pem", uuid::Uuid::new_v4()));
        fs::write(&path, DOGFOOD_PRIVATE_PEM).unwrap();
        let from_file = load_private_key_from_file(&path).unwrap();
        let from_pem = load_private_key_from_pem(DOGFOOD_PRIVATE_PEM).unwrap();
        let _ = fs::remove_file(&path);
        assert_eq!(from_file.to_bytes(), from_pem.to_bytes());

        let jwt = mint_from_pem(
            &audience_for_account("a1").unwrap(),
            "dev-1",
            DOGFOOD_PRIVATE_PEM,
            None,
            2,
        )
        .unwrap();
        assert_eq!(jwt.split('.').count(), 3);
        assert!(jwt.starts_with("eyJ"));
    }

    #[test]
    fn rejects_non_pkcs8_pem() {
        let err = load_private_key_from_pem(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n-----END OPENSSH PRIVATE KEY-----",
        )
        .unwrap_err();
        assert!(err.to_string().contains("PKCS#8"));
    }

    #[test]
    fn config_requires_key_material() {
        let err = DeviceOidcConfig::builder()
            .audience("https://trust.certlocker.io/oidc/a")
            .device_id("d1")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("privateKeyPath"));
    }

    fn decode_part(part: &str) -> serde_json::Value {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn load_public(pem: &str) -> VerifyingKey {
        let der = base64::engine::general_purpose::STANDARD
            .decode(strip_pem(pem))
            .unwrap();
        let raw: [u8; 32] = der[der.len() - 32..].try_into().unwrap();
        VerifyingKey::from_bytes(&raw).unwrap()
    }
}
