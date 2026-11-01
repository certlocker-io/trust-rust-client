// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

use super::asset::{Asset, AssetStatus};

/// Kind of secret stored in Trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretType {
    /// Private key material.
    PrivateKey,
    /// PEM-encoded key or certificate material.
    Pem,
    /// Password string.
    Password,
    /// Username and password pair.
    Credentials,
    /// Free-form configuration text.
    Configuration,
}

impl SecretType {
    /// Whether this secret type has a key algorithm.
    ///
    /// True for [`Self::PrivateKey`] and [`Self::Pem`].
    pub fn has_algo(self) -> bool {
        matches!(self, Self::PrivateKey | Self::Pem)
    }
}

/// Public-key algorithm for generated PEM and private-key secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretKeyAlgorithm {
    /// RSA.
    Rsa,
    /// Elliptic Curve Digital Signature Algorithm.
    Ecdsa,
    /// Ed25519.
    Ed25519,
}

impl SecretKeyAlgorithm {
    /// Ed25519 is the algorithm Trust treats as post-quantum ready.
    pub fn is_pq_ready(self) -> bool {
        self == Self::Ed25519
    }
}

/// Secret record returned by `get`.
///
/// `secret` on this record is stored material when Trust includes it.
/// Use [`crate::TrustService::fetch_secret`] for the secret contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", default)]
pub struct Secret {
    /// Asset id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Tenant account id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Free-form description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Lifecycle status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<AssetStatus>,
    /// Groups the asset belongs to.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::model::de::opt_vec"
    )]
    pub groups: Option<Vec<String>>,
    /// Principal that created the asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Principal that last updated the asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    /// Creation time, UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::model::de::opt_datetime"
    )]
    pub date_created: Option<chrono::DateTime<chrono::Utc>>,
    /// Last update time, UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::model::de::opt_datetime"
    )]
    pub date_updated: Option<chrono::DateTime<chrono::Utc>>,
    /// Who holds the edit lock, when the asset is locked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_by: Option<String>,
    /// When the edit lock was taken, UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::model::de::opt_datetime"
    )]
    pub date_locked: Option<chrono::DateTime<chrono::Utc>>,
    /// Discriminator for the secret payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<SecretType>,
    /// Stored secret material, when the record includes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Secret version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
}

impl_asset!(Secret);

/// PEM secret contents, including the key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", default)]
pub struct Pem {
    /// Key algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<SecretKeyAlgorithm>,
    /// Key size, as Trust stores it (for example `"256"` or `"2048"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<String>,
    /// Optional username paired with the PEM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// PEM text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl Pem {
    /// Whether the key algorithm is Ed25519.
    pub fn is_pq_ready(&self) -> bool {
        self.key_algorithm
            .is_some_and(SecretKeyAlgorithm::is_pq_ready)
    }
}

/// Private key secret contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", default)]
pub struct PrivateKey {
    /// Key algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<SecretKeyAlgorithm>,
    /// Key size, as Trust stores it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<String>,
    /// Private key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl PrivateKey {
    /// Whether the key algorithm is Ed25519.
    pub fn is_pq_ready(&self) -> bool {
        self.key_algorithm
            .is_some_and(SecretKeyAlgorithm::is_pq_ready)
    }
}

/// Username and password secret contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", default)]
pub struct Credentials {
    /// Username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Password secret. The password is the fetched secret contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Password {
    /// Password text returned by `fetch`.
    pub password: String,
}

impl Password {
    pub(crate) fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
        }
    }
}

/// Configuration secret. The secret value is the fetched secret contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    /// Configuration text returned by `fetch`.
    pub secret: String,
}

impl Configuration {
    pub(crate) fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_secret_record_and_typed_payloads() {
        let secret: Secret = serde_json::from_str(
            r#"{"id":"mvusgvkv5","account_id":"acct","name":"app","status":"ACTIVE","secret_type":"CONFIGURATION","version":3,"groups":"ops"}"#,
        )
        .unwrap();
        assert_eq!(secret.id.as_deref(), Some("mvusgvkv5"));
        assert_eq!(secret.secret_type, Some(SecretType::Configuration));
        assert!(secret.is_active());
        assert_eq!(secret.groups.unwrap(), vec!["ops"]);
        assert!(SecretType::Pem.has_algo());
        assert!(!SecretType::Password.has_algo());

        let pem: Pem = serde_json::from_str(
            r#"{"key_algorithm":"ED25519","key_size":"256","username":"root","key":"-----BEGIN"}"#,
        )
        .unwrap();
        assert!(pem.is_pq_ready());

        let key: PrivateKey =
            serde_json::from_str(r#"{"key_algorithm":"RSA","key_size":"2048","key":"pem"}"#)
                .unwrap();
        assert!(!key.is_pq_ready());
    }
}
