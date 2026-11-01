// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::asset::{Asset, AssetStatus};
use super::de;

/// How a certificate was validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateValidation {
    /// Domain Validated.
    #[serde(rename = "DV")]
    Dv,
    /// Organization Validated.
    #[serde(rename = "OV")]
    Ov,
    /// Extended Validation.
    #[serde(rename = "EV")]
    Ev,
    /// Self-signed.
    #[serde(rename = "SS")]
    Ss,
    /// Unknown or unspecified validation.
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl CertificateValidation {
    /// Display name of this validation level.
    pub fn description(self) -> &'static str {
        match self {
            Self::Dv => "Domain Validated",
            Self::Ov => "Organization Validated",
            Self::Ev => "Extended Validation",
            Self::Ss => "Self Signed",
            Self::Unknown => "Unknown",
        }
    }
}

/// Certificate record returned by `get`.
///
/// [`crate::TrustService::fetch_certificate`] returns the PEM contents.
/// [`crate::TrustService::fetch_certificate_bundle`] returns the certificate and private key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", default)]
pub struct Certificate {
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
    pub date_created: Option<DateTime<Utc>>,
    /// Last update time, UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::model::de::opt_datetime"
    )]
    pub date_updated: Option<DateTime<Utc>>,
    /// Who holds the edit lock, when the asset is locked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_by: Option<String>,
    /// When the edit lock was taken, UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::model::de::opt_datetime"
    )]
    pub date_locked: Option<DateTime<Utc>>,
    /// Not-after time, UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_datetime"
    )]
    pub expires: Option<DateTime<Utc>>,
    /// Primary domain name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_domain: Option<String>,
    /// Subject alternative names.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_vec"
    )]
    pub san_domains: Option<Vec<String>>,
    /// Not-before time, UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_datetime"
    )]
    pub not_before: Option<DateTime<Utc>>,
    /// Number of entries in the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<i32>,
    /// Certificate serial number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Public key algorithm name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_algo: Option<String>,
    /// Whether the certificate is a Merkle-tree certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_tree_cert: Option<bool>,
    /// Issuer common name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    /// Issuer organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_o: Option<String>,
    /// SHA-256 fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
    /// SHA-1 fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha1: Option<String>,
    /// Public certificate PEM, when the record includes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_cert: Option<String>,
    /// Extra certificate properties text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_properties: Option<String>,
    /// Private key PEM, when the record includes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Validation level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_validation: Option<CertificateValidation>,
    /// Linked asset id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_id: Option<String>,
    /// Percentage of the validity window remaining.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent_remaining: Option<i32>,
}

impl_asset!(Certificate);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_certificate_metadata() {
        let cert: Certificate = serde_json::from_str(
            r#"{"id":"cert1","primary_domain":"app.example","san_domains":["app.example"],"cert_validation":"DV","status":"ACTIVE","not_before":"2026-01-01T00:00:00"}"#,
        )
        .unwrap();
        assert_eq!(cert.primary_domain.as_deref(), Some("app.example"));
        assert_eq!(
            cert.cert_validation.unwrap().description(),
            "Domain Validated"
        );
        assert!(cert.is_active());
    }
}
