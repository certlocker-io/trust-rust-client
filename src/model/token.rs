// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::asset::{Asset, AssetStatus};
use super::de;

/// What a token grants access to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TokenType {
    /// Certificate asset token.
    Certificate,
    /// Host asset token.
    Host,
    /// Bastion access token.
    Bastion,
    /// Secret asset token.
    Secret,
    /// Root / elevated token.
    Root,
    /// MCP protocol token.
    Mcp,
    /// Wildcard token spanning multiple assets.
    Wildcard,
}

impl TokenType {
    /// Wire value used by the Gateway (`SECRET`, `CERTIFICATE`, `MCP`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "CERTIFICATE",
            Self::Host => "HOST",
            Self::Bastion => "BASTION",
            Self::Secret => "SECRET",
            Self::Root => "ROOT",
            Self::Mcp => "MCP",
            Self::Wildcard => "WILDCARD",
        }
    }

    /// Mint types the OIDC exchange accepts.
    ///
    /// Other variants are valid token records, but the Gateway only mints
    /// `SECRET`, `CERTIFICATE`, and `MCP` from an OIDC principal.
    pub fn is_oidc_mint_type(self) -> bool {
        matches!(self, Self::Secret | Self::Certificate | Self::Mcp)
    }
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Protocol a token is allowed to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Protocol {
    /// SSH access.
    Ssh,
    /// SFTP file transfer.
    Sftp,
    /// HTTPS API / fetch.
    Https,
    /// ACME certificate automation.
    Acme,
    /// Model Context Protocol.
    Mcp,
    /// Remote Desktop Protocol.
    Rdp,
    /// VNC remote desktop.
    Vnc,
}

impl Protocol {
    /// Whether this protocol is SSH or SFTP.
    pub fn is_ssh_family(self) -> bool {
        matches!(self, Self::Ssh | Self::Sftp)
    }
}

/// Access token record returned by `get`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", default)]
pub struct Token {
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
    /// Whether the token can be used once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_use: Option<bool>,
    /// Protocols the token may use.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_vec"
    )]
    pub protocols: Option<Vec<Protocol>>,
    /// What the token grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<TokenType>,
    /// Hosts the token may reach.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_vec"
    )]
    pub hosts: Option<Vec<String>>,
    /// Groups the token may access.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_vec"
    )]
    pub group_access: Option<Vec<String>>,
    /// Secret id, when the token is bound to one secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    /// Access code metadata. This is not the code to send on requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_code: Option<String>,
    /// Bastion id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bastion_id: Option<String>,
    /// Certificate id, when the token is bound to one certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_id: Option<String>,
    /// Whether Trust rotates the token automatically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_rotate: Option<bool>,
    /// Allowed client CIDR.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// User id the token acts as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Agent id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Time the token becomes valid, UTC.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de::opt_datetime"
    )]
    pub start_time: Option<DateTime<Utc>>,
    /// Percentage of the token lifetime remaining.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent_remaining: Option<i32>,
}

impl_asset!(Token);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_token_record() {
        let token: Token = serde_json::from_str(
            r#"{"id":"tok","token_type":"SECRET","protocols":"SSH","single_use":false,"status":"ACTIVE"}"#,
        )
        .unwrap();
        assert_eq!(token.token_type, Some(TokenType::Secret));
        assert!(token.protocols.as_ref().unwrap()[0].is_ssh_family());
        assert!(token.is_active());
        assert!(TokenType::Mcp.is_oidc_mint_type());
        assert!(!TokenType::Root.is_oidc_mint_type());
    }
}
