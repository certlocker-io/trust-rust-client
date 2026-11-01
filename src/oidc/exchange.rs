// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;

use crate::error::TrustClientError;
use crate::model::TokenType;
use crate::util::{join_base, truncate};

use super::http;
use super::{azure, azure_devops, device, gcp, github};

const PATH: &str = "/rest/api/v1/oidc/exchange";

/// Result of `POST /rest/api/v1/oidc/exchange`.
///
/// [`Self::token_id`] is the value to send as `x-api-token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcExchangeResult {
    /// Minted Trust API token id.
    pub token_id: String,
    /// Token expiry, or `None` when the response omitted it or it could not be parsed.
    pub expires_at: Option<DateTime<Utc>>,
    /// Token type string from Gateway (`SECRET`, `CERTIFICATE`, or `MCP`).
    pub token_type: Option<String>,
    /// Tenant account id for Gateway paths.
    pub account_id: Option<String>,
    /// OIDC principal id that minted the token.
    pub principal_id: Option<String>,
}

impl OidcExchangeResult {
    /// Parsed mint type, when Gateway returned a known `TokenType` name.
    pub fn token_type_enum(&self) -> Option<TokenType> {
        match self.token_type.as_deref() {
            Some("CERTIFICATE") => Some(TokenType::Certificate),
            Some("HOST") => Some(TokenType::Host),
            Some("BASTION") => Some(TokenType::Bastion),
            Some("SECRET") => Some(TokenType::Secret),
            Some("ROOT") => Some(TokenType::Root),
            Some("MCP") => Some(TokenType::Mcp),
            Some("WILDCARD") => Some(TokenType::Wildcard),
            _ => None,
        }
    }
}

/// Exchanges an OIDC id token for a short-lived Trust token.
///
/// Pass `token_type: None` to use the matched principal's default
/// (typically [`TokenType::Secret`]). `Some` must be `SECRET`, `CERTIFICATE`,
/// or `MCP`.
pub fn exchange(
    trust_url: &str,
    id_token: &str,
    token_type: Option<TokenType>,
) -> Result<OidcExchangeResult, TrustClientError> {
    let http = http::client(Duration::from_secs(10), Duration::from_secs(30))?;
    exchange_with(&http, trust_url, id_token, token_type)
}

pub(crate) fn exchange_with(
    http: &reqwest::blocking::Client,
    trust_url: &str,
    id_token: &str,
    token_type: Option<TokenType>,
) -> Result<OidcExchangeResult, TrustClientError> {
    if trust_url.trim().is_empty() {
        return Err(TrustClientError::message("trustUrl is required"));
    }
    if id_token.trim().is_empty() {
        return Err(TrustClientError::message("idToken is required"));
    }
    if let Some(token_type) = token_type {
        if !token_type.is_oidc_mint_type() {
            return Err(TrustClientError::message(format!(
                "OIDC exchange tokenType must be SECRET, CERTIFICATE, or MCP (got {token_type})"
            )));
        }
    }

    let body = request_body(id_token, token_type);
    let response = http
        .post(join_base(trust_url.trim(), PATH))
        .timeout(Duration::from_secs(30))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(body)
        .send()
        .map_err(|err| TrustClientError::request(format!("OIDC exchange failed: {err}"), err))?;
    let status = response.status().as_u16();
    let text = response.text().unwrap_or_default();
    if status != 200 {
        return Err(TrustClientError::message(format!(
            "OIDC exchange failed: HTTP {status} body={}",
            truncate(&text, 300)
        )));
    }
    parse_success(&text)
}

/// GitHub Actions ambient OIDC, then Gateway exchange.
pub fn from_github_actions(
    trust_url: &str,
    audience: &str,
    token_type: Option<TokenType>,
) -> Result<OidcExchangeResult, TrustClientError> {
    let http = http::client(Duration::from_secs(10), Duration::from_secs(30))?;
    let request_url = std::env::var(github::REQUEST_URL_ENV).unwrap_or_default();
    let request_token = std::env::var(github::REQUEST_TOKEN_ENV).unwrap_or_default();
    let id_token = github::request_with(
        &http,
        audience,
        &request_url,
        &request_token,
        Duration::from_secs(30),
    )?;
    exchange_with(&http, trust_url, &id_token, token_type)
}

/// GCP metadata identity token, then Gateway exchange.
pub fn from_gcp(
    trust_url: &str,
    audience: &str,
    token_type: Option<TokenType>,
) -> Result<OidcExchangeResult, TrustClientError> {
    let http = http::client(Duration::from_secs(10), Duration::from_secs(30))?;
    let id_token = gcp::request_with(&http, audience, Duration::from_secs(10))?;
    exchange_with(&http, trust_url, &id_token, token_type)
}

/// Azure managed-identity token, then Gateway exchange.
pub fn from_azure(
    trust_url: &str,
    audience: &str,
    token_type: Option<TokenType>,
) -> Result<OidcExchangeResult, TrustClientError> {
    let http = http::client(Duration::from_secs(10), Duration::from_secs(30))?;
    let id_token = azure::request_with(&http, audience, Duration::from_secs(10))?;
    exchange_with(&http, trust_url, &id_token, token_type)
}

/// Azure DevOps Pipelines ambient OIDC, then Gateway exchange.
///
/// No Trust audience is required. ADO tokens use `api://AzureADTokenExchange`.
pub fn from_azure_devops(
    trust_url: &str,
    token_type: Option<TokenType>,
) -> Result<OidcExchangeResult, TrustClientError> {
    let http = http::client(Duration::from_secs(10), Duration::from_secs(30))?;
    let id_token = azure_devops::request_with(&http, Duration::from_secs(30))?;
    exchange_with(&http, trust_url, &id_token, token_type)
}

/// Mints a device JWT from `config` and exchanges it.
pub fn from_device(
    trust_url: &str,
    config: &device::DeviceOidcConfig,
    token_type: Option<TokenType>,
) -> Result<OidcExchangeResult, TrustClientError> {
    let id_token = device::mint_from_config(config)?;
    exchange(trust_url, &id_token, token_type)
}

pub(crate) fn parse_success(body: &str) -> Result<OidcExchangeResult, TrustClientError> {
    if body.trim().is_empty() {
        return Err(TrustClientError::message(
            "OIDC exchange returned empty body",
        ));
    }
    let root: ExchangeBody = serde_json::from_str(body).map_err(|err| {
        TrustClientError::message(format!("OIDC exchange returned invalid JSON: {err}"))
    })?;
    if let Some(error) = root.error_message.filter(|value| !value.trim().is_empty()) {
        return Err(TrustClientError::message(format!(
            "OIDC exchange denied: {error}"
        )));
    }
    let token_id = root
        .token_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| TrustClientError::message("OIDC exchange response missing tokenId"))?;
    Ok(OidcExchangeResult {
        token_id,
        expires_at: root.expires_at.as_deref().and_then(parse_expires),
        token_type: root.token_type.filter(|value| !value.trim().is_empty()),
        account_id: root.account_id.filter(|value| !value.trim().is_empty()),
        principal_id: root.principal_id.filter(|value| !value.trim().is_empty()),
    })
}

fn request_body(id_token: &str, token_type: Option<TokenType>) -> String {
    let mut body = serde_json::Map::new();
    body.insert(
        "idToken".to_owned(),
        serde_json::Value::String(id_token.to_owned()),
    );
    if let Some(token_type) = token_type {
        body.insert(
            "tokenType".to_owned(),
            serde_json::Value::String(token_type.as_str().to_owned()),
        );
    }
    serde_json::Value::Object(body).to_string()
}

fn parse_expires(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&Utc));
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Some(naive.and_utc());
        }
    }
    None
}

#[derive(Debug, Deserialize)]
struct ExchangeBody {
    #[serde(default, rename = "errorMessage", alias = "error_message")]
    error_message: Option<String>,
    #[serde(default, rename = "tokenId", alias = "token_id")]
    token_id: Option<String>,
    #[serde(default, rename = "expiresAt", alias = "expires_at")]
    expires_at: Option<String>,
    #[serde(default, rename = "tokenType", alias = "token_type")]
    token_type: Option<String>,
    #[serde(default, rename = "accountId", alias = "account_id")]
    account_id: Option<String>,
    #[serde(default, rename = "principalId", alias = "principal_id")]
    principal_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_camel_case_exchange_response() {
        let result = parse_success(
            r#"{"tokenId":"tok-1","expiresAt":"2026-05-01T12:00:00","tokenType":"SECRET","accountId":"acct","principalId":"prn"}"#,
        )
        .unwrap();
        assert_eq!(result.token_id, "tok-1");
        assert_eq!(result.account_id.as_deref(), Some("acct"));
        assert_eq!(result.token_type_enum(), Some(TokenType::Secret));
        assert!(result.expires_at.is_some());
    }

    #[test]
    fn rejects_an_error_message_and_a_missing_token() {
        let denied = parse_success(r#"{"errorMessage":"no principal"}"#).unwrap_err();
        assert!(denied.to_string().contains("no principal"));
        let missing = parse_success(r#"{"accountId":"acct"}"#).unwrap_err();
        assert!(missing.to_string().contains("tokenId"));
    }

    #[test]
    fn request_body_includes_the_mint_type_only_when_asked() {
        assert_eq!(request_body("jwt", None), r#"{"idToken":"jwt"}"#);
        assert_eq!(
            request_body("jwt", Some(TokenType::Mcp)),
            r#"{"idToken":"jwt","tokenType":"MCP"}"#
        );
        let err = exchange("https://trust.example.com", "jwt", Some(TokenType::Root)).unwrap_err();
        assert!(err.to_string().contains("SECRET, CERTIFICATE, or MCP"));
    }
}
