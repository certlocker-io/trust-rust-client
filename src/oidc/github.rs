// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use crate::error::TrustClientError;
use crate::util::{append_query, form_encode, truncate};

use super::http;

/// GitHub Actions env var naming the OIDC token request URL.
pub const REQUEST_URL_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";

/// GitHub Actions env var naming the bearer token for the OIDC request URL.
pub const REQUEST_TOKEN_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/// Whether ambient GitHub Actions OIDC request env is present.
///
/// Requires workflow `permissions: id-token: write`.
pub fn is_available() -> bool {
    env_present(REQUEST_URL_ENV) && env_present(REQUEST_TOKEN_ENV)
}

/// Fetches an ID token for `audience` (the per-account Trust audience).
pub fn request_id_token(audience: &str) -> Result<String, TrustClientError> {
    let request_url = std::env::var(REQUEST_URL_ENV).unwrap_or_default();
    let request_token = std::env::var(REQUEST_TOKEN_ENV).unwrap_or_default();
    let http = http::client(Duration::from_secs(10), Duration::from_secs(30))?;
    request_with(
        &http,
        audience,
        &request_url,
        &request_token,
        Duration::from_secs(30),
    )
}

pub(crate) fn request_with(
    http: &reqwest::blocking::Client,
    audience: &str,
    request_url: &str,
    request_token: &str,
    timeout: Duration,
) -> Result<String, TrustClientError> {
    if audience.trim().is_empty() {
        return Err(TrustClientError::message("OIDC audience is required"));
    }
    if request_url.trim().is_empty() || request_token.trim().is_empty() {
        return Err(TrustClientError::message(format!(
            "GitHub Actions OIDC env not present ({REQUEST_URL_ENV} / {REQUEST_TOKEN_ENV})"
        )));
    }
    let url = append_query(
        request_url.trim(),
        &format!("audience={}", form_encode(audience.trim())),
    );
    let response = http
        .get(&url)
        .timeout(timeout)
        .header("Authorization", format!("Bearer {}", request_token.trim()))
        .header("Accept", "application/json")
        .send()
        .map_err(|err| {
            TrustClientError::request(format!("GitHub OIDC token request failed: {err}"), err)
        })?;
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    if status != 200 {
        return Err(TrustClientError::message(format!(
            "GitHub OIDC token request failed: HTTP {status} body={}",
            truncate(&body, 200)
        )));
    }
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    match json.get("value").and_then(|value| value.as_str()) {
        Some(jwt) if !jwt.trim().is_empty() => Ok(jwt.to_owned()),
        _ => Err(TrustClientError::message(
            "GitHub OIDC response missing value",
        )),
    }
}

fn env_present(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
}
