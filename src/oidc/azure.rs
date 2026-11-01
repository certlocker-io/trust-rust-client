// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::OnceLock;
use std::time::Duration;

use crate::error::TrustClientError;
use crate::util::{append_query, form_encode, truncate};

use super::http;

/// Default Azure Instance Metadata Service endpoint.
pub const DEFAULT_IMDS_BASE: &str = "http://169.254.169.254";

/// App Service / Functions / Arc identity endpoint.
pub const IDENTITY_ENDPOINT_ENV: &str = "IDENTITY_ENDPOINT";

/// Header secret paired with [`IDENTITY_ENDPOINT_ENV`].
pub const IDENTITY_HEADER_ENV: &str = "IDENTITY_HEADER";

/// Optional client id when several user-assigned identities are present.
pub const AZURE_CLIENT_ID_ENV: &str = "AZURE_CLIENT_ID";

const IMDS_TOKEN_PATH: &str = "/metadata/identity/oauth2/token";
const IMDS_API_VERSION: &str = "2018-02-01";
const APP_SERVICE_API_VERSION: &str = "2019-08-01";

/// Whether this process appears to have Azure managed-identity ambient credentials.
///
/// True when `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` are set, or when IMDS
/// answers a short probe. The probe result is cached for the process lifetime.
pub fn is_available() -> bool {
    if env_present(IDENTITY_ENDPOINT_ENV) && env_present(IDENTITY_HEADER_ENV) {
        return true;
    }
    *cache().get_or_init(probe_imds)
}

/// Fetches an Entra access token whose `resource` is the Trust audience.
pub fn request_id_token(audience: &str) -> Result<String, TrustClientError> {
    let http = http::client(Duration::from_secs(2), Duration::from_secs(10))?;
    request_with(&http, audience, Duration::from_secs(10))
}

pub(crate) fn request_with(
    http: &reqwest::blocking::Client,
    audience: &str,
    timeout: Duration,
) -> Result<String, TrustClientError> {
    if audience.trim().is_empty() {
        return Err(TrustClientError::message("OIDC audience is required"));
    }
    let endpoint = std::env::var(IDENTITY_ENDPOINT_ENV).unwrap_or_default();
    let header = std::env::var(IDENTITY_HEADER_ENV).unwrap_or_default();
    if !endpoint.trim().is_empty() && !header.trim().is_empty() {
        return request_from_app_service(
            http,
            audience.trim(),
            endpoint.trim(),
            header.trim(),
            timeout,
        );
    }
    request_from_imds(http, audience.trim(), timeout)
}

fn request_from_app_service(
    http: &reqwest::blocking::Client,
    audience: &str,
    endpoint: &str,
    identity_header: &str,
    timeout: Duration,
) -> Result<String, TrustClientError> {
    let url = append_query(
        endpoint,
        &format!(
            "api-version={APP_SERVICE_API_VERSION}&resource={}{}",
            form_encode(audience),
            client_id_query()
        ),
    );
    let response = http
        .get(url)
        .timeout(timeout)
        .header("X-IDENTITY-HEADER", identity_header)
        .send()
        .map_err(|err| {
            TrustClientError::request(
                format!("Azure App Service identity token request failed: {err}"),
                err,
            )
        })?;
    extract_access_token(response, "Azure App Service identity")
}

fn request_from_imds(
    http: &reqwest::blocking::Client,
    audience: &str,
    timeout: Duration,
) -> Result<String, TrustClientError> {
    let url = format!(
        "{DEFAULT_IMDS_BASE}{IMDS_TOKEN_PATH}?api-version={IMDS_API_VERSION}&resource={}{}",
        form_encode(audience),
        client_id_query()
    );
    let response = http
        .get(url)
        .timeout(timeout)
        .header("Metadata", "true")
        .send()
        .map_err(|err| {
            TrustClientError::request(
                format!("Azure IMDS identity token request failed: {err}"),
                err,
            )
        })?;
    extract_access_token(response, "Azure IMDS identity")
}

fn extract_access_token(
    response: reqwest::blocking::Response,
    label: &str,
) -> Result<String, TrustClientError> {
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    if status != 200 {
        return Err(TrustClientError::message(format!(
            "{label} token request failed: HTTP {status} body={}",
            truncate(&body, 200)
        )));
    }
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    match json.get("access_token").and_then(|value| value.as_str()) {
        Some(jwt) if !jwt.trim().is_empty() => Ok(jwt.trim().to_owned()),
        _ if body.trim().is_empty() => Err(TrustClientError::message(format!(
            "{label} token response empty"
        ))),
        _ => Err(TrustClientError::message(format!(
            "{label} response missing access_token"
        ))),
    }
}

fn probe_imds() -> bool {
    let Ok(http) = http::probe_client() else {
        return false;
    };
    let url = format!("{DEFAULT_IMDS_BASE}/metadata/instance?api-version={IMDS_API_VERSION}");
    http.get(url)
        .header("Metadata", "true")
        .send()
        .map(|response| response.status().as_u16() == 200)
        .unwrap_or(false)
}

fn client_id_query() -> String {
    match std::env::var(AZURE_CLIENT_ID_ENV) {
        Ok(client_id) if !client_id.trim().is_empty() => {
            format!("&client_id={}", form_encode(client_id.trim()))
        }
        _ => String::new(),
    }
}

fn env_present(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
}

fn cache() -> &'static OnceLock<bool> {
    static CACHE: OnceLock<bool> = OnceLock::new();
    &CACHE
}
