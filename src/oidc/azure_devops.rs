// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use crate::error::TrustClientError;
use crate::util::{append_query, form_encode, truncate};

use super::http;

/// Azure Pipelines variable `System.OidcRequestUri`.
pub const OIDC_REQUEST_URI_ENV: &str = "SYSTEM_OIDCREQUESTURI";

/// Bearer for the OIDC request.
///
/// Map `SYSTEM_ACCESSTOKEN: $(System.AccessToken)` into the job.
pub const ACCESS_TOKEN_ENV: &str = "SYSTEM_ACCESSTOKEN";

/// Optional service connection id exposed by AzureCLI and AzurePowerShell tasks.
pub const SERVICE_CONNECTION_ID_ENV: &str = "AZURESUBSCRIPTION_SERVICE_CONNECTION_ID";

/// Alternate explicit service-connection id for tasks that are not AzureRM.
pub const SERVICE_CONNECTION_ID_ALT_ENV: &str = "SYSTEM_OIDC_SERVICE_CONNECTION_ID";

const API_VERSION: &str = "7.1";

/// Whether ambient Azure DevOps OIDC request env is present.
pub fn is_available() -> bool {
    env_present(OIDC_REQUEST_URI_ENV) && env_present(ACCESS_TOKEN_ENV)
}

/// Fetches an Azure DevOps OIDC id token.
///
/// The token audience is ADO's fixed `api://AzureADTokenExchange`. Trust matches
/// `AZURE_DEVOPS` principals by issuer and `sub`, not by the Trust audience URL.
pub fn request_id_token() -> Result<String, TrustClientError> {
    let http = http::client(Duration::from_secs(10), Duration::from_secs(30))?;
    request_with(&http, Duration::from_secs(30))
}

pub(crate) fn request_with(
    http: &reqwest::blocking::Client,
    timeout: Duration,
) -> Result<String, TrustClientError> {
    let request_uri = std::env::var(OIDC_REQUEST_URI_ENV).unwrap_or_default();
    let access_token = std::env::var(ACCESS_TOKEN_ENV).unwrap_or_default();
    request_at(http, request_uri.trim(), access_token.trim(), timeout)
}

pub(crate) fn request_at(
    http: &reqwest::blocking::Client,
    request_uri: &str,
    access_token: &str,
    timeout: Duration,
) -> Result<String, TrustClientError> {
    if request_uri.is_empty() || access_token.is_empty() {
        return Err(TrustClientError::message(format!(
            "Azure DevOps OIDC env not present ({OIDC_REQUEST_URI_ENV} / {ACCESS_TOKEN_ENV})"
        )));
    }
    let service_connection = first_non_blank(&[
        std::env::var(SERVICE_CONNECTION_ID_ENV).ok(),
        std::env::var(SERVICE_CONNECTION_ID_ALT_ENV).ok(),
    ]);
    let mut query = format!("api-version={}", form_encode(API_VERSION));
    if let Some(service_connection) = service_connection {
        query.push_str("&serviceConnectionId=");
        query.push_str(&form_encode(service_connection.trim()));
    }
    let url = append_query(request_uri, &query);
    let response = http
        .post(url)
        .timeout(timeout)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body("")
        .send()
        .map_err(|err| {
            TrustClientError::request(
                format!("Azure DevOps OIDC token request failed: {err}"),
                err,
            )
        })?;
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(TrustClientError::message(format!(
            "Azure DevOps OIDC token request failed: HTTP {status} body={}",
            truncate(&body, 200)
        )));
    }
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    if json.is_null() {
        return Err(TrustClientError::message(
            "Azure DevOps OIDC response empty",
        ));
    }
    let token = text(&json, "oidcToken").or_else(|| text(&json, "token"));
    match token {
        Some(token) if !token.trim().is_empty() => Ok(token),
        _ => Err(TrustClientError::message(
            "Azure DevOps OIDC response missing oidcToken",
        )),
    }
}

fn text(json: &serde_json::Value, field: &str) -> Option<String> {
    json.get(field)
        .and_then(|value| value.as_str())
        .map(str::to_owned)
}

fn first_non_blank(values: &[Option<String>]) -> Option<String> {
    values.iter().find_map(|value| {
        value
            .as_ref()
            .filter(|text| !text.trim().is_empty())
            .cloned()
    })
}

fn env_present(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
}
