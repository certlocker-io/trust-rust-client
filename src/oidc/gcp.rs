// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::OnceLock;
use std::time::Duration;

use crate::error::TrustClientError;
use crate::util::{form_encode, truncate};

use super::http;

/// Default metadata host used on GCE, GKE, and Cloud Run.
pub const DEFAULT_METADATA_HOST: &str = "metadata.google.internal";

/// Env override for the metadata host (Google client libraries convention).
pub const METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";

/// Cloud Run service name. When set, metadata identity tokens are assumed available.
pub const CLOUD_RUN_SERVICE_ENV: &str = "K_SERVICE";

const IDENTITY_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/identity";

/// Whether this process appears to be on GCP with a reachable metadata identity endpoint.
///
/// Cloud Run (`K_SERVICE`) or `GCE_METADATA_HOST` is a fast positive signal.
/// Otherwise a short metadata probe is cached for the process lifetime.
pub fn is_available() -> bool {
    if env_present(CLOUD_RUN_SERVICE_ENV) || env_present(METADATA_HOST_ENV) {
        return true;
    }
    *cache().get_or_init(probe_metadata)
}

/// Fetches a Google identity token for `audience`.
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
    let url = format!(
        "{}{IDENTITY_PATH}?audience={}&format=full",
        metadata_base(),
        form_encode(audience.trim())
    );
    let response = http
        .get(url)
        .timeout(timeout)
        .header("Metadata-Flavor", "Google")
        .send()
        .map_err(|err| {
            TrustClientError::request(format!("GCP identity token request failed: {err}"), err)
        })?;
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    if status != 200 {
        return Err(TrustClientError::message(format!(
            "GCP identity token request failed: HTTP {status} body={}",
            truncate(&body, 200)
        )));
    }
    if body.trim().is_empty() {
        return Err(TrustClientError::message(
            "GCP identity token response empty",
        ));
    }
    Ok(body.trim().to_owned())
}

fn probe_metadata() -> bool {
    let Ok(http) = http::probe_client() else {
        return false;
    };
    let url = format!("{}/computeMetadata/v1/", metadata_base());
    http.get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .map(|response| response.status().as_u16() == 200)
        .unwrap_or(false)
}

pub(crate) fn metadata_base() -> String {
    let host = std::env::var(METADATA_HOST_ENV).unwrap_or_default();
    let host = if host.trim().is_empty() {
        DEFAULT_METADATA_HOST.to_owned()
    } else {
        host.trim().to_owned()
    };
    if host.starts_with("http://") || host.starts_with("https://") {
        host.trim_end_matches('/').to_owned()
    } else {
        format!("http://{host}")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_base_defaults_when_env_is_unset() {
        if std::env::var(METADATA_HOST_ENV)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return;
        }
        assert_eq!(metadata_base(), format!("http://{DEFAULT_METADATA_HOST}"));
    }
}
