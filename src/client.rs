// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::auth::AuthCodePrompt;
use crate::error::{TrustClientError, TrustError};
use crate::util::encode_segment;

/// Header for step-up 2FA / access code on user-bound tokens.
pub const ACCESS_CODE_HEADER: &str = "x-access-code";
/// Gateway challenge type when step-up input is required (`ACCESS_CODE` / `OTP` / `EMAIL`).
pub const ACCESS_RESPONSE_HEADER: &str = "x-access-response";
/// HTTP status Gateway uses for step-up. The response body is the prompt text.
pub const ACCESS_REQUIRED_STATUS: u16 = 401;

const APPLICATION_JSON: &str = "application/json";
const TEXT_PLAIN: &str = "text/plain";
const TRUST_BASE: &str = "/rest/api/v1";

/// Client for a Certlocker Trust Gateway.
///
/// `get_*` methods return the asset record as JSON text.
/// `fetch_*` methods return the asset contents.
/// Build one with [`TrustClient::builder`].
///
/// Multi-tenant Gateway paths include the account id:
/// `/rest/api/v1/{resource}/{accountId}/…`.
/// The path account must match the token's account.
///
/// # Example
///
/// ```no_run
/// use trust_client::TrustClient;
///
/// # fn main() -> Result<(), trust_client::TrustClientError> {
/// let client = TrustClient::builder()
///     .url("https://trust.certlocker.io")
///     .account_id("<accountId>")
///     .api_token("<ui-minted-token-id>")
///     .build()?;
///
/// let record = client.get_secret(Some("mvusgvkv5"))?;
/// let contents = client.fetch_secret(Some("mvusgvkv5"))?;
/// # let _ = (record, contents);
/// # Ok(())
/// # }
/// ```
pub struct TrustClient {
    inner: Arc<TrustClientInner>,
}

struct TrustClientInner {
    url: String,
    api_token: String,
    account_id: String,
    http: reqwest::blocking::Client,
    auth_code_prompt: Option<AuthCodePrompt>,
    access_code: Mutex<Option<String>>,
}

impl TrustClient {
    /// Returns a new builder. The default connect timeout is 10 seconds,
    /// and redirects are not followed.
    pub fn builder() -> crate::builder::TrustClientBuilder {
        crate::builder::TrustClientBuilder::new()
    }

    pub(crate) fn from_parts(
        url: String,
        api_token: String,
        account_id: String,
        http: reqwest::blocking::Client,
        auth_code_prompt: Option<AuthCodePrompt>,
    ) -> Self {
        Self {
            inner: Arc::new(TrustClientInner {
                url,
                api_token,
                account_id,
                http,
                auth_code_prompt,
                access_code: Mutex::new(None),
            }),
        }
    }

    /// Trust base URL, without a trailing slash.
    pub fn url(&self) -> &str {
        &self.inner.url
    }

    /// API token sent as the `x-api-token` header.
    ///
    /// This is a credential. Do not log it.
    pub fn api_token(&self) -> &str {
        &self.inner.api_token
    }

    /// Account id used in Gateway paths.
    pub fn account_id(&self) -> &str {
        &self.inner.account_id
    }

    /// HTTP client used for asset requests.
    pub fn http_client(&self) -> &reqwest::blocking::Client {
        &self.inner.http
    }

    /// Sets a 2FA / access code for subsequent requests (user-bound tokens).
    ///
    /// The value is sent as [`ACCESS_CODE_HEADER`]. A blank value clears it.
    pub fn set_access_code(&self, access_code: impl Into<String>) {
        let value = access_code.into();
        let mut slot = self
            .inner
            .access_code
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *slot = if value.trim().is_empty() {
            None
        } else {
            Some(value)
        };
    }

    /// Prompts for a 2FA / access code when a prompt was configured on the builder.
    ///
    /// `reason` is usually the Gateway response body.
    pub fn prompt_for_access_code(&self, reason: &str) -> Result<(), TrustClientError> {
        let prompt = self.inner.auth_code_prompt.as_ref().ok_or_else(|| {
            TrustClientError::message(
                "No AuthCodePrompt configured; call TrustClientBuilder.authCodePrompt(...)",
            )
        })?;
        let code = prompt(reason).map_err(|err| {
            TrustClientError::message(format!("Failed to read authentication code: {err}"))
        })?;
        self.set_access_code(code);
        Ok(())
    }

    /// Secret record JSON for `secret_id`.
    ///
    /// Pass [`None`] when the token is assigned to one secret.
    /// Use [`Self::fetch_secret`] for the secret contents.
    pub fn get_secret(&self, secret_id: Option<&str>) -> Result<String, TrustClientError> {
        self.process(self.secret_path("get"), secret_id, APPLICATION_JSON)
    }

    /// Secret contents.
    ///
    /// Pass [`None`] when the token is assigned to one secret.
    pub fn fetch_secret(&self, secret_id: Option<&str>) -> Result<String, TrustClientError> {
        self.process(self.secret_path("fetch"), secret_id, TEXT_PLAIN)
    }

    /// Certificate record JSON for `certificate_id`.
    ///
    /// Pass [`None`] when the token is assigned to one certificate.
    pub fn get_certificate(
        &self,
        certificate_id: Option<&str>,
    ) -> Result<String, TrustClientError> {
        self.process(self.cert_path("get"), certificate_id, APPLICATION_JSON)
    }

    /// Certificate PEM contents.
    ///
    /// Pass [`None`] when the token is assigned to one certificate.
    pub fn fetch_certificate(
        &self,
        certificate_id: Option<&str>,
    ) -> Result<String, TrustClientError> {
        self.process(self.cert_path("fetch"), certificate_id, TEXT_PLAIN)
    }

    /// Certificate bundle (certificate and private key PEM).
    ///
    /// Pass [`None`] when the token is assigned to one certificate.
    pub fn fetch_certificate_bundle(
        &self,
        certificate_id: Option<&str>,
    ) -> Result<String, TrustClientError> {
        self.process(self.cert_path("fetch-bundle"), certificate_id, TEXT_PLAIN)
    }

    /// Token record JSON for `id`.
    pub fn get_token(&self, id: &str) -> Result<String, TrustClientError> {
        self.process(self.token_path("get"), Some(id), APPLICATION_JSON)
    }

    fn cert_path(&self, action: &str) -> String {
        action_path("cert", &self.inner.account_id, action)
    }

    fn secret_path(&self, action: &str) -> String {
        action_path("secret", &self.inner.account_id, action)
    }

    fn token_path(&self, action: &str) -> String {
        action_path("token", &self.inner.account_id, action)
    }

    fn process(
        &self,
        path: String,
        id: Option<&str>,
        media_type: &str,
    ) -> Result<String, TrustClientError> {
        self.process_once(&path, id, media_type, true)
    }

    fn process_once(
        &self,
        path: &str,
        id: Option<&str>,
        media_type: &str,
        allow_prompt_retry: bool,
    ) -> Result<String, TrustClientError> {
        let response = self.send(path, id, media_type)?;
        let status = response.status().as_u16();
        let body_type = header_value(response.headers(), "x-body-type");
        let access_response = header_value(response.headers(), ACCESS_RESPONSE_HEADER);
        let body = response
            .text()
            .map_err(|err| TrustClientError::request("Failed to read Trust response", err))?;
        if status == 200 {
            return Ok(body);
        }

        let step_up = status == ACCESS_REQUIRED_STATUS || access_response.is_some();
        if allow_prompt_retry && self.inner.auth_code_prompt.is_some() && step_up {
            let prompt = if body.trim().is_empty() {
                "Please enter authentication code"
            } else {
                body.trim()
            };
            self.prompt_for_access_code(prompt)?;
            return self.process_once(path, id, media_type, false);
        }

        Err(TrustClientError::trust(parse_error(
            status, body_type, &body,
        )))
    }

    fn send(
        &self,
        path: &str,
        id: Option<&str>,
        media_type: &str,
    ) -> Result<reqwest::blocking::Response, TrustClientError> {
        let url = request_url(&self.inner.url, path, id);
        let mut request = self
            .inner
            .http
            .get(&url)
            .header("x-api-token", &self.inner.api_token)
            .header("content-type", media_type)
            .header("accept", media_type);
        if let Some(code) = self.current_access_code() {
            request = request.header(ACCESS_CODE_HEADER, code);
        }
        request
            .send()
            .map_err(|err| TrustClientError::request(format!("Trust request failed: {err}"), err))
    }

    fn current_access_code(&self) -> Option<String> {
        let slot = self
            .inner
            .access_code
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        slot.clone().filter(|value| !value.trim().is_empty())
    }
}

impl Clone for TrustClient {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl std::fmt::Debug for TrustClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustClient")
            .field("url", &self.inner.url)
            .field("account_id", &self.inner.account_id)
            .field("api_token", &"<redacted>")
            .finish()
    }
}

fn action_path(resource: &str, account_id: &str, action: &str) -> String {
    format!(
        "{TRUST_BASE}/{resource}/{}/{action}",
        encode_segment(account_id)
    )
}

fn request_url(base: &str, path: &str, id: Option<&str>) -> String {
    let mut url = format!("{base}{path}");
    if let Some(id) = id {
        url.push('/');
        url.push_str(&encode_segment(id));
    }
    url
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn parse_error(status: u16, body_type: Option<String>, body: &str) -> TrustError {
    let mut error = None;
    if let Some(class_name) = body_type.filter(|value| !value.trim().is_empty()) {
        if class_name == "certlocker.gateway.api.model.ErrorDTO" {
            if let Ok(dto) = serde_json::from_str::<ErrorDto>(body) {
                if let Some(message) = dto.message() {
                    error = Some(message);
                }
            }
        } else if class_name == "certlocker.core.exceptions.CLErrorException" {
            if let Ok(dto) = serde_json::from_str::<ClErrorException>(body) {
                if let Some(message) = dto.error.and_then(|err| err.message) {
                    if !message.trim().is_empty() {
                        error = Some(message);
                    }
                }
            }
        }
    }

    let message = error.unwrap_or_else(|| {
        if body.trim().is_empty() {
            "Unknown error".to_owned()
        } else {
            body.to_owned()
        }
    });
    TrustError::new(message, status)
}

#[derive(Debug, Deserialize)]
struct ErrorDto {
    #[serde(default, alias = "errorMessage")]
    error_message: Option<String>,
}

impl ErrorDto {
    fn message(self) -> Option<String> {
        self.error_message.filter(|value| !value.trim().is_empty())
    }
}

#[derive(Debug, Deserialize)]
struct ClErrorException {
    error: Option<ClError>,
}

#[derive(Debug, Deserialize)]
struct ClError {
    message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_error_shapes() {
        let dto = parse_error(
            404,
            Some("certlocker.gateway.api.model.ErrorDTO".to_owned()),
            r#"{"error_message":"missing secret"}"#,
        );
        assert_eq!(dto.error_message, "missing secret");
        assert_eq!(dto.http_status, 404);

        let camel = parse_error(
            401,
            Some("certlocker.gateway.api.model.ErrorDTO".to_owned()),
            r#"{"errorMessage":"Invalid token"}"#,
        );
        assert_eq!(camel.error_message, "Invalid token");

        let cl = parse_error(
            400,
            Some("certlocker.core.exceptions.CLErrorException".to_owned()),
            r#"{"error":{"message":"denied"}}"#,
        );
        assert_eq!(cl.error_message, "denied");

        let plain = parse_error(500, None, "boom");
        assert_eq!(plain.error_message, "boom");

        let unknown = parse_error(500, None, "  ");
        assert_eq!(unknown.error_message, "Unknown error");
    }
}
