// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use reqwest::redirect::Policy;

use crate::auth::{console_auth_code_prompt, AuthCodePrompt};
use crate::client::TrustClient;
use crate::error::TrustClientError;
use crate::oidc::{self, DeviceOidcConfig, OidcExchangeResult};
use crate::util::normalize_base_url;

/// Connect timeout used when the caller does not set one and does not supply a finished HTTP client.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const USER_AGENT: &str = concat!("trust-client/", env!("CARGO_PKG_VERSION"));

/// How the client follows HTTP redirects.
///
/// The JDK `HttpClient` does not follow redirects unless asked. This client matches that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Redirects {
    /// Do not follow redirects.
    #[default]
    Never,
    /// Follow up to 10 redirects.
    ///
    /// This is the practical equivalent of `HttpClient.Redirect.NORMAL` for Trust,
    /// which stays on HTTPS.
    Normal,
    /// Follow up to 20 redirects.
    Always,
}

/// Preferred HTTP version for asset calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpVersion {
    /// Negotiate HTTP/2 with ALPN and fall back to HTTP/1.1. This is the default.
    #[default]
    Negotiate,
    /// Force HTTP/1.1.
    Http1,
}

/// Proxy selection for asset calls.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// Honor `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`.
    #[default]
    Environment,
    /// Do not use a proxy.
    Direct,
    /// Send traffic through this proxy URL (`http://host:port` or `https://host:port`).
    All(String),
}

/// Builds a [`TrustClient`] for a Trust URL and an API token.
///
/// HTTP settings cover the same cases as the Java client's `HttpClient.Builder`
/// that Trust callers actually use: connect timeout, redirects, HTTP version,
/// proxy, local address, and a pre-built client. When no HTTP settings are
/// supplied, the client uses a connect timeout of [`DEFAULT_CONNECT_TIMEOUT`]
/// and does not follow redirects.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
/// use trust_client::{HttpVersion, Redirects, TrustClient};
///
/// # fn main() -> Result<(), trust_client::TrustClientError> {
/// let client = TrustClient::builder()
///     .url("https://trust.example.com")
///     .account_id("acct-1")
///     .api_token("secret-key")
///     .connect_timeout(Duration::from_secs(10))
///     .follow_redirects(Redirects::Normal)
///     .http_version(HttpVersion::Http1)
///     .build()?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct TrustClientBuilder {
    url: Option<String>,
    api_token: Option<String>,
    account_id: Option<String>,
    legacy_api: bool,
    oidc_audience: Option<String>,
    prefer_ambient_oidc: bool,
    auth_code_prompt: Option<AuthCodePrompt>,
    connect_timeout: Option<Duration>,
    timeout: Option<Duration>,
    redirects: Redirects,
    http_version: HttpVersion,
    proxy: ProxyMode,
    local_address: Option<IpAddr>,
    danger_accept_invalid_certs: bool,
    http_client: Option<reqwest::blocking::Client>,
}

impl TrustClientBuilder {
    /// Creates a builder with the default connect timeout.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Trust base URL.
    ///
    /// Absolute `http` or `https` URL. Surrounding whitespace is ignored.
    /// A trailing slash is removed when the client is built.
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Sets the API token sent as the `x-api-token` header.
    pub fn api_token(mut self, api_token: impl Into<String>) -> Self {
        self.api_token = Some(api_token.into());
        self
    }

    /// Tenant account id for Gateway paths (`/v1/{resource}/{accountId}/…`).
    ///
    /// Must match the API token's account. When ambient OIDC is used and this
    /// is omitted, the account id is taken from the exchange response.
    pub fn account_id(mut self, account_id: impl Into<String>) -> Self {
        self.account_id = Some(account_id.into());
        self
    }

    /// Select pre-account-ID Gateway routes explicitly. Never retries in another mode.
    pub fn legacy_api(mut self, legacy: bool) -> Self {
        self.legacy_api = legacy;
        self
    }

    /// Per-account OIDC audience, for example `https://trust.certlocker.io/oidc/<accountId>`.
    ///
    /// Required for GitHub Actions, GCP, and Azure ambient exchange.
    /// Azure DevOps uses its own fixed audience and ignores this value.
    pub fn oidc_audience(mut self, audience: impl Into<String>) -> Self {
        self.oidc_audience = Some(audience.into());
        self
    }

    /// When true, [`Self::build`] exchanges ambient GitHub Actions, GCP, Azure,
    /// or Azure DevOps OIDC before using a break-glass API token.
    ///
    /// If exchange fails and an API token was also set, that token is kept.
    pub fn prefer_ambient_oidc(mut self, prefer: bool) -> Self {
        self.prefer_ambient_oidc = prefer;
        self
    }

    /// Prompt used when Gateway requires 2FA / access code on a user-bound token.
    ///
    /// [`console_auth_code_prompt`] reads from stdin. Any `Fn(&str) -> Result<String, TrustClientError>`
    /// works, including a closure.
    pub fn auth_code_prompt<F>(mut self, prompt: F) -> Self
    where
        F: Fn(&str) -> Result<String, TrustClientError> + Send + Sync + 'static,
    {
        self.auth_code_prompt = Some(Box::new(prompt));
        self
    }

    /// Reads the access code from stdin. Same as `.auth_code_prompt(console_auth_code_prompt)`.
    pub fn console_auth_code_prompt(self) -> Self {
        self.auth_code_prompt(console_auth_code_prompt)
    }

    /// Uses this HTTP client as-is for asset calls.
    ///
    /// Connect timeout, redirects, proxy, and the other HTTP methods on this
    /// builder are ignored when a finished client is supplied. OIDC exchange
    /// still uses its own short-lived client, matching the Java client.
    pub fn http_client(mut self, http_client: reqwest::blocking::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Sets the HTTP connect timeout.
    ///
    /// When this is not called and no finished client is supplied, the timeout
    /// is [`DEFAULT_CONNECT_TIMEOUT`].
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = Some(connect_timeout);
        self
    }

    /// Sets an overall timeout for each asset request, including the body.
    ///
    /// Unset by default, so a slow Gateway is not aborted after connect.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the redirect policy. The default is [`Redirects::Never`].
    pub fn follow_redirects(mut self, follow_redirects: Redirects) -> Self {
        self.redirects = follow_redirects;
        self
    }

    /// Sets the preferred HTTP version. The default negotiates HTTP/2.
    pub fn http_version(mut self, version: HttpVersion) -> Self {
        self.http_version = version;
        self
    }

    /// Sets proxy behaviour. The default follows environment proxy variables.
    pub fn proxy(mut self, proxy: ProxyMode) -> Self {
        self.proxy = proxy;
        self
    }

    /// Binds outbound connections to `local_address`.
    pub fn local_address(mut self, local_address: IpAddr) -> Self {
        self.local_address = Some(local_address);
        self
    }

    /// Accepts invalid TLS certificates.
    ///
    /// Leave this off for Trust. It exists for a local Gateway with a private
    /// certificate. A custom [`reqwest::blocking::Client`] is the right place
    /// for a private CA.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    /// URL plus per-account audience. Resolves a credential via ambient
    /// GitHub, GCP, Azure, or Azure DevOps OIDC exchange.
    ///
    /// `account_id` is taken from the exchange response.
    pub fn from_ambient_oidc(
        trust_url: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<TrustClient, TrustClientError> {
        Self::new()
            .url(trust_url)
            .oidc_audience(audience)
            .prefer_ambient_oidc(true)
            .build()
    }

    /// Exchanges an already-acquired OIDC JWT, then builds a client.
    ///
    /// `account_id` must be present on the exchange response.
    pub fn from_id_token(
        trust_url: impl Into<String>,
        id_token: impl Into<String>,
    ) -> Result<TrustClient, TrustClientError> {
        let trust_url = trust_url.into();
        let id_token = id_token.into();
        if trust_url.trim().is_empty() {
            return Err(TrustClientError::config("trustUrl must not be blank"));
        }
        if id_token.trim().is_empty() {
            return Err(TrustClientError::config("idToken must not be blank"));
        }
        let url = normalize_base_url(&trust_url)?;
        let exchanged = oidc::exchange(&url, &id_token, None)?;
        client_from_exchange(&url, exchanged)
    }

    /// Mints a device Ed25519 / `EdDSA` JWT, exchanges it, and builds a client.
    ///
    /// The exchanged token uses the principal's default mint type.
    pub fn from_device_oidc(
        trust_url: impl Into<String>,
        config: DeviceOidcConfig,
    ) -> Result<TrustClient, TrustClientError> {
        let trust_url = trust_url.into();
        if trust_url.trim().is_empty() {
            return Err(TrustClientError::config("trustUrl must not be blank"));
        }
        let url = normalize_base_url(&trust_url)?;
        let id_token = oidc::mint_device_jwt(&config)?;
        Self::from_id_token(url, id_token)
    }

    /// Device OIDC from a private-key file and the required enrollment fields.
    pub fn from_device_key_file(
        trust_url: impl Into<String>,
        audience: impl Into<String>,
        device_id: impl Into<String>,
        private_key_path: impl Into<std::path::PathBuf>,
        key_id: Option<&str>,
    ) -> Result<TrustClient, TrustClientError> {
        let mut builder = DeviceOidcConfig::builder()
            .audience(audience)
            .device_id(device_id)
            .private_key_path(private_key_path);
        if let Some(key_id) = key_id {
            builder = builder.key_id(key_id);
        }
        Self::from_device_oidc(trust_url, builder.build()?)
    }

    /// Builds the client.
    pub fn build(mut self) -> Result<TrustClient, TrustClientError> {
        let url = match self.url.as_deref() {
            Some(url) => normalize_base_url(url)?,
            None => return Err(TrustClientError::config("url is required")),
        };
        if self
            .api_token
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(TrustClientError::config("apiToken must not be blank"));
        }
        if self
            .account_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(TrustClientError::config("accountId must not be blank"));
        }
        if self
            .oidc_audience
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(TrustClientError::config("oidcAudience must not be blank"));
        }

        let http = match self.http_client.take() {
            Some(client) => client,
            None => build_http_client(&self)?,
        };
        let (api_token, account_id) = resolve_credentials(
            &url,
            self.api_token,
            self.account_id,
            self.oidc_audience.as_deref(),
            self.prefer_ambient_oidc,
            self.legacy_api,
        )?;
        Ok(TrustClient::from_parts(
            url,
            api_token,
            account_id,
            self.legacy_api,
            http,
            self.auth_code_prompt,
        ))
    }
}

fn client_from_exchange(
    url: &str,
    exchanged: OidcExchangeResult,
) -> Result<TrustClient, TrustClientError> {
    let account_id = exchanged
        .account_id
        .filter(|value| !value.trim().is_empty());
    let Some(account_id) = account_id else {
        return Err(TrustClientError::message(
            "OIDC exchange response missing accountId",
        ));
    };
    TrustClient::builder()
        .url(url)
        .api_token(exchanged.token_id)
        .account_id(account_id)
        .build()
}

fn resolve_credentials(
    url: &str,
    api_token: Option<String>,
    account_id: Option<String>,
    oidc_audience: Option<&str>,
    prefer_ambient_oidc: bool,
    legacy_api: bool,
) -> Result<(String, String), TrustClientError> {
    let mut api_token = api_token.filter(|value| !value.trim().is_empty());
    let mut account_id = account_id.filter(|value| !value.trim().is_empty());

    if api_token.is_none() || prefer_ambient_oidc {
        let ambient_gha = oidc::github_actions_available();
        let ambient_gcp = !ambient_gha && oidc::gcp_available();
        let ambient_azure = !ambient_gha && !ambient_gcp && oidc::azure_available();
        let ambient_ado =
            !ambient_gha && !ambient_gcp && !ambient_azure && oidc::azure_devops_available();
        if prefer_ambient_oidc || ambient_gha || ambient_gcp || ambient_azure || ambient_ado {
            match exchange_ambient(
                url,
                oidc_audience,
                ambient_gha,
                ambient_gcp,
                ambient_azure,
                ambient_ado,
                prefer_ambient_oidc,
            ) {
                Ok(exchanged) => {
                    api_token = Some(exchanged.token_id);
                    if account_id.is_none() {
                        account_id = exchanged
                            .account_id
                            .filter(|value| !value.trim().is_empty());
                    }
                }
                Err(err) => {
                    if api_token.is_none() {
                        return Err(TrustClientError::ambient(err));
                    }
                }
            }
        }
    }

    require_credentials(api_token, account_id, legacy_api)
}

fn require_credentials(
    api_token: Option<String>,
    account_id: Option<String>,
    legacy_api: bool,
) -> Result<(String, String), TrustClientError> {
    let api_token = api_token.ok_or_else(|| {
        TrustClientError::config(
            "apiToken is required (or enable ambient OIDC with oidcAudience / preferAmbientOidc)",
        )
    })?;
    let account_id = if legacy_api {
        account_id.unwrap_or_default()
    } else {
        account_id.ok_or_else(|| TrustClientError::config("accountId is required"))?
    };
    Ok((api_token, account_id))
}

fn exchange_ambient(
    url: &str,
    audience: Option<&str>,
    gha: bool,
    gcp: bool,
    azure: bool,
    ado: bool,
    prefer_ambient: bool,
) -> Result<OidcExchangeResult, TrustClientError> {
    if gha {
        oidc::from_github_actions(url, require_audience(audience, "GitHub Actions")?, None)
    } else if gcp {
        oidc::from_gcp(url, require_audience(audience, "GCP")?, None)
    } else if azure {
        oidc::from_azure(url, require_audience(audience, "Azure")?, None)
    } else if ado || (prefer_ambient && oidc::azure_devops_available()) {
        oidc::from_azure_devops(url, None)
    } else {
        Err(TrustClientError::message(
            "No ambient OIDC provider available (GitHub Actions, GCP, Azure, or Azure DevOps)",
        ))
    }
}

fn require_audience<'a>(
    audience: Option<&'a str>,
    provider: &str,
) -> Result<&'a str, TrustClientError> {
    match audience.map(str::trim).filter(|value| !value.is_empty()) {
        Some(audience) => Ok(audience),
        None => Err(TrustClientError::message(format!(
            "oidcAudience is required for {provider} OIDC"
        ))),
    }
}

fn build_http_client(
    builder: &TrustClientBuilder,
) -> Result<reqwest::blocking::Client, TrustClientError> {
    let mut http = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(builder.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT))
        .redirect(match builder.redirects {
            Redirects::Never => Policy::none(),
            Redirects::Normal => Policy::limited(10),
            Redirects::Always => Policy::limited(20),
        })
        .danger_accept_invalid_certs(builder.danger_accept_invalid_certs);
    if let Some(timeout) = builder.timeout {
        http = http.timeout(timeout);
    }
    if builder.http_version == HttpVersion::Http1 {
        http = http.http1_only();
    }
    http = match &builder.proxy {
        ProxyMode::Environment => http,
        ProxyMode::Direct => http.no_proxy(),
        ProxyMode::All(url) => {
            let proxy = reqwest::Proxy::all(url)
                .map_err(|err| TrustClientError::config(format!("invalid proxy URL: {err}")))?;
            http.proxy(proxy)
        }
    };
    if let Some(address) = builder.local_address {
        http = http.local_address(address);
    }
    http.build()
        .map_err(|err| TrustClientError::request("Failed to build HTTP client", err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_url_token_and_account() {
        let missing_url = TrustClient::builder()
            .account_id("acct-1")
            .api_token("key")
            .build()
            .unwrap_err();
        assert_eq!(missing_url.to_string(), "url is required");

        // Test validation after credential discovery without probing the host's
        // cloud metadata endpoint (GitHub-hosted runners may be Azure VMs).
        let missing_key = require_credentials(None, Some("acct-1".into()), false).unwrap_err();
        assert!(missing_key.to_string().starts_with("apiToken is required"));

        let missing_account = TrustClient::builder()
            .url("https://trust.example.com")
            .api_token("key")
            .build()
            .unwrap_err();
        assert_eq!(missing_account.to_string(), "accountId is required");
    }

    #[test]
    fn rejects_blank_token_and_invalid_url() {
        let blank = TrustClient::builder()
            .url("https://trust.example.com")
            .account_id("acct-1")
            .api_token("  ")
            .build()
            .unwrap_err();
        assert_eq!(blank.to_string(), "apiToken must not be blank");

        let blank_account = TrustClient::builder()
            .url("https://trust.example.com")
            .account_id("  ")
            .api_token("key")
            .build()
            .unwrap_err();
        assert_eq!(blank_account.to_string(), "accountId must not be blank");

        assert!(TrustClient::builder()
            .url("ftp://files.example.com")
            .account_id("acct-1")
            .api_token("key")
            .build()
            .is_err());
        assert!(TrustClient::builder()
            .url("/relative")
            .account_id("acct-1")
            .api_token("key")
            .build()
            .is_err());
    }

    #[test]
    fn trims_the_base_url() {
        let client = TrustClient::builder()
            .url("  https://trust.example.com/api/  ")
            .account_id("acct-1")
            .api_token("secret-key")
            .build()
            .unwrap();
        assert_eq!(client.url(), "https://trust.example.com/api");
        assert_eq!(client.api_token(), "secret-key");
        assert_eq!(client.account_id(), "acct-1");
    }
}
