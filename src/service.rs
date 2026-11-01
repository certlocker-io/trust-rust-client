// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use serde::de::DeserializeOwned;

use crate::builder::TrustClientBuilder;
use crate::client::TrustClient;
use crate::error::TrustClientError;
use crate::model::{
    Certificate, Configuration, Credentials, Password, Pem, PrivateKey, Secret, Token,
};

/// Typed access to Trust secrets, certificates, and tokens.
///
/// `get` methods return the asset record. `fetch` methods return the asset contents.
/// Dropping the service drops the underlying [`TrustClient`] and its connection pool.
///
/// An asset token is an `x-api-token` assigned to one secret or one certificate.
/// The `*_assigned_*` methods send no id. Pass an id when the token is not bound
/// to a single asset.
///
/// # Example
///
/// ```no_run
/// use trust_client::TrustService;
///
/// # fn main() -> Result<(), trust_client::TrustClientError> {
/// let service = TrustService::from_builder(
///     trust_client::TrustClient::builder()
///         .url("https://trust.certlocker.io")
///         .account_id("<accountId>")
///         .api_token("<token>"),
/// )?;
///
/// let secret = service.get_secret("mvusgvkv5")?;
/// let configuration = service.get_secret_as_configuration("mvusgvkv5")?;
/// let pem = service.get_secret_as_pem("b5fqj6c8d")?;
/// let password = service.get_secret_as_password("v5q7pspif")?;
/// let credentials = service.get_secret_as_credentials("17bu1p62uq")?;
/// let private_key = service.get_secret_as_private_key("k8m7c8pps")?;
/// let certificate = service.get_certificate("certId")?;
/// let pem_leaf = service.fetch_certificate("certId")?;
/// let bundle = service.fetch_certificate_bundle("certId")?;
/// let token = service.get_token("tokenId")?;
/// # let _ = (secret, configuration, pem, password, credentials, private_key, certificate, pem_leaf, bundle, token);
/// # Ok(())
/// # }
/// ```
pub struct TrustService {
    client: TrustClient,
}

impl TrustService {
    /// Creates a service for an existing client.
    pub fn new(client: TrustClient) -> Self {
        Self { client }
    }

    /// Builds the client and wraps it.
    pub fn from_builder(builder: TrustClientBuilder) -> Result<Self, TrustClientError> {
        Ok(Self::new(builder.build()?))
    }

    /// Client used for requests.
    pub fn client(&self) -> &TrustClient {
        &self.client
    }

    /// Contents of the secret `id`.
    pub fn fetch_secret(&self, id: &str) -> Result<String, TrustClientError> {
        self.client.fetch_secret(Some(id))
    }

    /// Contents of the secret assigned to this API token.
    pub fn fetch_assigned_secret(&self) -> Result<String, TrustClientError> {
        self.client.fetch_secret(None)
    }

    /// Secret record for `id`.
    pub fn get_secret(&self, id: &str) -> Result<Secret, TrustClientError> {
        parse_json(&self.client.get_secret(Some(id))?)
    }

    /// Secret record assigned to this API token.
    pub fn get_assigned_secret(&self) -> Result<Secret, TrustClientError> {
        parse_json(&self.client.get_secret(None)?)
    }

    /// Secret contents parsed as a PEM secret.
    pub fn get_secret_as_pem(&self, id: &str) -> Result<Pem, TrustClientError> {
        self.secret_as(id)
    }

    /// Assigned secret contents parsed as a PEM secret.
    pub fn get_assigned_secret_as_pem(&self) -> Result<Pem, TrustClientError> {
        parse_json(&self.client.fetch_secret(None)?)
    }

    /// Secret contents as configuration text.
    pub fn get_secret_as_configuration(&self, id: &str) -> Result<Configuration, TrustClientError> {
        Ok(Configuration::new(self.client.fetch_secret(Some(id))?))
    }

    /// Assigned secret contents as configuration text.
    pub fn get_assigned_secret_as_configuration(&self) -> Result<Configuration, TrustClientError> {
        Ok(Configuration::new(self.client.fetch_secret(None)?))
    }

    /// Secret contents parsed as a private key.
    pub fn get_secret_as_private_key(&self, id: &str) -> Result<PrivateKey, TrustClientError> {
        self.secret_as(id)
    }

    /// Assigned secret contents parsed as a private key.
    pub fn get_assigned_secret_as_private_key(&self) -> Result<PrivateKey, TrustClientError> {
        parse_json(&self.client.fetch_secret(None)?)
    }

    /// Secret contents as a password.
    pub fn get_secret_as_password(&self, id: &str) -> Result<Password, TrustClientError> {
        Ok(Password::new(self.client.fetch_secret(Some(id))?))
    }

    /// Assigned secret contents as a password.
    pub fn get_assigned_secret_as_password(&self) -> Result<Password, TrustClientError> {
        Ok(Password::new(self.client.fetch_secret(None)?))
    }

    /// Secret contents parsed as credentials.
    pub fn get_secret_as_credentials(&self, id: &str) -> Result<Credentials, TrustClientError> {
        self.secret_as(id)
    }

    /// Assigned secret contents parsed as credentials.
    pub fn get_assigned_secret_as_credentials(&self) -> Result<Credentials, TrustClientError> {
        parse_json(&self.client.fetch_secret(None)?)
    }

    /// Certificate record for `id`.
    ///
    /// This calls `GET /rest/api/v1/cert/{accountId}/get/{id}` and parses the JSON record.
    /// Use [`Self::fetch_certificate`] for the PEM.
    pub fn get_certificate(&self, id: &str) -> Result<Certificate, TrustClientError> {
        parse_json(&self.client.get_certificate(Some(id))?)
    }

    /// Certificate record assigned to this API token.
    pub fn get_assigned_certificate(&self) -> Result<Certificate, TrustClientError> {
        parse_json(&self.client.get_certificate(None)?)
    }

    /// Certificate PEM for `id`.
    pub fn fetch_certificate(&self, id: &str) -> Result<String, TrustClientError> {
        self.client.fetch_certificate(Some(id))
    }

    /// Certificate PEM assigned to this API token.
    pub fn fetch_assigned_certificate(&self) -> Result<String, TrustClientError> {
        self.client.fetch_certificate(None)
    }

    /// Certificate bundle for `id`.
    pub fn fetch_certificate_bundle(&self, id: &str) -> Result<String, TrustClientError> {
        self.client.fetch_certificate_bundle(Some(id))
    }

    /// Certificate bundle assigned to this API token.
    pub fn fetch_assigned_certificate_bundle(&self) -> Result<String, TrustClientError> {
        self.client.fetch_certificate_bundle(None)
    }

    /// Token record for `id`.
    pub fn get_token(&self, id: &str) -> Result<Token, TrustClientError> {
        parse_json(&self.client.get_token(id)?)
    }

    fn secret_as<T: DeserializeOwned>(&self, id: &str) -> Result<T, TrustClientError> {
        parse_json(&self.client.fetch_secret(Some(id))?)
    }
}

fn parse_json<T: DeserializeOwned>(body: &str) -> Result<T, TrustClientError> {
    if body.trim().is_empty() {
        return Err(TrustClientError::message("Trust response body was empty"));
    }
    serde_json::from_str(body)
        .map_err(|err| TrustClientError::message(format!("Failed to parse Trust response: {err}")))
}
