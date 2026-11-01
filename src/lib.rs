// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

//! Rust client for [Certlocker Trust](https://trust.certlocker.io).
//!
//! Read secrets, certificates, and tokens from the Gateway API. Sign in with a
//! UI-minted API token, or exchange a workload OIDC token (GitHub Actions, GCP,
//! Azure, Azure DevOps, or an enrolled device key).
//!
//! `get` returns asset metadata. `fetch` returns asset contents.
//! Gateway paths include the account id, and that account must match the token.
//!
//! See the crate README for end-to-end examples.

#![forbid(unsafe_code)]

mod auth;
mod builder;
mod client;
mod error;
pub mod model;
pub mod oidc;
mod service;
mod util;

pub use auth::console_auth_code_prompt;
pub use builder::{HttpVersion, ProxyMode, Redirects, TrustClientBuilder, DEFAULT_CONNECT_TIMEOUT};
pub use client::{TrustClient, ACCESS_CODE_HEADER, ACCESS_REQUIRED_STATUS, ACCESS_RESPONSE_HEADER};
pub use error::{TrustClientError, TrustError};
pub use model::{
    Asset, AssetStatus, AssetType, Certificate, CertificateValidation, Configuration, Credentials,
    Password, Pem, PrivateKey, Protocol, Secret, SecretKeyAlgorithm, SecretType, Token, TokenType,
};
pub use service::TrustService;
