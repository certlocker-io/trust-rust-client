// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

//! OIDC sign-in for Trust.
//!
//! Ambient providers are tried in this order: GitHub Actions, GCP, Azure,
//! Azure DevOps. Device OIDC mints an Ed25519 JWT on the machine and exchanges
//! that. Every successful exchange returns a short-lived Trust API token.

mod http;

pub mod azure;
pub mod azure_devops;
pub mod device;
mod exchange;
pub mod gcp;
pub mod github;

pub use device::{
    audience_for_account, load_private_key_from_file, load_private_key_from_pem, mint,
    mint_from_file, mint_from_pem, mint_with_issuer, mint_with_ttl, subject_for_device,
    DeviceOidcConfig, DeviceOidcConfigBuilder, DEFAULT_TTL_MINUTES, DEVICE_ISSUER,
};
pub use ed25519_dalek::SigningKey;
pub use exchange::{
    exchange, from_azure, from_azure_devops, from_device, from_gcp, from_github_actions,
    OidcExchangeResult,
};

pub(crate) use device::mint_from_config as mint_device_jwt;

pub(crate) fn github_actions_available() -> bool {
    github::is_available()
}

pub(crate) fn gcp_available() -> bool {
    gcp::is_available()
}

pub(crate) fn azure_available() -> bool {
    azure::is_available()
}

pub(crate) fn azure_devops_available() -> bool {
    azure_devops::is_available()
}
