// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

//! Trust asset records.
//!
//! Gateway JSON for secrets, certificates, and tokens uses snake_case.
//! Unknown properties are ignored. Timestamps are UTC.

#[macro_use]
mod asset;
mod certificate;
mod de;
mod secret;
mod token;

pub use asset::{Asset, AssetStatus, AssetType};
pub use certificate::{Certificate, CertificateValidation};
pub use secret::{
    Configuration, Credentials, Password, Pem, PrivateKey, Secret, SecretKeyAlgorithm, SecretType,
};
pub use token::{Protocol, Token, TokenType};
