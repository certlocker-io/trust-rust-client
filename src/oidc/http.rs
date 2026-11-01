// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use crate::error::TrustClientError;

pub(crate) fn client(
    connect_timeout: Duration,
    timeout: Duration,
) -> Result<reqwest::blocking::Client, TrustClientError> {
    reqwest::blocking::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| TrustClientError::request("Failed to build HTTP client", err))
}

pub(crate) fn probe_client() -> Result<reqwest::blocking::Client, TrustClientError> {
    client(Duration::from_millis(200), Duration::from_millis(400))
}
