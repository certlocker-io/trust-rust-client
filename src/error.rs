// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::fmt;

/// Failure returned by Trust, or a failure while calling Trust.
#[derive(Debug, thiserror::Error)]
pub enum TrustClientError {
    /// Builder input was missing or invalid.
    #[error("{0}")]
    Config(String),

    /// The call failed before a Trust error body was available, or Trust rejected it
    /// without a structured error.
    #[error("{0}")]
    Message(String),

    /// Trust returned an HTTP error response.
    #[error("{message}")]
    Trust {
        /// Message taken from the Trust error body.
        message: String,
        /// Parsed Trust error, including the HTTP status.
        error: TrustError,
    },

    /// The HTTP call itself failed (DNS, connection, timeout, or I/O).
    #[error("{message}")]
    Request {
        /// Short description of the failed call.
        message: String,
        /// Underlying HTTP or I/O error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Ambient OIDC exchange failed and no static API token was set.
    #[error("Ambient OIDC exchange failed and no apiToken set")]
    Ambient {
        /// The exchange or provider error.
        #[source]
        source: Box<TrustClientError>,
    },
}

impl TrustClientError {
    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub(crate) fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub(crate) fn trust(error: TrustError) -> Self {
        let message = if error.error_message.trim().is_empty() {
            "Unknown error".to_owned()
        } else {
            error.error_message.clone()
        };
        Self::Trust { message, error }
    }

    pub(crate) fn request(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Request {
            message: message.into(),
            source: Box::new(source),
        }
    }

    pub(crate) fn ambient(source: TrustClientError) -> Self {
        Self::Ambient {
            source: Box::new(source),
        }
    }

    /// Trust error body when the failure came from an HTTP error response.
    pub fn trust_error(&self) -> Option<&TrustError> {
        match self {
            Self::Trust { error, .. } => Some(error),
            _ => None,
        }
    }

    /// Whether [`Self::trust_error`] is present.
    pub fn has_trust_error(&self) -> bool {
        self.trust_error().is_some()
    }
}

/// Error returned by Trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustError {
    /// Human-readable message from the Gateway.
    pub error_message: String,
    /// HTTP status of the failed response.
    pub http_status: u16,
}

impl TrustError {
    pub(crate) fn new(error_message: impl Into<String>, http_status: u16) -> Self {
        Self {
            error_message: error_message.into(),
            http_status,
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HTTP {}: {}",
            self.http_status,
            if self.error_message.trim().is_empty() {
                "Unknown error"
            } else {
                self.error_message.as_str()
            }
        )
    }
}
