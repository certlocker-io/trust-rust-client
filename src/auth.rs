// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{self, BufRead, Write};

use crate::error::TrustClientError;

/// Prompt used when Gateway requires a 2FA / access code on a user-bound token.
///
/// `reason` is the prompt text from the Gateway response body.
pub type AuthCodePrompt = Box<dyn Fn(&str) -> Result<String, TrustClientError> + Send + Sync>;

/// Reads a 2FA / access code from stdin.
///
/// Pass this function to [`crate::TrustClientBuilder::auth_code_prompt`].
/// The prompt is printed to stdout. An empty line is an error.
pub fn console_auth_code_prompt(reason: &str) -> Result<String, TrustClientError> {
    let label = if reason.trim().is_empty() {
        "authentication code"
    } else {
        reason.trim()
    };
    print!("Trust {label}: ");
    io::stdout()
        .flush()
        .map_err(|err| TrustClientError::request("Failed to read authentication code", err))?;

    let stdin = io::stdin();
    let mut line = String::new();
    let read = stdin
        .lock()
        .read_line(&mut line)
        .map_err(|err| TrustClientError::request("Failed to read authentication code", err))?;
    if read == 0 || line.trim().is_empty() {
        return Err(TrustClientError::message(
            "Failed to read authentication code: Empty authentication code",
        ));
    }
    Ok(line.trim().to_owned())
}
