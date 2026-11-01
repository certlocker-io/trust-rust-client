// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use crate::error::TrustClientError;

pub(crate) fn normalize_base_url(input: &str) -> Result<String, TrustClientError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(TrustClientError::config(
            "url must be an absolute http or https URI",
        ));
    }
    let url = reqwest::Url::parse(trimmed)
        .map_err(|_| TrustClientError::config("url must be an absolute http or https URI"))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(TrustClientError::config("url must use http or https"));
        }
    }
    if url.host_str().map(str::is_empty).unwrap_or(true) {
        return Err(TrustClientError::config(
            "url must be an absolute http or https URI",
        ));
    }
    let mut serialized = url.to_string();
    while serialized.ends_with('/') {
        serialized.pop();
    }
    Ok(serialized)
}

/// RFC 3986 path-segment encoding. Unreserved characters are left as-is, so
/// ordinary Trust ids are unchanged.
pub(crate) fn encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Java `URLEncoder.encode` (UTF-8): space is `+`, and every byte outside
/// `[A-Za-z0-9-_. *]` is percent-encoded.
pub(crate) fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub(crate) fn append_query(endpoint: &str, query: &str) -> String {
    if endpoint.contains('?') {
        format!("{endpoint}&{query}")
    } else {
        format!("{endpoint}?{query}")
    }
}

pub(crate) fn trim_slash(url: &str) -> &str {
    url.trim_end_matches('/')
}

pub(crate) fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_owned();
    }
    let mut end = 0;
    for (i, (idx, _)) in value.char_indices().enumerate() {
        if i == max {
            end = idx;
            break;
        }
    }
    format!("{}…", &value[..end])
}

pub(crate) fn join_base(base: &str, path: &str) -> String {
    format!("{}{path}", trim_slash(base))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_http_urls() {
        assert_eq!(
            normalize_base_url("  https://trust.example.com  ").unwrap(),
            "https://trust.example.com"
        );
        assert_eq!(
            normalize_base_url("https://trust.example.com/api/").unwrap(),
            "https://trust.example.com/api"
        );
        assert!(normalize_base_url("ftp://files.example.com").is_err());
        assert!(normalize_base_url("/relative").is_err());
        assert!(normalize_base_url("https://").is_err());
    }

    #[test]
    fn encodes_like_the_gateway_expects() {
        assert_eq!(encode_segment("mvusgvkv5"), "mvusgvkv5");
        assert_eq!(
            form_encode("https://trust.certlocker.io/oidc/acct"),
            "https%3A%2F%2Ftrust.certlocker.io%2Foidc%2Facct"
        );
        assert_eq!(
            append_query("https://example/token", "a=1"),
            "https://example/token?a=1"
        );
        assert_eq!(
            append_query("https://example/token?b=2", "a=1"),
            "https://example/token?b=2&a=1"
        );
    }
}
