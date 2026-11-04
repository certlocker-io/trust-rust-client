use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use trust_client::model::{SecretType, TokenType};
use trust_client::oidc::{self, DeviceOidcConfig};
use trust_client::{
    HttpVersion, ProxyMode, Redirects, TrustClient, TrustClientBuilder, TrustService,
    ACCESS_CODE_HEADER, ACCESS_REQUIRED_STATUS, ACCESS_RESPONSE_HEADER,
};

struct Hit {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

struct Mock {
    url: String,
    hits: Arc<Mutex<Vec<Hit>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Mock {
    fn spawn<F>(handler: F) -> Self
    where
        F: Fn(&Hit, &str) -> (u16, Vec<(&'static str, String)>, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let hits = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let hits_thread = Arc::clone(&hits);
        let stop_thread = Arc::clone(&stop);
        let server_url = url.clone();
        let join = thread::spawn(move || {
            let handler = Arc::new(handler);
            loop {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Some(hit) = read_hit(&mut stream) else {
                    continue;
                };
                let (status, headers, body) = handler(&hit, &server_url);
                hits_thread.lock().unwrap().push(hit);
                write_response(&mut stream, status, &headers, &body);
            }
        });
        Self {
            url,
            hits,
            stop,
            join: Some(join),
        }
    }

    fn hit_count(&self) -> usize {
        self.hits.lock().unwrap().len()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn read_hit(stream: &mut TcpStream) -> Option<Hit> {
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 1024 * 1024 {
            return None;
        }
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(length);
    Some(Hit {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn write_response(stream: &mut TcpStream, status: u16, headers: &[(&str, String)], body: &str) {
    let reason = match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.push_str(body);
    let _ = stream.write_all(out.as_bytes());
}

fn client(url: &str) -> TrustClient {
    TrustClient::builder()
        .url(url)
        .account_id("acct-1")
        .api_token("test-token")
        .build()
        .unwrap()
}

#[test]
fn reads_secrets_certificates_and_tokens() {
    let server = Mock::spawn(|hit, _| {
        assert_eq!(
            hit.headers.get("x-api-token").map(String::as_str),
            Some("test-token")
        );
        let body = match hit.path.as_str() {
            "/rest/api/v1/secret/acct-1/get/mvusgvkv5" => {
                r#"{"id":"mvusgvkv5","account_id":"acct-1","name":"app","status":"ACTIVE","secret_type":"CONFIGURATION","version":2,"date_created":"2026-05-01T12:34:56.789Z"}"#
            }
            "/rest/api/v1/secret/acct-1/fetch/mvusgvkv5" => "mode: dark\n",
            "/rest/api/v1/secret/acct-1/fetch" => "assigned-secret",
            "/rest/api/v1/secret/acct-1/fetch/b5fqj6c8d" => {
                r#"{"key_algorithm":"ED25519","key_size":"256","username":"root","key":"-----BEGIN"}"#
            }
            "/rest/api/v1/secret/acct-1/fetch/v5q7pspif" => "s3cret",
            "/rest/api/v1/secret/acct-1/fetch/17bu1p62uq" => {
                r#"{"username":"ada","password":"hunter2"}"#
            }
            "/rest/api/v1/secret/acct-1/fetch/k8m7c8pps" => {
                r#"{"key_algorithm":"RSA","key_size":"2048","key":"private"}"#
            }
            "/rest/api/v1/cert/acct-1/get/cert1" => {
                r#"{"id":"cert1","primary_domain":"app.example","cert_validation":"EV","status":"ACTIVE","san_domains":["app.example","www.example"]}"#
            }
            "/rest/api/v1/cert/acct-1/fetch/cert1" => "-----BEGIN CERTIFICATE-----\nLEAF\n",
            "/rest/api/v1/cert/acct-1/fetch-bundle/cert1" => {
                "-----BEGIN CERTIFICATE-----\nBUNDLE\n"
            }
            "/rest/api/v1/token/acct-1/get/token1" => {
                r#"{"id":"token1","token_type":"SECRET","protocols":["SSH","HTTPS"],"status":"SUSPENDED","single_use":false}"#
            }
            other => panic!("unexpected path {other}"),
        };
        let media = if hit.path.contains("/fetch") {
            "text/plain"
        } else {
            "application/json"
        };
        (
            200,
            vec![("Content-Type", media.to_owned())],
            body.to_owned(),
        )
    });

    let service = TrustService::new(client(&server.url));
    let secret = service.get_secret("mvusgvkv5").unwrap();
    assert_eq!(secret.id.as_deref(), Some("mvusgvkv5"));
    assert_eq!(secret.secret_type, Some(SecretType::Configuration));
    assert!(secret.is_active());
    assert!(secret.date_created.is_some());

    let configuration = service.get_secret_as_configuration("mvusgvkv5").unwrap();
    assert_eq!(configuration.secret, "mode: dark\n");
    assert_eq!(service.fetch_assigned_secret().unwrap(), "assigned-secret");

    let pem = service.get_secret_as_pem("b5fqj6c8d").unwrap();
    assert!(pem.is_pq_ready());
    assert_eq!(pem.username.as_deref(), Some("root"));

    assert_eq!(
        service
            .get_secret_as_password("v5q7pspif")
            .unwrap()
            .password,
        "s3cret"
    );
    let credentials = service.get_secret_as_credentials("17bu1p62uq").unwrap();
    assert_eq!(credentials.username.as_deref(), Some("ada"));
    assert_eq!(credentials.password.as_deref(), Some("hunter2"));

    let key = service.get_secret_as_private_key("k8m7c8pps").unwrap();
    assert!(!key.is_pq_ready());
    assert_eq!(key.key.as_deref(), Some("private"));

    let certificate = service.get_certificate("cert1").unwrap();
    assert_eq!(certificate.primary_domain.as_deref(), Some("app.example"));
    assert_eq!(
        certificate.cert_validation.unwrap().description(),
        "Extended Validation"
    );
    assert_eq!(
        service.fetch_certificate("cert1").unwrap(),
        "-----BEGIN CERTIFICATE-----\nLEAF\n"
    );
    assert_eq!(
        service.fetch_certificate_bundle("cert1").unwrap(),
        "-----BEGIN CERTIFICATE-----\nBUNDLE\n"
    );

    let token = service.get_token("token1").unwrap();
    assert_eq!(token.token_type, Some(TokenType::Secret));
    assert!(token.status.unwrap().can_resume());
    assert_eq!(server.hit_count(), 11);
}

#[test]
fn steps_up_when_the_gateway_asks_for_an_access_code() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let server = Mock::spawn(move |hit, _| {
        let n = seen.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            return (
                401,
                vec![
                    (ACCESS_RESPONSE_HEADER, "EMAIL".to_owned()),
                    ("Content-Type", "text/plain".to_owned()),
                ],
                "Please enter verification code emailed to you".to_owned(),
            );
        }
        assert_eq!(
            hit.headers.get(ACCESS_CODE_HEADER).map(String::as_str),
            Some("email-code-99")
        );
        (
            200,
            vec![("Content-Type", "text/plain".to_owned())],
            "super-secret-value".to_owned(),
        )
    });

    let prompted = Arc::new(Mutex::new(String::new()));
    let prompted_for_closure = Arc::clone(&prompted);
    let service = TrustService::from_builder(
        TrustClient::builder()
            .url(&server.url)
            .account_id("acct-1")
            .api_token("test-token")
            .auth_code_prompt(move |reason| {
                *prompted_for_closure.lock().unwrap() = reason.to_owned();
                Ok("email-code-99".to_owned())
            }),
    )
    .unwrap();

    assert_eq!(
        service.fetch_assigned_secret().unwrap(),
        "super-secret-value"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(
        prompted.lock().unwrap().as_str(),
        "Please enter verification code emailed to you"
    );
    assert_eq!(ACCESS_REQUIRED_STATUS, 401);
}

#[test]
fn sends_a_preset_access_code_and_surfaces_gateway_errors() {
    let mode = Arc::new(Mutex::new(String::from("code")));
    let mode_for_handler = Arc::clone(&mode);
    let server = Mock::spawn(
        move |hit, _| match mode_for_handler.lock().unwrap().as_str() {
            "code" => {
                assert_eq!(
                    hit.headers.get("x-access-code").map(String::as_str),
                    Some("already")
                );
                (200, vec![], "ok".to_owned())
            }
            "dto" => (
                404,
                vec![(
                    "x-body-type",
                    "certlocker.gateway.api.model.ErrorDTO".to_owned(),
                )],
                r#"{"error_message":"missing secret"}"#.to_owned(),
            ),
            _ => (
                400,
                vec![(
                    "x-body-type",
                    "certlocker.core.exceptions.CLErrorException".to_owned(),
                )],
                r#"{"error":{"message":"denied by policy"}}"#.to_owned(),
            ),
        },
    );

    let trust = client(&server.url);
    trust.set_access_code("already");
    assert_eq!(trust.fetch_secret(Some("one")).unwrap(), "ok");

    *mode.lock().unwrap() = "dto".to_owned();
    let err = trust.fetch_secret(Some("missing")).unwrap_err();
    let trust_error = err.trust_error().unwrap();
    assert_eq!(trust_error.http_status, 404);
    assert_eq!(trust_error.error_message, "missing secret");
    assert!(err.has_trust_error());

    *mode.lock().unwrap() = "cl".to_owned();
    let err = trust.get_secret(Some("nope")).unwrap_err();
    assert_eq!(err.to_string(), "denied by policy");
}

#[test]
fn does_not_follow_redirects_unless_asked() {
    let server = Mock::spawn(|hit, url| {
        if hit.path.ends_with("/fetch/s") {
            return (
                302,
                vec![("Location", format!("{url}/landed"))],
                String::new(),
            );
        }
        (200, vec![], "followed".to_owned())
    });

    let err = client(&server.url).fetch_secret(Some("s")).unwrap_err();
    assert_eq!(err.trust_error().unwrap().http_status, 302);

    let followed = TrustClient::builder()
        .url(&server.url)
        .account_id("acct-1")
        .api_token("test-token")
        .follow_redirects(Redirects::Normal)
        .http_version(HttpVersion::Http1)
        .proxy(ProxyMode::Direct)
        .connect_timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    assert_eq!(followed.fetch_secret(Some("s")).unwrap(), "followed");
}

#[test]
fn uses_a_caller_supplied_http_client() {
    let server = Mock::spawn(|hit, _| {
        assert_eq!(
            hit.headers.get("x-from-test").map(String::as_str),
            Some("yes")
        );
        (200, vec![], "from-custom".to_owned())
    });
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-from-test", "yes".parse().unwrap());
    let http = reqwest::blocking::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();
    let trust = TrustClient::builder()
        .url(&server.url)
        .account_id("acct-1")
        .api_token("test-token")
        .http_client(http)
        .build()
        .unwrap();
    assert_eq!(trust.fetch_secret(None).unwrap(), "from-custom");
}

#[test]
fn exchanges_an_id_token_and_mints_device_jwts() {
    let server = Mock::spawn(|hit, _| {
        assert_eq!(hit.method, "POST");
        assert_eq!(hit.path, "/rest/api/v1/oidc/exchange");
        let body: serde_json::Value = serde_json::from_str(&hit.body).unwrap();
        assert_eq!(body["idToken"], "raw-jwt");
        assert_eq!(body["tokenType"], "CERTIFICATE");
        (
            200,
            vec![("Content-Type", "application/json".to_owned())],
            r#"{"tokenId":"minted-token","expiresAt":"2026-11-01T12:00:00Z","tokenType":"CERTIFICATE","accountId":"acct-from-exchange","principalId":"prn-1"}"#.to_owned(),
        )
    });

    let exchanged = oidc::exchange(&server.url, "raw-jwt", Some(TokenType::Certificate)).unwrap();
    assert_eq!(exchanged.token_id, "minted-token");
    assert_eq!(exchanged.account_id.as_deref(), Some("acct-from-exchange"));
    assert_eq!(exchanged.token_type_enum(), Some(TokenType::Certificate));
    assert!(exchanged.expires_at.is_some());
    assert_eq!(exchanged.principal_id.as_deref(), Some("prn-1"));

    let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIF9AaYYFhQwyap4byHSJdP10An9RnSyjIs7938lU7Sm/\n-----END PRIVATE KEY-----\n";
    let config = DeviceOidcConfig::builder()
        .audience(oidc::audience_for_account("acct-from-exchange").unwrap())
        .device_id("laptop-1")
        .private_key_pem(pem)
        .key_id("device-abc123")
        .build()
        .unwrap();
    let jwt = oidc::mint_from_pem(
        &config.audience,
        &config.device_id,
        pem,
        Some("device-abc123"),
        5,
    )
    .unwrap();
    assert_eq!(jwt.split('.').count(), 3);
    assert_eq!(
        oidc::subject_for_device("laptop-1").unwrap(),
        "device:laptop-1"
    );
}

#[test]
fn reports_exchange_failures_and_builds_from_the_response() {
    let server = Mock::spawn(|hit, _| {
        if hit.method == "POST" && hit.body.contains("denied-jwt") {
            return (
                200,
                vec![],
                r#"{"errorMessage":"No OIDC principal matched this token"}"#.to_owned(),
            );
        }
        if hit.method == "POST" {
            return (
                200,
                vec![],
                r#"{"tokenId":"minted","accountId":"acct-9","tokenType":"SECRET","expiresAt":"2026-11-01T12:00:00"}"#
                    .to_owned(),
            );
        }
        assert_eq!(hit.path, "/rest/api/v1/secret/acct-9/fetch");
        assert_eq!(
            hit.headers.get("x-api-token").map(String::as_str),
            Some("minted")
        );
        (200, vec![], "via-oidc".to_owned())
    });

    let err = oidc::exchange(&server.url, "denied-jwt", None).unwrap_err();
    assert!(err.to_string().contains("No OIDC principal matched"));

    let blank = TrustClientBuilder::from_id_token(&server.url, "   ").unwrap_err();
    assert!(blank.to_string().contains("idToken must not be blank"));

    let client = TrustClientBuilder::from_id_token(&server.url, "raw-jwt").unwrap();
    assert_eq!(client.account_id(), "acct-9");
    assert_eq!(client.api_token(), "minted");
    assert_eq!(client.fetch_secret(None).unwrap(), "via-oidc");
}

#[test]
fn github_actions_availability_follows_the_process_environment() {
    let present = std::env::var(oidc::github::REQUEST_URL_ENV)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
        && std::env::var(oidc::github::REQUEST_TOKEN_ENV)
            .ok()
            .is_some_and(|value| !value.trim().is_empty());
    assert_eq!(oidc::github::is_available(), present);
    assert_eq!(oidc::azure_devops::is_available(), {
        std::env::var(oidc::azure_devops::OIDC_REQUEST_URI_ENV)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
            && std::env::var(oidc::azure_devops::ACCESS_TOKEN_ENV)
                .ok()
                .is_some_and(|value| !value.trim().is_empty())
    });
}

#[test]
fn exchanges_with_current_gateway_snake_case_contract() {
    let server = Mock::spawn(|hit, _| {
        let body: serde_json::Value = serde_json::from_str(&hit.body).unwrap();
        assert_eq!(body["id_token"], "fixture-jwt");
        assert_eq!(body["token_type"], "SECRET");
        (
            200,
            vec![("Content-Type", "application/json".to_owned())],
            r#"{"token_id":"fixture-token","account_id":"acct-current","token_type":"SECRET","expires_at":"2026-11-04T12:00:00"}"#.to_owned(),
        )
    });
    let exchanged = oidc::exchange(&server.url, "fixture-jwt", Some(TokenType::Secret)).unwrap();
    assert_eq!(exchanged.token_id, "fixture-token");
    assert_eq!(exchanged.account_id.as_deref(), Some("acct-current"));
    assert!(exchanged.expires_at.is_some());
}

#[test]
fn legacy_and_account_routes_resolve_assigned_assets_without_downgrade() {
    for legacy in [true, false] {
        let account = if legacy { "" } else { "acct-1/" };
        let server = Mock::spawn(move |hit, _| {
            if hit.path == format!("/rest/api/v1/token/{account}get/test-token") {
                return (200, vec![], r#"{"secret_id":"bound-secret"}"#.to_owned());
            }
            if hit.path.ends_with("/denied") {
                return (403, vec![], "denied".to_owned());
            }
            (200, vec![], r#"{"id":"fixture"}"#.to_owned())
        });
        let mut builder = TrustClient::builder()
            .url(&server.url)
            .api_token("test-token")
            .legacy_api(legacy);
        if !legacy {
            builder = builder.account_id("acct-1");
        }
        let trust = builder.build().unwrap();
        trust.get_secret(None).unwrap();
        trust.fetch_secret(Some("a/b")).unwrap();
        trust.get_certificate(None).unwrap();
        trust.fetch_certificate_bundle(Some("cert-token")).unwrap();
        let expected = [
            format!("/rest/api/v1/token/{account}get/test-token"),
            format!("/rest/api/v1/secret/{account}get/bound-secret"),
            format!("/rest/api/v1/secret/{account}fetch/a%2Fb"),
            format!("/rest/api/v1/cert/{account}get/test-token"),
            format!("/rest/api/v1/cert/{account}fetch-bundle/cert-token"),
        ];
        let paths: Vec<String> = server
            .hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| h.path.clone())
            .collect();
        assert_eq!(paths, expected);
        assert_eq!(
            trust
                .fetch_secret(Some("denied"))
                .unwrap_err()
                .trust_error()
                .unwrap()
                .http_status,
            403
        );
        assert_eq!(server.hit_count(), 6);
    }
}
