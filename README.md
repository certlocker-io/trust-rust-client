<img align="right" alt="Certlocker" src="https://certlocker.io/logo-white-32.png" width="32" height="32">

# Trust Rust Client

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Rust client for [Certlocker Trust](https://trust.certlocker.io): read secrets, certificates, and tokens over the Gateway API.

The crate name is `trust-client`. In Rust code that is `trust_client`. It follows the same Gateway calls as the Java `trust-client` library: `get` returns the asset record, `fetch` returns the asset contents, and sign-in is either a UI-minted API token or an OIDC exchange.

Requires **Rust 1.84** or newer. This repository's `Cargo.lock` is pinned so `cargo test --locked` builds on 1.84.

## Dependency

```toml
[dependencies]
trust-client = "1.0.4"
```

From this repository while it is not on crates.io:

```toml
[dependencies]
trust-client = { path = "../trust-rust-client" }
```

HTTP uses `reqwest` with the platform TLS stack. JSON uses `serde`. Device OIDC signs Ed25519 JWTs locally. No OpenSSL install is required on macOS or Windows.

## Features

`get` returns asset metadata. `fetch` returns asset contents.

- **Secrets** — get / fetch. Typed readers for PEM, configuration, password, credentials, and private key.
- **Certificates** — get the record, fetch the leaf PEM, or fetch the bundle (certificate plus private key).
- **Tokens** — get the token record.
- **Auth** — UI-minted static API token. Ambient OIDC (GitHub Actions, GCP, Azure, Azure DevOps). Device OIDC. Optional mint type `SECRET` / `CERTIFICATE` / `MCP`. 2FA access-code prompt.
- **Paths** — every Gateway asset call includes `{accountId}`. That path account must match the token's account.

Asset JSON is snake_case (`secret_type`, `date_created`). The OIDC exchange body and response are camelCase (`tokenId`, `accountId`). Unknown JSON fields are ignored. Timestamps are UTC. A JSON array **or** a single JSON value is accepted anywhere the client expects a list.

Dropping a `TrustClient` or `TrustService` drops the connection pool. `Debug` prints the URL and account id and redacts the API token. `api_token()` still returns the credential, so do not log that value.

## Authentication

Prefer federated OIDC for CI and machines. Use a UI-minted `SECRET` token for break-glass or local human use.

The audience for GitHub, GCP, Azure, and device OIDC is per account:

```text
https://trust.certlocker.io/oidc/<accountId>
```

`trust_client::oidc::audience_for_account` builds that URL. Azure DevOps uses ADO's fixed audience `api://AzureADTokenExchange`. Trust matches that principal by issuer and `sub`, not by the Trust audience URL.

### Static API token (UI-minted)

```rust
use trust_client::TrustClient;

let client = TrustClient::builder()
    .url("https://trust.certlocker.io")
    .account_id("<accountId>")
    .api_token("<ui-minted-token-id>")
    .build()?;
```

The token is sent as `x-api-token`. Gateway asset paths look like `/rest/api/v1/secret/{accountId}/fetch`. The path `accountId` must match the token's account.

`url` must be an absolute `http` or `https` URL. Surrounding whitespace is ignored and a trailing slash is removed. `build` returns an error when the URL, account id, or API token is missing or blank.

### Ambient OIDC (CI / cloud)

`from_ambient_oidc` / `prefer_ambient_oidc(true)` picks the first available ambient provider: GitHub Actions, then GCP, then Azure, then Azure DevOps. When `account_id` is not set on the builder, it is taken from the exchange response.

```rust
use trust_client::TrustClientBuilder;

let client = TrustClientBuilder::from_ambient_oidc(
    "https://trust.certlocker.io",
    "https://trust.certlocker.io/oidc/<accountId>",
)?;
```

Or, with a static token kept as a fallback if the exchange fails:

```rust
use trust_client::TrustClient;

let client = TrustClient::builder()
    .url("https://trust.certlocker.io")
    .oidc_audience("https://trust.certlocker.io/oidc/<accountId>")
    .api_token("<break-glass-token>")
    .prefer_ambient_oidc(true)
    .build()?;
```

If ambient exchange fails and an API token was also set, that token is used. If exchange fails and no token was set, `build` returns `TrustClientError::Ambient`.

| Provider | Detection | Needs Trust audience |
| --- | --- | --- |
| GitHub Actions | `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` (`permissions: id-token: write`) | Yes |
| GCP | `K_SERVICE`, `GCE_METADATA_HOST`, or a short probe of the GCE / GKE / Cloud Run metadata server | Yes |
| Azure | `IDENTITY_ENDPOINT` + `IDENTITY_HEADER`, or a short IMDS probe. Optional `AZURE_CLIENT_ID` when several user-assigned identities exist | Yes |
| Azure DevOps | `SYSTEM_OIDCREQUESTURI` and `SYSTEM_ACCESSTOKEN`. Optional `AZURESUBSCRIPTION_SERVICE_CONNECTION_ID` or `SYSTEM_OIDC_SERVICE_CONNECTION_ID` | No (fixed ADO audience) |

GCP and Azure probes are cached for the process lifetime. They run only when a token is missing or `prefer_ambient_oidc` is set, and only after a higher-priority provider was absent.

Explicit provider exchange, then build a client yourself:

```rust
use trust_client::model::TokenType;
use trust_client::oidc;
use trust_client::TrustClient;

let trust = "https://trust.certlocker.io";
let aud = "https://trust.certlocker.io/oidc/<accountId>";

let gha = oidc::from_github_actions(trust, aud, None)?;
let gcp = oidc::from_gcp(trust, aud, None)?;
let azure = oidc::from_azure(trust, aud, None)?;
let ado = oidc::from_azure_devops(trust, None)?;

let client = TrustClient::builder()
    .url(trust)
    .api_token(&gha.token_id)
    .account_id(gha.account_id.as_deref().unwrap_or("<accountId>"))
    .build()?;
```

`OidcExchangeResult` carries `token_id` (send this as `x-api-token`), `expires_at`, `token_type`, `account_id`, and `principal_id`. `token_type_enum()` parses the Gateway type name when it is one of the known `TokenType` values.

Each provider also exposes `is_available()` and `request_id_token(...)` if you want the raw JWT without exchanging it:

```rust
use trust_client::oidc::github;

if github::is_available() {
    let jwt = github::request_id_token("https://trust.certlocker.io/oidc/<accountId>")?;
    let exchanged = trust_client::oidc::exchange(
        "https://trust.certlocker.io",
        &jwt,
        None,
    )?;
    let _ = exchanged.token_id;
}
```

### Device OIDC (enrolled machine)

Mints a short-lived Ed25519 / `EdDSA` JWT from the private key downloaded at enroll, then exchanges it for a Trust token. Keep the private key on the machine. Never check it in.

The JWT matches Trust `DeviceOidcVerifier`:

| Claim / header | Value |
| --- | --- |
| `iss` | `https://trust.certlocker.io/oidc/device` (`oidc::DEVICE_ISSUER`) |
| `aud` | `https://trust.certlocker.io/oidc/<accountId>` |
| `sub` | `device:<deviceId>` |
| `device_id` | the enrolled device id |
| `iat` / `exp` | now, plus the TTL (default 5 minutes, minimum 1) |
| `jti` | a random UUID |
| `kid` | the enrolled key id, omitted when `key_id` is blank |

The key must be PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`), Ed25519. OpenSSH and encrypted PEM files are rejected.

```rust
use std::path::PathBuf;
use trust_client::oidc::DeviceOidcConfig;
use trust_client::TrustClientBuilder;

let client = TrustClientBuilder::from_device_oidc(
    "https://trust.certlocker.io",
    DeviceOidcConfig::builder()
        .audience("https://trust.certlocker.io/oidc/<accountId>")
        .device_id("laptop-1")
        .private_key_path(PathBuf::from("/home/me/.trust/device.pem"))
        .key_id("device-abc123") // required when the principal enrolled a keyId
        .build()?,
)?;
```

A PEM string can be passed with `.private_key_pem(pem)` instead of a path. When both are set, the path is used. `.issuer(...)` and `.ttl_minutes(...)` override the defaults.

The same enrollment fields as a file path:

```rust
use trust_client::TrustClientBuilder;

let client = TrustClientBuilder::from_device_key_file(
    "https://trust.certlocker.io",
    "https://trust.certlocker.io/oidc/<accountId>",
    "laptop-1",
    "/home/me/.trust/device.pem",
    Some("device-abc123"),
)?;
```

Or mint the JWT yourself and exchange it. `pem` is the PKCS#8 text from the enroll download:

```rust
use trust_client::oidc;
use trust_client::TrustClientBuilder;

let audience = oidc::audience_for_account("<accountId>")?;
let jwt = oidc::mint_from_pem(&audience, "laptop-1", pem, Some("device-abc123"), 5)?;
let client = TrustClientBuilder::from_id_token("https://trust.certlocker.io", jwt)?;
```

`from_id_token` is also the entry point for any already-acquired workload JWT. The exchange response must include `accountId`.

`oidc::from_device` mints and exchanges without building a client, which is useful when you need `expires_at` or a non-default mint type:

```rust
use trust_client::model::TokenType;
use trust_client::oidc;

let exchanged = oidc::from_device("https://trust.certlocker.io", &config, Some(TokenType::Mcp))?;
```

### Exchange mint types: SECRET / CERTIFICATE / MCP

By default the Gateway uses the matched principal's `defaultTokenType` (typically `SECRET`). Pass a `TokenType` when the principal allows it. Only `Secret`, `Certificate`, and `Mcp` are accepted. `TokenType::is_oidc_mint_type` reports that. Anything else, such as `Root`, is rejected before the HTTP call.

```rust
use trust_client::model::TokenType;
use trust_client::oidc;
use trust_client::TrustClient;

let trust = "https://trust.certlocker.io";
let aud = "https://trust.certlocker.io/oidc/<accountId>";

let secret = oidc::from_github_actions(trust, aud, Some(TokenType::Secret))?;
let cert = oidc::from_gcp(trust, aud, Some(TokenType::Certificate))?;
let mcp = oidc::from_azure(trust, aud, Some(TokenType::Mcp))?;

let client = TrustClient::builder()
    .url(trust)
    .api_token(&secret.token_id)
    .account_id(secret.account_id.unwrap())
    .build()?;

assert_eq!(secret.token_type_enum(), Some(TokenType::Secret));
```

`None` leaves the mint type unset so the principal default is used. `from_ambient_oidc`, `from_device_oidc`, and `from_id_token` use that default.

The exchange is `POST {trustUrl}/rest/api/v1/oidc/exchange` with `{"idToken":"...","tokenType":"CERTIFICATE"}`. The request also includes `id_token` and (when set) `token_type` for the current Gateway snake_case mapper. Both mint-type spellings are omitted when the type is `None`. A 200 body with `errorMessage` set is a denial. `expiresAt` may be RFC 3339 or a UTC local datetime (`2026-11-01T12:00:00`).

### 2FA / access-code step-up

User-bound tokens may require an access code on Gateway calls. Configure a prompt on the builder. On HTTP 401, or when the response carries `x-access-response` (`ACCESS_CODE`, `OTP`, or `EMAIL`), the client shows the response body as the prompt, then retries the call once with `x-access-code`.

```rust
use trust_client::{console_auth_code_prompt, TrustClient};

let client = TrustClient::builder()
    .url("https://trust.certlocker.io")
    .account_id("<accountId>")
    .api_token("<user-bound-token>")
    .auth_code_prompt(console_auth_code_prompt)
    // or: .console_auth_code_prompt()
    // or: .auth_code_prompt(|reason| Ok(read_code_from_ui(reason)))
    .build()?;
```

`console_auth_code_prompt` prints `Trust {reason}: ` to stdout and reads one line from stdin. A blank line is an error.

You can also set a code before calling, which skips the prompt when the header is already present:

```rust
client.set_access_code("email-code-99");
```

A blank `set_access_code` clears the stored code. `prompt_for_access_code` runs the configured prompt immediately. Without a prompt, a 401 is returned as `TrustClientError::Trust`.

## Using TrustService

`TrustService` is the typed API. It owns a `TrustClient`. Closing the scope drops both.

Password and configuration secrets are the raw `fetch` body. PEM, credentials, and private key secrets are JSON in that body. `get_secret` / `get_certificate` / `get_token` parse the record JSON from `get`.

```rust
use trust_client::{TrustClient, TrustService};

fn main() -> Result<(), trust_client::TrustClientError> {
    let service = TrustService::from_builder(
        TrustClient::builder()
            .url("https://trust.certlocker.io")
            .account_id("<accountId>")
            .api_token("<token>"),
    )?;

    let secret = service.get_secret("mvusgvkv5")?;
    println!("{} {:?}", secret.name.unwrap_or_default(), secret.secret_type);

    let configuration = service.get_secret_as_configuration("mvusgvkv5")?;
    let pem = service.get_secret_as_pem("b5fqj6c8d")?;
    let password = service.get_secret_as_password("v5q7pspif")?;
    let credentials = service.get_secret_as_credentials("17bu1p62uq")?;
    let private_key = service.get_secret_as_private_key("k8m7c8pps")?;

    if pem.is_pq_ready() {
        println!("ed25519 key for {}", pem.username.unwrap_or_default());
    }

    let certificate = service.get_certificate("certificate-token-id")?;
    let pem_leaf = service.fetch_certificate("certificate-token-id")?;
    let bundle = service.fetch_certificate_bundle("certificate-token-id")?;

    let token = service.get_token("tokenId")?;
    println!("{:?} {}", token.token_type, token.is_active());

    let _ = (configuration, password, credentials, private_key, certificate, pem_leaf, bundle);
    Ok(())
}
```

An asset token is an `x-api-token` bound to one secret or one certificate. Trust already knows that asset, so the `*_assigned_*` methods send no id:

```rust
let contents = service.fetch_assigned_secret()?;
let secret = service.get_assigned_secret()?;
let password = service.get_assigned_secret_as_password()?;
let pem = service.fetch_assigned_certificate()?;
let bundle = service.fetch_assigned_certificate_bundle()?;
```

The low-level client returns response text. Pass `None` for the assigned asset:

```rust
let record_json = client.get_secret(Some("mvusgvkv5"))?;
let contents = client.fetch_secret(None)?;
let leaf = client.fetch_certificate(Some("certificate-token-id"))?;
let bundle = client.fetch_certificate_bundle(Some("certificate-token-id"))?;
let token_json = client.get_token("tokenId")?;
```

### Calls

| Method | HTTP | Body |
| --- | --- | --- |
| `get_secret` / `get_assigned_secret` | `GET /rest/api/v1/secret/{accountId}/get[/{id}]` | JSON `Secret` |
| `fetch_secret` / `fetch_assigned_secret` | `GET /rest/api/v1/secret/{accountId}/fetch[/{id}]` | raw contents |
| `get_secret_as_pem` | fetch, parsed | JSON `Pem` |
| `get_secret_as_private_key` | fetch, parsed | JSON `PrivateKey` |
| `get_secret_as_credentials` | fetch, parsed | JSON `Credentials` |
| `get_secret_as_password` | fetch | `Password { password }` is the body |
| `get_secret_as_configuration` | fetch | `Configuration { secret }` is the body |
| `get_certificate` | `GET /rest/api/v1/cert/{accountId}/get[/{id}]` | JSON `Certificate` |
| `fetch_certificate` | `GET /rest/api/v1/cert/{accountId}/fetch[/{id}]` | leaf PEM |
| `fetch_certificate_bundle` | `GET /rest/api/v1/cert/{accountId}/fetch-bundle[/{id}]` | PEM bundle |
| `get_token` | `GET /rest/api/v1/token/{accountId}/get/{id}` | JSON `Token` |

Each assigned method is the same path with no id segment. Ids are percent-encoded as path segments. Ordinary Trust ids (`mvusgvkv5`) are unchanged.

Requests send `x-api-token`, `content-type`, and `accept`. `get` uses `application/json`. `fetch` uses `text/plain`.

## Models

Records share asset fields: `id`, `account_id`, `name`, `description`, `status`, `groups`, `created_by`, `updated_by`, `date_created`, `date_updated`, `locked_by`, `date_locked`.

```rust
use trust_client::{AssetStatus, Secret, SecretType};

let secret = Secret::default();
assert!(!secret.is_locked());
assert!(!secret.is_active());
assert!(AssetStatus::Active.can_suspend());
assert!(AssetStatus::Suspended.can_resume());
assert!(AssetStatus::Expired.can_renew() && AssetStatus::Expired.can_rotate());
assert!(!AssetStatus::Revoked.can_revoke());
assert!(SecretType::Pem.has_algo());
assert!(!SecretType::Password.has_algo());
```

`Secret` also has `secret_type`, `secret`, and `version`.

`Pem` and `PrivateKey` have `key_algorithm` (`Rsa`, `Ecdsa`, `Ed25519`), `key_size`, and `key`. `Pem` also has `username`. `is_pq_ready()` is true for Ed25519. `Credentials` has `username` and `password`.

`Certificate` includes `primary_domain`, `san_domains`, `not_before`, `expires`, `serial_number`, fingerprints, issuer fields, and `cert_validation`. `CertificateValidation::description` returns `Domain Validated`, `Organization Validated`, `Extended Validation`, `Self Signed`, or `Unknown`.

`Token` includes `token_type`, `protocols`, `single_use`, `hosts`, `group_access`, `secret_id`, `cert_id`, `user_id`, and `percent_remaining`. `Protocol::is_ssh_family` is true for `Ssh` and `Sftp`.

`AssetType` names the kinds of asset Trust stores (`Host`, `Secret`, `Certificate`, `Token`, `Bastion`, and the rest). It is not required to read a secret.

Dates accept RFC 3339 (`2026-05-01T12:34:56.789Z`), a zone-less UTC datetime, a Jackson `LocalDateTime` array (`[2026,5,1,12,34,56]`), or epoch seconds / milliseconds. Empty lists deserialize as an empty `Vec`. A single JSON string deserializes as a one-element list. `null` and missing fields become `None`.

## HTTP client

The default connect timeout is 10 seconds (`DEFAULT_CONNECT_TIMEOUT`). Redirects are not followed. HTTP version is negotiated (HTTP/2 when the server offers it). Proxies follow `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`. The user agent is `trust-client/1.0.4`.

```rust
use std::time::Duration;
use trust_client::{HttpVersion, ProxyMode, Redirects, TrustClient};

let client = TrustClient::builder()
    .url("https://trust.certlocker.io")
    .account_id("<accountId>")
    .api_token("<token>")
    .connect_timeout(Duration::from_secs(10))
    .timeout(Duration::from_secs(30)) // optional overall request timeout
    .follow_redirects(Redirects::Normal) // up to 10; Always allows 20
    .http_version(HttpVersion::Http1) // or HttpVersion::Negotiate
    .proxy(ProxyMode::Direct) // or ProxyMode::Environment, or ProxyMode::All("http://proxy:8080".into())
    .build()?;
```

`Redirects::Normal` is the practical match for the JDK `HttpClient.Redirect.NORMAL` setting used against Trust, which stays on HTTPS.

Pass a finished `reqwest` client when you need a custom CA, cookies, or any other `reqwest` setting. That client is used as-is. The builder's timeout, redirect, and proxy methods are ignored once `http_client` is set. OIDC exchange still uses its own client (10 second connect, 30 second request timeout, redirects disabled), matching the Java client.

```rust
let http = reqwest::blocking::Client::builder()
    .connect_timeout(Duration::from_secs(5))
    .danger_accept_invalid_certs(false)
    .build()?;

let client = TrustClient::builder()
    .url("https://trust.certlocker.io")
    .account_id("<accountId>")
    .api_token("<token>")
    .http_client(http)
    .build()?;

let _pool = client.http_client();
```

`danger_accept_invalid_certs(true)` on the builder turns off TLS verification for a local Gateway. Leave it off for Trust. A private CA belongs on a custom `reqwest` client. `local_address` binds outbound connections to one local IP.

## Errors

Every call returns `Result<_, TrustClientError>`.

| Variant | When |
| --- | --- |
| `Config` | Missing or invalid URL, token, account id, audience, proxy URL, or device config |
| `Message` | OIDC or device JWT failed, the prompt was missing, or the JSON body could not be parsed |
| `Trust` | Gateway responded with a non-200 status. `trust_error()` is `Some` |
| `Request` | DNS, connect, timeout, or other I/O failure. The source error is attached |
| `Ambient` | Ambient OIDC failed and no static API token was set |

```rust
use trust_client::TrustClientError;

match service.get_secret("missing") {
    Ok(secret) => println!("{}", secret.id.unwrap_or_default()),
    Err(err) => {
        if let Some(trust_error) = err.trust_error() {
            eprintln!("HTTP {}: {}", trust_error.http_status, trust_error.error_message);
        } else {
            eprintln!("{err}");
        }
    }
}
```

Gateway error bodies are read from `x-body-type`:

- `certlocker.gateway.api.model.ErrorDTO` uses `error_message` (or camelCase `errorMessage`).
- `certlocker.core.exceptions.CLErrorException` uses `error.message`.
- Anything else uses the response body, or `Unknown error` when the body is blank.

`has_trust_error()` is true only for the `Trust` variant. The `Display` text of that variant is the Gateway message, which is what `TrustClientException.getMessage()` returns in the Java client.

## Layout

| Module | Role |
| --- | --- |
| `trust_client::TrustClient` / `TrustClientBuilder` | HTTP calls and sign-in |
| `trust_client::TrustService` | Typed get / fetch |
| `trust_client::model` | `Secret`, `Certificate`, `Token`, and the enums |
| `trust_client::oidc` | Ambient providers, device JWT minting, and `/oidc/exchange` |
| `trust_client::console_auth_code_prompt` | Stdin prompt for 2FA |

## Build and test

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

The tests cover URL validation, snake_case records, device JWT signing against the Trust dogfood Ed25519 key, OIDC exchange JSON, Gateway error bodies, redirect policy, a caller-supplied HTTP client, and the 2FA retry (`401` + `x-access-response`, then a second call with `x-access-code`). They do not call `trust.certlocker.io`.

## License

Licensed under GNU General Public License v3.0. See [LICENSE](LICENSE).

## Gateway rollout compatibility (2026-11-04)

Legacy Gateway URLs and the new account-scoped URLs are both supported. Select
the mode explicitly during rollout; authentication or authorization failures never
trigger a retry against the other mode. The account must belong to the token.

```rust
let client = TrustClient::builder()
    .url("https://trust.certlocker.io")
    .api_token(token)
    .legacy_api(true)
    .build()?;
```

Use `.account_id(account_id)` with the default mode for the new Gateway. Base URLs
omit `/rest`. Certificate methods take a CERTIFICATE access-token ID, not a
certificate asset ID; `None` uses the configured API token. `get_secret(None)`
resolves the assigned secret through token metadata and errors if unassigned.
OIDC exchange sends both snake_case/camelCase fields and accepts both responses.

Validation: `cargo test --locked` — 32 passed (19 unit, 10 integration, 3 doc);
`cargo clippy --all-targets --locked -- -D warnings` and `cargo fmt --all -- --check`
also pass. Both route modes and denied requests without fallback are covered.
Live legacy secret metadata, exact payload and token metadata passed against a
disposable Ansible-created fixture, revoked afterward. See
[live evidence](docs/live-gateway-verification.json).

For a read-only live check, securely supply `CERTLOCKER_TOKEN`, `TRUST_URL` without
`/rest`, `CERTLOCKER_API_MODE=legacy` or `account`, `CERTLOCKER_ACCOUNT_ID` for
account mode, `TRUST_SECRET_ID`, and `TRUST_EXPECTED_VALUE` for a synthetic fixture:

```bash
cargo run --locked --example smoke
```

Only assertion booleans are printed. Live new-Gateway/OIDC checks require the
enabled deployment and a corresponding identity; these were not claimed as live.
