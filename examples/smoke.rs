//! Read-only live smoke; prints booleans only. See README for environment inputs.
use std::env;
use trust_client::TrustClient;
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let token = env::var("CERTLOCKER_TOKEN")?;
    let mut builder = TrustClient::builder()
        .url(env::var("TRUST_URL")?)
        .api_token(&token)
        .legacy_api(env::var("CERTLOCKER_API_MODE").as_deref() == Ok("legacy"));
    if let Ok(account) = env::var("CERTLOCKER_ACCOUNT_ID") {
        if !account.is_empty() {
            builder = builder.account_id(account);
        }
    }
    let client = builder.build()?;
    let mut proof = serde_json::Map::new();
    if let Some(cert_id) = env::var("TRUST_CERTIFICATE_ID")
        .ok()
        .filter(|value| !value.is_empty())
    {
        let metadata: serde_json::Value = serde_json::from_str(&client.get_certificate(None)?)?;
        if metadata["id"] != cert_id {
            return Err("certificate metadata mismatch".into());
        }
        if !client
            .fetch_certificate(None)?
            .contains("-----BEGIN CERTIFICATE-----")
        {
            return Err("certificate missing".into());
        }
        let bundle = client.fetch_certificate_bundle(None)?;
        if !bundle.contains("-----BEGIN CERTIFICATE-----") || !bundle.contains("PRIVATE KEY-----") {
            return Err("bundle missing".into());
        }
        for key in [
            "certificate_metadata",
            "certificate_pem",
            "certificate_bundle",
        ] {
            proof.insert(key.into(), true.into());
        }
    } else {
        let secret_id = env::var("TRUST_SECRET_ID")?;
        let metadata: serde_json::Value =
            serde_json::from_str(&client.get_secret(Some(&secret_id))?)?;
        if metadata["id"] != secret_id {
            return Err("secret metadata mismatch".into());
        }
        if client.fetch_secret(Some(&secret_id))? != env::var("TRUST_EXPECTED_VALUE")? {
            return Err("value mismatch".into());
        }
        proof.insert("secret_metadata".into(), true.into());
        proof.insert("secret_value_matches".into(), true.into());
    }
    let metadata: serde_json::Value = serde_json::from_str(&client.get_token(&token)?)?;
    if metadata["id"] != token {
        return Err("token metadata mismatch".into());
    }
    proof.insert("token_metadata".into(), true.into());
    println!("{}", serde_json::Value::Object(proof));
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("Trust smoke failed; credential and response details suppressed");
        std::process::exit(1);
    }
}
