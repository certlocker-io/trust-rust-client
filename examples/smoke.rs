//! Read-only live smoke; prints booleans only. See README for environment inputs.
use std::env;
use trust_client::TrustClient;
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let token = env::var("CERTLOCKER_TOKEN")?;
    let secret_id = env::var("TRUST_SECRET_ID")?;
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
    let metadata: serde_json::Value = serde_json::from_str(&client.get_secret(Some(&secret_id))?)?;
    if metadata["id"] != secret_id {
        return Err("secret metadata mismatch".into());
    }
    if client.fetch_secret(Some(&secret_id))? != env::var("TRUST_EXPECTED_VALUE")? {
        return Err("value mismatch".into());
    }
    let metadata: serde_json::Value = serde_json::from_str(&client.get_token(&token)?)?;
    if metadata["id"] != token {
        return Err("token metadata mismatch".into());
    }
    println!("{{\"secret_metadata\":true,\"secret_value_matches\":true,\"token_metadata\":true}}");
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("Trust smoke failed; credential and response details suppressed");
        std::process::exit(1);
    }
}
