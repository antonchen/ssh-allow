use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
};
use nftables::{
    helper::apply_ruleset_async,
    schema::{NfCmd, NfObject, Nftables},
    types::NfFamily,
};
use uuid::Uuid;

const HEALTH_HEADER: &str = "x-ssh-allow-health";

pub type Tokens = Arc<Mutex<HashMap<Uuid, Instant>>>;

pub fn health_state() -> Tokens {
    Arc::new(Mutex::new(HashMap::new()))
}

pub async fn health(
    State((_, _, tokens)): State<(u32, bool, Tokens)>,
    headers: HeaderMap,
) -> (StatusCode, HeaderMap) {
    let mut response = HeaderMap::new();
    response.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    if let Some(value) = headers
        .get(HEALTH_HEADER)
        .and_then(|value| value.to_str().ok())
        && let Ok(token) = Uuid::parse_str(value)
    {
        let mut tokens = tokens.lock().unwrap();
        tokens.retain(|_, expiry| *expiry > Instant::now());
        if tokens.remove(&token).is_some() {
            return (StatusCode::NO_CONTENT, response);
        }
    }
    let token = Uuid::new_v4();
    let mut tokens = tokens.lock().unwrap();
    tokens.retain(|_, expiry| *expiry > Instant::now());
    tokens.insert(token, Instant::now() + Duration::from_secs(10));
    response.insert(
        HEALTH_HEADER,
        HeaderValue::from_str(&token.to_string()).unwrap(),
    );
    (StatusCode::NO_CONTENT, response)
}

pub async fn healthcheck(
    client: reqwest::Client,
    url: reqwest::Url,
    tokens: Tokens,
    hook_rule: NfObject<'static>,
    check_interval: Duration,
) {
    let mut failures = 0;
    let mut policy_enabled = true;
    let mut next_check = check_interval;
    loop {
        tokio::time::sleep(next_check).await;
        next_check = check_interval;
        match check_health(&client, &url, &tokens).await {
            Ok(()) => {
                if failures != 0 {
                    eprintln!("Health check recovered");
                }
                failures = 0;
                if !policy_enabled {
                    match set_policy_enabled(true, &hook_rule).await {
                        Ok(()) => policy_enabled = true,
                        Err(error) => {
                            eprintln!("Failed to restore SSH rules: {error}");
                            next_check = Duration::from_secs(10);
                        }
                    }
                }
            }
            Err(error) => {
                if failures == 0 {
                    eprintln!("Health check failed: {error}");
                }
                failures = (failures + 1).min(2);
                next_check = Duration::from_secs(10);
                if failures >= 2 && policy_enabled {
                    match set_policy_enabled(false, &hook_rule).await {
                        Ok(()) => policy_enabled = false,
                        Err(error) => eprintln!("Failed to disable SSH rules: {error}"),
                    }
                }
            }
        }
    }
}

pub async fn check_health(
    client: &reqwest::Client,
    url: &reqwest::Url,
    tokens: &Tokens,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let response = client.get(url.clone()).send().await?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err("health endpoint returned non-204".into());
    }
    let token = response
        .headers()
        .get(HEALTH_HEADER)
        .ok_or("missing health UUID")?
        .to_str()?
        .parse::<Uuid>()?;
    let mut tokens = tokens.lock().unwrap();
    tokens.retain(|_, expiry| *expiry > Instant::now());
    if tokens.remove(&token).is_none() {
        return Err("health UUID was not issued by this instance".into());
    }
    Ok(())
}

async fn set_policy_enabled(enabled: bool, hook_rule: &NfObject<'_>) -> Result<(), Box<dyn Error>> {
    let objects = if enabled {
        match hook_rule {
            NfObject::CmdObject(NfCmd::Add(object)) => {
                vec![NfObject::CmdObject(NfCmd::Add(object.clone()))]
            }
            _ => return Err("embedded SSH policy hook is invalid".into()),
        }
    } else {
        vec![NfObject::CmdObject(NfCmd::Flush(
            nftables::schema::FlushObject::Chain(nftables::schema::Chain {
                family: NfFamily::INet,
                table: "ssh_access".into(),
                name: "input".into(),
                ..Default::default()
            }),
        ))]
    };
    let ruleset = Nftables {
        objects: objects.into(),
    };
    apply_ruleset_async(&ruleset).await?;
    Ok(())
}
