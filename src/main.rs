use std::{error::Error, fs::Permissions, os::unix::fs::PermissionsExt, time::Duration};

use axum::{Router, routing::get};
use nftables::helper::apply_ruleset_async;
use tokio::net::UnixListener;

mod allowlist;
mod health;
mod startup;

use health::{check_health, health, health_state, healthcheck};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(config) = startup::parse_args(std::env::args_os().skip(1))? else {
        return Ok(());
    };
    let startup::Config {
        socket,
        timeout,
        ipv6,
        healthcheck: healthcheck_config,
        healthcheck_interval,
    } = config;
    let ports = startup::ssh_ports()?;
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, Permissions::from_mode(0o666))?;
    let (initial_ruleset, input_ruleset, hook_rule) =
        startup::rulesets(timeout, ipv6, &ports, healthcheck_config.is_some())?;
    apply_ruleset_async(&initial_ruleset).await?;
    let tokens = health_state();
    eprintln!(
        "Listening on {}, SSH ports {ports:?}, timeout {timeout} seconds, IPv6 {}",
        socket.display(),
        if ipv6 { "enabled" } else { "disabled" }
    );

    let app = Router::new()
        .route("/", get(allowlist::allow))
        .route("/health", get(health))
        .with_state((timeout, ipv6, tokens.clone()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    if let Some((client, url)) = &healthcheck_config {
        let mut healthcheck_failed = false;
        loop {
            match check_health(client, url, &tokens).await {
                Ok(()) => {
                    if healthcheck_failed {
                        eprintln!("Initial health check recovered");
                    } else {
                        eprintln!("Initial health check succeeded");
                    }
                    break;
                }
                Err(error) => {
                    if !healthcheck_failed {
                        eprintln!(
                            "Initial health check failed: {error}; retrying every 10 seconds"
                        );
                        healthcheck_failed = true;
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        }
        apply_ruleset_async(&input_ruleset).await?;
    }
    if let Some((client, url)) = healthcheck_config {
        tokio::spawn(healthcheck(
            client,
            url,
            tokens,
            hook_rule,
            healthcheck_interval,
        ));
    }
    server.await??;
    Ok(())
}
