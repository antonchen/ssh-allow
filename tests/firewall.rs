mod support;

use std::{fs, thread, time::Duration};

use support::{Firewall, IPV4, IPV6};

#[test]
fn loaded_rules_use_detected_ssh_ports() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.sshd_config("Port 2200\nPort 2222");

    // Act
    firewall.start(true, 30);
    let rules = firewall.nft(&["list", "table", "inet", "ssh_access"]);

    // Assert
    let mut matches = 0;
    for object in rules.as_array().unwrap() {
        if let Some(expressions) = object["rule"]["expr"].as_array() {
            for expression in expressions {
                if expression["match"]["left"]["payload"]["field"] == "dport" {
                    assert_eq!(
                        expression["match"]["right"],
                        serde_json::json!({ "set": [2200, 2222] })
                    );
                    matches += 1;
                }
            }
        }
    }
    assert_eq!(matches, 4);
}

#[test]
fn ipv4_whitelist_allows_ssh() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.network();
    firewall.start(false, 30);
    firewall.assert_connection(4, false);

    // Act
    let status = firewall.request(IPV4);

    // Assert
    assert_eq!(status, 204);
    firewall.assert_connection(4, true);
}

#[test]
fn ipv6_requires_opt_in() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.network();
    firewall.start(false, 30);
    assert_eq!(firewall.request(IPV6), 400);
    firewall.assert_connection(6, false);

    // Act
    firewall.start(true, 30);
    let status = firewall.request(IPV6);

    // Assert
    assert_eq!(status, 204);
    firewall.assert_connection(6, true);
}

#[test]
fn repeat_request_refreshes_timeout() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.start(false, 10);
    assert_eq!(firewall.request(IPV4), 204);
    thread::sleep(Duration::from_secs(2));
    let before = firewall.clients(4)[IPV4]["expires"].as_f64().unwrap();

    // Act
    let status = firewall.request(IPV4);

    // Assert
    assert_eq!(status, 204);
    let after = firewall.clients(4)[IPV4]["expires"].as_f64().unwrap();
    assert!(
        after > before + 1.0,
        "expiry did not refresh: {before} -> {after}"
    );
}

#[test]
fn expired_client_cannot_open_ssh() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.network();
    firewall.start(false, 3);
    assert_eq!(firewall.request(IPV4), 204);
    firewall.assert_connection(4, true);

    // Act
    thread::sleep(Duration::from_millis(3500));

    // Assert
    firewall.assert_connection(4, false);
}

#[test]
fn switching_ipv6_mode_changes_access() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.network();
    firewall.start(true, 30);
    assert_eq!(firewall.request(IPV6), 204);
    firewall.assert_connection(6, true);

    // Act
    firewall.start(false, 30);

    // Assert
    firewall.assert_connection(6, false);
}

#[test]
fn restart_preserves_whitelist() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.start(true, 30);
    assert_eq!(firewall.request(IPV4), 204);
    assert_eq!(firewall.request(IPV6), 204);

    // Act
    firewall.start(true, 30);

    // Assert
    assert!(firewall.clients(4).contains_key(IPV4));
    assert!(firewall.clients(6).contains_key(IPV6));
}

#[test]
fn nft_failure_returns_500_without_recreating_rules() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.start(false, 30);
    firewall.run(&["nft", "delete", "table", "inet", "ssh_access"]);

    // Act
    let status = firewall.request(IPV4);

    // Assert
    assert_eq!(status, 500);
    assert!(
        !firewall
            .nft(&["list", "tables"])
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["table"]["name"] == "ssh_access")
    );
}

#[test]
fn invalid_ip_returns_400_without_updating_whitelist() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.start(false, 30);

    // Act
    let status = firewall.request("not-an-ip");

    // Assert
    assert_eq!(status, 400);
    assert!(firewall.clients(4).is_empty());
}

#[test]
fn health_uuid_is_consumed_once_without_allowing_an_ip() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.start(false, 30);

    // Act
    let (status, token, no_store) = firewall.health_request(None);

    // Assert
    assert_eq!(status, 204);
    assert!(no_store);
    let token = token.expect("health endpoint did not return its UUID");
    assert_eq!(firewall.health_request(Some(&token)), (204, None, true));
    let (replay_status, replay_token, replay_no_store) = firewall.health_request(Some(&token));
    assert_eq!(replay_status, 204);
    assert!(replay_no_store);
    assert!(replay_token.is_some_and(|replay| replay != token));
    assert!(firewall.clients(4).is_empty());
}

#[test]
fn healthcheck_gates_restarted_policy_until_the_proxy_recovers() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.network();
    firewall.start(false, 30);
    assert_eq!(firewall.request("192.0.2.99"), 204);
    firewall.assert_connection(4, false);
    let (proxy_state, health_url) = firewall.health_proxy("failed");

    // Act
    firewall.start_with_healthcheck(false, 30, &health_url, 2);

    // Assert the old input hook cannot keep enforcing its stale policy.
    firewall.assert_connection(4, true);
    assert!(firewall.clients(4).contains_key("192.0.2.99"));

    fs::write(&proxy_state, "healthy").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !firewall.policy_rules_loaded() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        firewall.policy_rules_loaded(),
        "health recovery did not load policy rules: {}",
        firewall.log_contents()
    );
    firewall.assert_connection(4, false);
    assert_eq!(firewall.request(IPV4), 204);
    firewall.assert_connection(4, true);

    // A runtime outage is detected quickly, then recovery is retried.
    fs::write(&proxy_state, "failed").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while firewall.policy_hook_installed() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(250));
    }
    assert!(
        !firewall.policy_hook_installed(),
        "two failed checks kept the SSH policy active"
    );
    firewall.assert_connection(6, true);

    fs::write(&proxy_state, "healthy").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !firewall.policy_hook_installed() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        firewall.policy_hook_installed(),
        "health recovery did not restore the policy hook"
    );
    firewall.assert_connection(6, false);
}

#[test]
fn openssh_configured_ports_are_whitelisted() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.network();

    for config in ["Port 2222", "port 2222\nPort 2200\nPort 2222"] {
        firewall.sshd_config(config);

        // Act
        firewall.start(true, 30);

        // Assert
        for family in [4, 6] {
            firewall.assert_port(family, 2222, false);
            firewall.assert_port(family, 22, true);
            firewall.assert_port(family, 2200, !config.contains("2200"));
        }
        assert_eq!(firewall.request(IPV4), 204);
        assert_eq!(firewall.request(IPV6), 204);
        for family in [4, 6] {
            firewall.assert_port(family, 2222, true);
            firewall.assert_port(family, 2200, true);
        }
        firewall.run(&["nft", "delete", "table", "inet", "ssh_access"]);
    }
}

#[test]
fn dropbear_arguments_select_ssh_ports() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.network();
    firewall.dropbear(&["-p", "2222", "-p", "127.0.0.1:2200", "-p[::]:2222"]);

    // Act
    firewall.start(true, 30);

    // Assert
    for family in [4, 6] {
        firewall.assert_port(family, 22, true);
        firewall.assert_port(family, 2200, false);
        firewall.assert_port(family, 2222, false);
    }
    assert_eq!(firewall.request(IPV4), 204);
    assert_eq!(firewall.request(IPV6), 204);
    for family in [4, 6] {
        firewall.assert_port(family, 2200, true);
        firewall.assert_port(family, 2222, true);
    }
}

#[test]
fn missing_explicit_port_defaults_to_22() {
    // Arrange
    let mut firewall = Firewall::new();
    firewall.network();
    firewall.sshd_config("AddressFamily any");

    for dropbear in [false, true] {
        if dropbear {
            firewall.dropbear(&[]);
        }

        // Act
        firewall.start(true, 30);

        // Assert
        for family in [4, 6] {
            firewall.assert_port(family, 22, false);
            firewall.assert_port(family, 2222, true);
        }
        assert_eq!(firewall.request(IPV4), 204);
        assert_eq!(firewall.request(IPV6), 204);
        for family in [4, 6] {
            firewall.assert_port(family, 22, true);
        }
        firewall.run(&["nft", "delete", "table", "inet", "ssh_access"]);
    }
}
