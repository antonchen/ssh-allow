use std::net::IpAddr;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
};
use nftables::{
    batch::Batch,
    expr::{Elem, Expression, NamedExpression},
    helper::apply_ruleset_async,
    schema::{Element, NfListObject},
    types::NfFamily,
};

use crate::health::Tokens;

pub async fn allow(
    State((timeout, ipv6, _)): State<(u32, bool, Tokens)>,
    headers: HeaderMap,
) -> StatusCode {
    let Some(ip) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<IpAddr>().ok())
    else {
        return StatusCode::BAD_REQUEST;
    };
    let name = match ip {
        IpAddr::V4(_) => "ssh_clients_v4",
        IpAddr::V6(_) if ipv6 => "ssh_clients_v6",
        IpAddr::V6(_) => return StatusCode::BAD_REQUEST,
    };

    let element = Element {
        family: NfFamily::INet,
        table: "ssh_access".into(),
        name: name.into(),
        elem: vec![Expression::String(ip.to_string().into())].into(),
    };
    let mut batch = Batch::new();
    // Ensure existence, then recreate atomically to refresh an existing timeout.
    batch.add(NfListObject::Element(element.clone()));
    batch.delete(NfListObject::Element(element));
    batch.add(NfListObject::Element(Element {
        family: NfFamily::INet,
        table: "ssh_access".into(),
        name: name.into(),
        elem: vec![Expression::Named(NamedExpression::Elem(Elem {
            val: Box::new(Expression::String(ip.to_string().into())),
            timeout: Some(timeout),
            ..Default::default()
        }))]
        .into(),
    }));

    match apply_ruleset_async(&batch.to_nftables()).await {
        Ok(()) => {
            eprintln!("Allowed SSH from {ip} for {timeout} seconds");
            StatusCode::NO_CONTENT
        }
        Err(error) => {
            eprintln!("Failed to allow {ip}: {error:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
