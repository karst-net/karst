// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Receiver tests use Go-produced wire vectors, not a second fixture encoder.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::IpAddr;
use std::time::Duration;

use base64ct::Encoding;
use karst_control_client::compliance::{
    PendingPermitRequest, PermitContext, PermitError, Protocol,
};
use karst_control_client::transport::pb::KarstCompliancePermitSnapshot;
use prost::Message;

const HANDLE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const OTHER: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn wire(name: &str) -> KarstCompliancePermitSnapshot {
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spec/vectors/device-compliance-permits-v1.json"
    ))
    .unwrap();
    let case = file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    KarstCompliancePermitSnapshot::decode(
        hex::decode(case["hex"].as_str().unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap()
}
fn context() -> PermitContext {
    PermitContext {
        tenant_id: "tenant-a".into(),
        device_id: "device-a".into(),
        handle: HANDLE.into(),
        policy_revision: "revision-42".into(),
    }
}
fn nonce() -> [u8; 32] {
    std::array::from_fn(|i| u8::try_from(i).unwrap())
}
fn pending() -> PendingPermitRequest {
    let nonce = nonce();
    PendingPermitRequest::new(context(), nonce, Duration::from_secs(10)).unwrap()
}
fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

#[test]
fn go_snapshot_installs_and_transit_consumes_the_original_budget() {
    let request = pending();
    assert_eq!(request.request().schema_version, 1);
    assert_eq!(request.request().nonce.len(), 32);
    let mut installed = request
        .accept(&wire("permit-snapshot"), Duration::from_secs(50))
        .unwrap();
    for address in [ip("10.99.0.2"), ip("fd00:99::2")] {
        assert!(installed.ingress_satisfied(
            HANDLE,
            address,
            Protocol::Tcp,
            443,
            Duration::from_secs(50)
        ));
        assert!(installed.egress_satisfied(address, Protocol::Tcp, 443, Duration::from_secs(50)));
        assert!(!installed.ingress_satisfied(
            OTHER,
            address,
            Protocol::Tcp,
            443,
            Duration::from_secs(50)
        ));
    }
    assert!(installed.egress_satisfied(
        ip("10.99.0.2"),
        Protocol::Tcp,
        443,
        Duration::from_millis(128_999)
    ));
    // Deadline is request start 10s + source budget 119s, not receipt 50s + 119s.
    assert!(!installed.egress_satisfied(
        ip("10.99.0.2"),
        Protocol::Tcp,
        443,
        Duration::from_secs(129)
    ));
    assert!(installed.egress_satisfied(
        ip("100.64.0.4"),
        Protocol::Tcp,
        443,
        Duration::from_secs(129)
    ));
    assert!(!installed.egress_satisfied(
        ip("100.64.0.4"),
        Protocol::Tcp,
        443,
        Duration::from_secs(130)
    ));
}

#[test]
fn elapsed_expiry_rollback_and_suspended_time_cannot_renew() {
    assert_eq!(
        pending()
            .accept(&wire("permit-snapshot"), Duration::from_secs(130))
            .unwrap_err(),
        PermitError::Expired
    );
    assert_eq!(
        pending()
            .accept(&wire("permit-snapshot"), Duration::from_secs(9))
            .unwrap_err(),
        PermitError::ClockReversed
    );
    assert!(PendingPermitRequest::new(context(), nonce(), Duration::MAX)
        .unwrap()
        .accept(&wire("permit-snapshot"), Duration::MAX)
        .is_err());
    let mut installed = pending()
        .accept(&wire("permit-snapshot"), Duration::from_secs(50))
        .unwrap();
    assert!(!installed.egress_satisfied(
        ip("10.99.0.2"),
        Protocol::Tcp,
        443,
        Duration::from_secs(49)
    ));
    assert!(
        !installed.egress_satisfied(ip("10.99.0.2"), Protocol::Tcp, 443, Duration::from_secs(51)),
        "rollback latches invalidity"
    );
    let mut after_sleep = pending()
        .accept(&wire("permit-snapshot"), Duration::from_secs(50))
        .unwrap();
    // An injected suspend-aware clock jumps over the sleep interval.
    assert!(!after_sleep.egress_satisfied(
        ip("10.99.0.2"),
        Protocol::Tcp,
        443,
        Duration::from_secs(150)
    ));
    assert!(!after_sleep.egress_satisfied(
        ip("10.99.0.2"),
        Protocol::Tcp,
        443,
        Duration::from_secs(51)
    ));
}

#[test]
fn deny_gates_overlap_and_ungated_resources_remain_distinct() {
    let mut denied = pending()
        .accept(&wire("deny-snapshot"), Duration::from_secs(10))
        .unwrap();
    assert!(!denied.egress_satisfied(ip("10.99.0.2"), Protocol::Tcp, 443, Duration::from_secs(10)));
    assert!(denied.egress_satisfied(ip("10.99.1.2"), Protocol::Tcp, 443, Duration::from_secs(10)));
    assert!(denied.egress_satisfied(ip("10.99.0.2"), Protocol::Udp, 443, Duration::from_secs(10)));
    assert!(denied.egress_satisfied(ip("10.99.0.2"), Protocol::Tcp, 444, Duration::from_secs(10)));
    assert!(!denied.ingress_satisfied(
        "*",
        ip("100.64.0.4"),
        Protocol::Tcp,
        443,
        Duration::from_secs(10)
    ));
    let mut reply = wire("permit-snapshot");
    let mut extra = reply.ingress[0].clone();
    extra.guardrail_id = "stricter".into();
    extra.sources.clear();
    reply.ingress.push(extra);
    let mut overlap = pending().accept(&reply, Duration::from_secs(10)).unwrap();
    assert!(!overlap.ingress_satisfied(
        HANDLE,
        ip("10.99.0.2"),
        Protocol::Tcp,
        443,
        Duration::from_secs(10)
    ));
    let mut empty = wire("permit-snapshot");
    empty.ingress.clear();
    empty.egress.clear();
    let mut empty = pending().accept(&empty, Duration::from_secs(10)).unwrap();
    assert!(empty.egress_satisfied(ip("10.99.0.2"), Protocol::Tcp, 443, Duration::from_secs(10)));
    assert!(!empty.egress_satisfied(
        ip("10.99.0.2"),
        Protocol::Tcp,
        443,
        Duration::from_secs(130)
    ));
}

#[test]
fn malformed_or_substituted_candidates_are_rejected_as_a_whole() {
    type Change = fn(&mut KarstCompliancePermitSnapshot);
    let changes: &[(&str, Change)] = &[
        ("schema", |s| s.schema_version = 2),
        ("nonce", |s| s.request_nonce[0] ^= 1),
        ("tenant", |s| s.tenant_id = "foreign".into()),
        ("device", |s| s.enforcer_device_id = "other".into()),
        ("handle", |s| s.enforcer_handle = OTHER.into()),
        ("revision", |s| s.policy_revision = "old".into()),
        ("zero budget", |s| s.valid_for_millis = 0),
        ("oversized budget", |s| s.valid_for_millis = 120_001),
        ("missing guardrail", |s| s.ingress[0].guardrail_id.clear()),
        ("duplicate gate", |s| s.ingress.push(s.ingress[0].clone())),
        ("zero protocol", |s| s.ingress[0].protocol = 0),
        ("unknown protocol", |s| s.ingress[0].protocol = 99),
        ("missing ports", |s| s.ingress[0].ports = None),
        ("reversed ports", |s| {
            s.ingress[0].ports.as_mut().unwrap().first = 444;
        }),
        ("port overflow", |s| {
            s.ingress[0].ports.as_mut().unwrap().last = 65536;
        }),
        ("missing CIDRs", |s| s.ingress[0].destination_cidrs.clear()),
        ("duplicate CIDR", |s| {
            s.ingress[0].destination_cidrs.push("10.99.0.0/24".into());
        }),
        ("host bits", |s| {
            s.ingress[0].destination_cidrs = vec!["10.99.0.1/24".into()];
        }),
        ("mapped prefix", |s| {
            s.ingress[0].destination_cidrs = vec!["::ffff:10.99.0.0/120".into()];
        }),
        ("bad CIDR", |s| {
            s.ingress[0].destination_cidrs = vec!["bad".into()];
        }),
        ("overflow prefix", |s| {
            s.ingress[0].destination_cidrs = vec!["10.99.0.0/33".into()];
        }),
        ("IPv6 overflow", |s| {
            s.ingress[0].destination_cidrs = vec!["fd00::/129".into()];
        }),
        ("wildcard source", |s| {
            s.ingress[0].sources[0].handle = "*".into();
        }),
        ("missing source device", |s| {
            s.ingress[0].sources[0].device_id.clear();
        }),
        ("zero generation", |s| {
            s.ingress[0].sources[0].evidence_generation = 0;
        }),
        ("mixed generation", |s| {
            s.ingress[0].sources[0].evidence_generation += 1;
        }),
        ("zero source budget", |s| {
            s.ingress[0].sources[0].valid_for_millis = 0;
        }),
        ("long source budget", |s| {
            s.ingress[0].sources[0].valid_for_millis = 120_001;
        }),
        ("duplicate source", |s| {
            let duplicate = s.ingress[0].sources[0].clone();
            s.ingress[0].sources.push(duplicate);
        }),
        ("foreign egress", |s| {
            s.egress[0].sources[0].handle = OTHER.into();
            s.egress[0].sources[0].device_id = "other".into();
        }),
    ];
    for (name, change) in changes {
        let mut candidate = wire("permit-snapshot");
        change(&mut candidate);
        assert!(
            pending()
                .accept(&candidate, Duration::from_secs(10))
                .is_err(),
            "{name}"
        );
    }
}

#[test]
fn replaced_requests_and_policy_context_cannot_accept_old_responses() {
    let replaced =
        PendingPermitRequest::new(context(), [0x42; 32], Duration::from_secs(10)).unwrap();
    assert!(replaced
        .accept(&wire("permit-snapshot"), Duration::from_secs(10))
        .is_err());
    let mut changed = context();
    changed.policy_revision = "revision-43".into();
    let changed = PendingPermitRequest::new(changed, nonce(), Duration::from_secs(10)).unwrap();
    assert!(changed
        .accept(&wire("permit-snapshot"), Duration::from_secs(10))
        .is_err());
    let mut invalid = context();
    invalid.handle = "*".into();
    assert!(PendingPermitRequest::new(invalid, [0; 32], Duration::ZERO).is_err());
}

#[test]
fn default_routes_and_exact_host_prefixes_are_safe() {
    for prefix in ["0.0.0.0/0", "::/0", "10.99.0.2/32", "fd00:99::2/128"] {
        let mut reply = wire("deny-snapshot");
        reply.egress[0].destination_cidrs = vec![prefix.into()];
        let mut installed = pending().accept(&reply, Duration::from_secs(10)).unwrap();
        let address = if prefix.contains(':') {
            ip("fd00:99::2")
        } else {
            ip("10.99.0.2")
        };
        assert!(!installed.egress_satisfied(address, Protocol::Tcp, 443, Duration::from_secs(10)));
    }
}

#[test]
fn a_source_cannot_change_enrollment_or_handle_between_resources() {
    let mut reply = wire("permit-snapshot");
    reply.egress.clear();
    reply.ingress[0].sources[0].handle = OTHER.into();
    reply.ingress[0].sources[0].device_id = "device-b".into();
    let mut second = reply.ingress[0].clone();
    second.guardrail_id = "other-resource".into();
    reply.ingress.push(second);
    assert!(pending().accept(&reply, Duration::from_secs(10)).is_ok());
    reply.ingress[1].sources[0].device_id = "device-c".into();
    assert!(pending().accept(&reply, Duration::from_secs(10)).is_err());
    reply.ingress[1].sources[0].device_id = "device-b".into();
    reply.ingress[1].sources[0].handle = base64ct::Base64::encode_string(&[2; 32]);
    assert!(pending().accept(&reply, Duration::from_secs(10)).is_err());
}
