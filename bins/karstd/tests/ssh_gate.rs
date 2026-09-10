// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The independent SSH admission gate — `plans/phase-6/07-acl-gated-ssh.md`.
//!
//! §3.1: a connection reaches port 22 only if **both** the general ACL and
//! the "ssh" gate permit it — neither alone is enough, and this is the
//! property `acl_flows.rs` cannot exercise, since that file's daemons carry
//! no "ssh" gate at all. §3.2: an absent gate leaves today's ACL-only
//! behavior untouched; a present, empty one denies every connection. §3.4: a
//! revocation reaches the *next* connection attempt, not one already open and
//! carrying traffic.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use karst_control_client::transport::pb;
use karstd::config::{Config, Peer};
use karstd::engine::Engine;
use karstd::filter::{Direction, PacketFilter, SshFilter};
use karstd::routing::{AllowedIps, Prefix};

const CLIENT_IP: [u8; 4] = [100, 64, 0, 2];
const SERVER_IP: [u8; 4] = [100, 64, 0, 3];
const SSH: u16 = 22;
const EPHEMERAL: u16 = 54321;
const HANDLE: &str = "client-handle";

/// A TCP SYN-shaped packet with the ports the gate cares about.
fn tcp(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    let total = u16::try_from(p.len()).expect("small");
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[9] = 6; // TCP
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&src_port.to_be_bytes());
    p[22..24].copy_from_slice(&dst_port.to_be_bytes());
    p
}

fn request() -> Vec<u8> {
    tcp(CLIENT_IP, EPHEMERAL, SERVER_IP, SSH)
}

fn keys(byte: u8) -> Arc<karst_noise::handshake::StaticKeys> {
    Arc::new(karst_noise::handshake::StaticKeys::from_seed(&[byte; 64]))
}

/// The general ACL permitting `HANDLE` to reach port 22 — never enough on its
/// own once an "ssh" gate is present (§3.1).
fn acl_permitting_ssh() -> PacketFilter {
    let ports = vec![pb::KarstPortRange {
        first: u32::from(SSH),
        last: u32::from(SSH),
    }];
    PacketFilter::compile(
        &[pb::KarstFilterRule {
            srcs: vec![HANDLE.to_owned()],
            ports,
        }],
        &[],
        &[HANDLE.as_bytes().to_vec()],
    )
}

/// A general ACL that does not mention port 22 at all — reachability denied
/// before the SSH gate is ever consulted.
fn acl_denying_everything() -> PacketFilter {
    PacketFilter::compile(&[], &[], &[HANDLE.as_bytes().to_vec()])
}

/// An "ssh" block granting `HANDLE`.
fn ssh_granting() -> SshFilter {
    SshFilter::compile(
        &[pb::KarstFilterRule {
            srcs: vec![HANDLE.to_owned()],
            ports: vec![pb::KarstPortRange {
                first: u32::from(SSH),
                last: u32::from(SSH),
            }],
        }],
        true,
        &[HANDLE.as_bytes().to_vec()],
    )
}

/// `"ssh": []` — present, granting nobody.
fn ssh_deny_all() -> SshFilter {
    SshFilter::compile(&[], true, &[HANDLE.as_bytes().to_vec()])
}

/// The server: the one node whose ingress ACL and SSH gate matter here.
fn server(filter: PacketFilter, ssh_filter: SshFilter) -> Engine {
    Engine::new(&server_config(filter, ssh_filter))
}

fn server_config(filter: PacketFilter, ssh_filter: SshFilter) -> Arc<Config> {
    let peer_keys = keys(0x01);
    let prefix: Prefix = "100.64.0.2/32".parse().expect("peer prefix");
    Arc::new(Config {
        route_offers: Vec::new(),
        exit_node_state_file: None,
        keys: keys(0x02),
        listen: "0.0.0.0:0".parse().expect("listen"),
        port_mapping: true,
        interface: "karst-ssh-gate".to_owned(),
        network_mode: karstd::config::NetworkMode::Tun,
        dns: karstd::config::DnsSettings::default(),
        netmap_dns: karstd::netmap::DNSConfig::default(),
        userspace_socks5_listen: None,
        userspace_publish: Vec::new(),
        nat64: None,
        addresses: vec!["100.64.0.3/24".parse().expect("interface address")],
        psk_epoch: 1,
        node_id: Vec::new(),
        relays: Vec::new(),
        turn_servers: Vec::new(),
        relay_ca_file: None,
        metrics_listen: None,
        peers: vec![Peer {
            name: "client".to_owned(),
            node_id: Vec::new(),
            public: Arc::new(karst_noise::handshake::PeerPublic {
                kem_pk: peer_keys.kem_pk.clone(),
                psk: [0x77; 32],
            }),
            endpoint: Some("203.0.113.1:51820".parse().expect("endpoint")),
            allowed_ips: vec![prefix],
            psk_is_fallback: false,
            psk_previous: None,
            disco_key: None,
            home_relay: None,
        }],
        routes: AllowedIps::build(vec![(prefix, 0)]).expect("no conflicts"),
        skipped: Vec::new(),
        filter,
        ssh_filter,
    })
}

// ── §3.1: both gates must permit ────────────────────────────────────────────

/// Both gates grant it: the connection is admitted.
#[test]
fn granted_by_both_gates_is_admitted() {
    let s = server(acl_permitting_ssh(), ssh_granting());
    assert!(s.permits_for_test(Direction::In, 0, &request(), 1_000));
}

/// The general ACL permits reaching port 22, but the "ssh" block does not
/// name this principal. Reachability is not shell authorization (§2).
#[test]
fn acl_alone_does_not_grant_ssh() {
    let s = server(acl_permitting_ssh(), ssh_deny_all());
    assert!(
        !s.permits_for_test(Direction::In, 0, &request(), 1_000),
        "the acl grant alone was enough to reach ssh"
    );
}

/// The "ssh" block grants this principal, but the general ACL does not
/// permit the packet to reach port 22 at all — so the SSH gate is never
/// even consulted; the packet never reaches it (§6).
#[test]
fn ssh_alone_does_not_bypass_the_general_acl() {
    let s = server(acl_denying_everything(), ssh_granting());
    assert!(
        !s.permits_for_test(Direction::In, 0, &request(), 1_000),
        "an ssh grant reached a destination the general acl never permitted"
    );
}

// ── §3.2: absent vs. empty ───────────────────────────────────────────────────

/// No "ssh" block at all: SSH reachability is governed by the general ACL
/// alone, exactly as it was before this workstream.
#[test]
fn absent_ssh_gate_is_unaffected_by_this_workstream() {
    let s = server(acl_permitting_ssh(), SshFilter::absent());
    assert!(s.permits_for_test(Direction::In, 0, &request(), 1_000));
}

/// `"ssh": []` denies every SSH connection, even one the general ACL
/// permits — the opposite of absent, and the reason the two states must be
/// observably different (§3.2's whole argument).
#[test]
fn empty_ssh_gate_denies_everything_the_acl_would_otherwise_allow() {
    let s = server(acl_permitting_ssh(), ssh_deny_all());
    assert!(!s.permits_for_test(Direction::In, 0, &request(), 1_000));
}

// ── §3.4: revocation reaches the next connection, not the current one ──────

/// An admitted flow is not re-checked mid-stream: a policy change since the
/// flow was admitted must not tear it down. Only a genuinely new flow (here,
/// a fresh five-tuple) is checked against the updated gate.
#[test]
fn a_revocation_does_not_tear_down_an_already_admitted_flow() {
    let engine = Engine::new(&server_config(acl_permitting_ssh(), ssh_granting()));
    assert!(
        engine.permits_for_test(Direction::In, 0, &request(), 0),
        "the first packet of the granted flow was not admitted"
    );

    // The policy is revoked. Sessions, endpoints, and — deliberately, unlike
    // the general ACL's flow table — the SSH admission cache are all carried
    // across the reconfiguration (§3.4).
    engine.reconfigure(&server_config(acl_permitting_ssh(), ssh_deny_all()));

    assert!(
        engine.permits_for_test(Direction::In, 0, &request(), 1),
        "a revocation tore down a connection that was already admitted"
    );

    // But a genuinely new flow — a different client port, so a different
    // five-tuple — is checked against the now-revoked gate and refused.
    let new_flow = tcp(CLIENT_IP, EPHEMERAL + 1, SERVER_IP, SSH);
    assert!(
        !engine.permits_for_test(Direction::In, 0, &new_flow, 2),
        "a new connection attempt was admitted after the ssh rule was revoked"
    );
}

/// The mirror of the above: a newly granted rule reaches only new flows.
/// (Existing behavior for a flow that was never checked against the old gate
/// at all — there is nothing to "keep working" here, this just confirms the
/// gate applies going forward once reconfigured.)
#[test]
fn a_new_grant_reaches_a_new_connection_attempt() {
    let engine = Engine::new(&server_config(acl_permitting_ssh(), ssh_deny_all()));
    assert!(
        !engine.permits_for_test(Direction::In, 0, &request(), 0),
        "the gate granted access before the rule existed"
    );

    engine.reconfigure(&server_config(acl_permitting_ssh(), ssh_granting()));

    assert!(
        engine.permits_for_test(Direction::In, 0, &request(), 1),
        "the new grant did not reach the next connection attempt"
    );
}
