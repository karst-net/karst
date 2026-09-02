// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Cross-implementation vectors for KARST-CONTROL v1.
//!
//! `spec/vectors/karst-control-v1.json` is generated from the **Go server's own
//! code**, not from a second implementation of the spec — a vector produced by
//! a reimplementation proves only that the reimplementation agrees with itself.
//!
//! Every failure here is a place where the Go server and this crate would
//! disagree by a byte at runtime, producing a handshake that never completes
//! and no diagnostic to explain why.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use karst_control_client::{
    channel::{derive_keys, hello_signing_input, init_signing_input, Record, KEY_LEN},
    handle::handle,
    netmap::{
        netmap_version, peer_digest, BedrockHeadView, DNSConfigView, DNSRouteView, FilterRuleView,
        NetmapContent, PeerEntry, RelayView,
    },
    psk::{pair, PSK_LEN},
};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    spec: String,
    cases: Cases,
}

#[derive(Deserialize)]
struct Cases {
    hello_signing_input: Vec<HelloSig>,
    init_signing_input: Vec<InitSig>,
    derive_keys: Vec<Derive>,
    seal: Vec<Seal>,
    handle: Vec<Handle>,
    psk: Vec<PskCase>,
    peer_digest: Vec<DigestCase>,
    netmap_version: Vec<VersionCase>,
}

#[derive(Deserialize, Debug, Clone)]
struct VersionCase {
    psk_epoch: u32,
    node_id: String,
    dns_name: String,
    addresses: Option<Vec<String>>,
    peers: Option<Vec<VersionPeer>>,
    packet_filter: Option<Vec<VersionRule>>,
    egress_filter: Option<Vec<VersionRule>>,
    #[serde(default)]
    relays: Option<Vec<VersionRelay>>,
    #[serde(default)]
    dns: VersionDNS,
    #[serde(default)]
    bedrock: VersionBedrock,
    version: u64,
}

/// The Bedrock log tip as the version hash sees it — `bedrock-v1.md` §5.
#[derive(Deserialize, Debug, Clone, Default)]
struct VersionBedrock {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    mode: u32,
}

#[derive(Deserialize, Debug, Clone, Default)]
struct VersionDNS {
    #[serde(default)]
    nameservers: Vec<String>,
    #[serde(default)]
    search_domains: Vec<String>,
    #[serde(default)]
    routes: Vec<VersionDNSRoute>,
    #[serde(default)]
    zone: String,
    #[serde(default)]
    magic_dns: bool,
}

#[derive(Deserialize, Debug, Clone)]
struct VersionDNSRoute {
    match_domain: String,
    resolvers: Vec<String>,
}

/// The relay registry, as the version hash sees it.
///
/// The `karst-relays` term has been hashed by both ends since 2026-08-18 and no
/// vector carried a relay until 2026-08-21, because until then no production
/// server ever populated the field — the only code that did was the Go test
/// server (GitHub issue [#48](https://github.com/karst-net/karst/issues/48)). A drift here is not a degraded relay: this node
/// recomputes the version over what it assembled and refuses a netmap that
/// disagrees, so **no netmap would ever apply**.
#[derive(Deserialize, Debug, Clone)]
struct VersionRelay {
    address: String,
    tls_server_name: String,
    relay_id: String,
    identity_key: String,
    region: String,
}

#[derive(Deserialize, Debug, Clone)]
struct VersionPeer {
    node_id: String,
    kem_public_key: String,
    dh_public_key: String,
    dns_name: String,
    endpoint: String,
    allowed_ips: Option<Vec<String>>,
    /// Carried by the vector but *not* hashed — see
    /// `the_version_ignores_the_psk_bytes`.
    psk: String,
    #[serde(default)]
    home_relay: String,
}

#[derive(Deserialize, Debug, Clone)]
struct VersionRule {
    srcs: Option<Vec<String>>,
    ports: Option<Vec<VersionPortRange>>,
}

#[derive(Deserialize, Debug, Clone)]
struct VersionPortRange {
    first: u32,
    last: u32,
}

#[derive(Deserialize)]
struct DigestCase {
    epoch: u32,
    node_id: String,
    kem_public_key: String,
    dh_public_key: String,
    dns_name: String,
    endpoint: String,
    #[serde(default)]
    home_relay: String,
    allowed_ips: Option<Vec<String>>,
    digest: u64,
}

#[derive(Deserialize)]
struct HelloSig {
    server_random: String,
    eph_kem_pk: String,
    expected: String,
}

#[derive(Deserialize)]
struct InitSig {
    server_random: String,
    ct_static: String,
    ct_eph: String,
    node_id: String,
    expected: String,
}

#[derive(Deserialize)]
struct Derive {
    ss_static: String,
    ss_eph: String,
    server_random: String,
    ct_static: String,
    ct_eph: String,
    key_c2s: String,
    key_s2c: String,
}

#[derive(Deserialize)]
struct Seal {
    key: String,
    node_id: String,
    seq: u64,
    plaintext: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct Handle {
    identity_pk: String,
    handle: String,
}

#[derive(Deserialize)]
struct PskCase {
    master: String,
    a: String,
    b: String,
    epoch: u32,
    psk: String,
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("vector field is not valid hex")
}

fn vectors() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/karst-control-v1.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e} (regenerate on the Go side)"));
    serde_json::from_str(&raw).expect("vector file is not valid JSON")
}

#[test]
fn vector_file_is_the_expected_spec() {
    assert_eq!(vectors().spec, "KARST-CONTROL v1");
}

#[test]
fn hello_signing_input_matches() {
    for (i, c) in vectors().cases.hello_signing_input.iter().enumerate() {
        let got = hello_signing_input(&unhex(&c.server_random), &unhex(&c.eph_kem_pk));
        assert_eq!(
            hex::encode(got),
            c.expected,
            "hello_signing_input case {i} disagrees with the Go server"
        );
    }
}

/// One case carries an empty `node_id` — the registration case. An
/// implementation that omits the field rather than writing a zero-length
/// prefix agrees on every other vector and fails only on this one.
#[test]
fn init_signing_input_matches() {
    let v = vectors();
    assert!(
        v.cases
            .init_signing_input
            .iter()
            .any(|c| c.node_id.is_empty()),
        "vectors no longer cover the empty node_id case"
    );
    for (i, c) in v.cases.init_signing_input.iter().enumerate() {
        let got = init_signing_input(
            &unhex(&c.server_random),
            &unhex(&c.ct_static),
            &unhex(&c.ct_eph),
            &unhex(&c.node_id),
        );
        assert_eq!(
            hex::encode(got),
            c.expected,
            "init_signing_input case {i} disagrees with the Go server"
        );
    }
}

#[test]
fn key_schedule_matches() {
    for (i, c) in vectors().cases.derive_keys.iter().enumerate() {
        let keys = derive_keys(
            &unhex(&c.ss_static),
            &unhex(&c.ss_eph),
            &unhex(&c.server_random),
            &unhex(&c.ct_static),
            &unhex(&c.ct_eph),
        )
        .expect("derive");
        assert_eq!(hex::encode(keys.c2s), c.key_c2s, "c2s key, case {i}");
        assert_eq!(hex::encode(keys.s2c), c.key_s2c, "s2c key, case {i}");
        assert_ne!(
            keys.c2s, keys.s2c,
            "case {i}: the two directions share a key"
        );
    }
}

#[test]
fn record_layer_matches() {
    for (i, c) in vectors().cases.seal.iter().enumerate() {
        let key: [u8; KEY_LEN] = unhex(&c.key).try_into().expect("key length");
        let got = Record::seal_at(&key, &unhex(&c.node_id), c.seq, &unhex(&c.plaintext));
        assert_eq!(
            hex::encode(&got),
            c.ciphertext,
            "seal case {i} disagrees with the Go server"
        );

        // And the round trip: what Go sealed, this crate opens.
        let mut r = Record::new(&key);
        let opened = r
            .open(&unhex(&c.node_id), c.seq, &unhex(&c.ciphertext))
            .expect("open a Go-sealed envelope");
        assert_eq!(hex::encode(opened), c.plaintext, "open case {i}");
    }
}

#[test]
fn handle_derivation_matches() {
    for (i, c) in vectors().cases.handle.iter().enumerate() {
        let got = handle(&unhex(&c.identity_pk));
        assert_eq!(
            got, c.handle,
            "handle case {i} disagrees with the Go server"
        );
        assert_eq!(got.len(), 44, "handle must be 44 characters");
    }
}

#[test]
fn psk_derivation_matches() {
    for (i, c) in vectors().cases.psk.iter().enumerate() {
        let master: [u8; PSK_LEN] = unhex(&c.master).try_into().expect("master length");
        let got = pair(&master, &c.a, &c.b, c.epoch).expect("derive psk");
        assert_eq!(
            hex::encode(got.as_bytes()),
            c.psk,
            "psk case {i} ({}, {}, epoch {}) disagrees with the Go server",
            c.a,
            c.b,
            c.epoch
        );
    }
}

/// The two properties the PSK scheme rests on, asserted against the vectors
/// rather than only against this implementation: swapping the pair must not
/// change the key, and length prefixing must keep `("ab","c")` distinct from
/// `("a","bc")`.
#[test]
fn psk_vectors_capture_symmetry_and_prefixing() {
    let v = vectors();
    let find = |a: &str, b: &str, epoch: u32| -> Option<String> {
        v.cases
            .psk
            .iter()
            .find(|c| c.a == a && c.b == b && c.epoch == epoch)
            .map(|c| c.psk.clone())
    };

    let ab = find("alice", "bob", 1).expect("vector (alice,bob,1)");
    let ba = find("bob", "alice", 1).expect("vector (bob,alice,1)");
    assert_eq!(
        ab, ba,
        "psk(A,B) != psk(B,A): the two ends would never agree"
    );

    let e2 = find("alice", "bob", 2).expect("vector (alice,bob,2)");
    assert_ne!(
        ab, e2,
        "the epoch does not change the key, so rotation is a no-op"
    );

    let x = find("ab", "c", 1).expect("vector (ab,c,1)");
    let y = find("a", "bc", 1).expect("vector (a,bc,1)");
    assert_ne!(
        x, y,
        "ambiguous concatenation: two different pairs share a PSK"
    );
}

/// Replay and forgery behave the same way on both sides.
#[test]
fn record_layer_rejects_replay_and_forgery() {
    let c = &vectors().cases.seal[0];
    let key: [u8; KEY_LEN] = unhex(&c.key).try_into().expect("key length");
    let node_id = unhex(&c.node_id);
    let ct = unhex(&c.ciphertext);

    let mut r = Record::new(&key);
    r.open(&node_id, c.seq, &ct).expect("first open");
    assert_eq!(
        r.open(&node_id, c.seq, &ct),
        Err(karst_control_client::channel::Error::Replay),
        "a replayed sequence number was accepted"
    );

    // node_id is cleartext, so it must be bound to the ciphertext.
    let mut r = Record::new(&key);
    assert_eq!(
        r.open(b"another-node", c.seq, &ct),
        Err(karst_control_client::channel::Error::Decrypt),
        "the node_id was not bound to the ciphertext"
    );
}

/// Delta push depends on both ends computing this identically. If they drift,
/// the server keeps resending entries the node already has — or, worse, never
/// sends a change because both sides believe it already arrived.
#[test]
fn peer_digest_matches() {
    for (i, c) in vectors().cases.peer_digest.iter().enumerate() {
        let ips = c.allowed_ips.clone().unwrap_or_default();
        let entry = PeerEntry {
            node_id: &unhex(&c.node_id),
            kem_public_key: &unhex(&c.kem_public_key),
            dh_public_key: &unhex(&c.dh_public_key),
            dns_name: &c.dns_name,
            endpoint: &c.endpoint,
            home_relay: &unhex(&c.home_relay),
            allowed_ips: &ips,
        };
        assert_eq!(
            peer_digest(&entry, c.epoch),
            c.digest,
            "peer_digest case {i} disagrees with the Go server"
        );
    }
}

/// The epoch must be part of the digest, or a PSK rotation would leave every
/// digest unchanged and every node holding a stale key.
#[test]
fn peer_digest_covers_the_epoch() {
    let v = vectors();
    let by_epoch: Vec<_> = v
        .cases
        .peer_digest
        .iter()
        .filter(|c| c.node_id == hex::encode("node-one") && c.dns_name == "alpha")
        .collect();
    assert!(
        by_epoch.len() >= 2,
        "vectors no longer cover the same peer at two epochs"
    );
    assert_ne!(
        by_epoch[0].digest,
        by_epoch[by_epoch.len() - 1].digest,
        "the epoch does not affect the digest, so a rotation would go unnoticed"
    );
}

// ── the netmap version ──────────────────────────────────────────────────────

/// Build the borrowed view a version case describes.
///
/// Returns the owned backing store alongside it, because `NetmapContent`
/// borrows everything and the decoded hex has to outlive the call.
struct VersionInputs {
    ids: Vec<Vec<u8>>,
    kems: Vec<Vec<u8>>,
    dhs: Vec<Vec<u8>>,
    homes: Vec<Vec<u8>>,
    ips: Vec<Vec<String>>,
    ports: Vec<Vec<(u32, u32)>>,
    egress_ports: Vec<Vec<(u32, u32)>>,
    node_id: Vec<u8>,
    addresses: Vec<String>,
    relay_ids: Vec<Vec<u8>>,
    relay_keys: Vec<Vec<u8>>,
}

/// Inclusive port ranges out of a rule list.
fn port_ranges(rules: &[VersionRule]) -> Vec<Vec<(u32, u32)>> {
    rules
        .iter()
        .map(|r| {
            r.ports
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|p| (p.first, p.last))
                .collect()
        })
        .collect()
}

/// Node handles out of a rule list.
fn rule_nodes(rules: &[VersionRule]) -> Vec<Vec<String>> {
    rules
        .iter()
        .map(|r| r.srcs.clone().unwrap_or_default())
        .collect()
}

fn inputs(c: &VersionCase) -> VersionInputs {
    let peers = c.peers.as_deref().unwrap_or_default();
    VersionInputs {
        ids: peers.iter().map(|p| unhex(&p.node_id)).collect(),
        kems: peers.iter().map(|p| unhex(&p.kem_public_key)).collect(),
        dhs: peers.iter().map(|p| unhex(&p.dh_public_key)).collect(),
        homes: peers.iter().map(|p| unhex(&p.home_relay)).collect(),
        ips: peers
            .iter()
            .map(|p| p.allowed_ips.clone().unwrap_or_default())
            .collect(),
        ports: port_ranges(c.packet_filter.as_deref().unwrap_or_default()),
        egress_ports: port_ranges(c.egress_filter.as_deref().unwrap_or_default()),
        node_id: unhex(&c.node_id),
        addresses: c.addresses.clone().unwrap_or_default(),
        relay_ids: relays_of(c).iter().map(|r| unhex(&r.relay_id)).collect(),
        relay_keys: relays_of(c)
            .iter()
            .map(|r| unhex(&r.identity_key))
            .collect(),
    }
}

fn relays_of(c: &VersionCase) -> &[VersionRelay] {
    c.relays.as_deref().unwrap_or_default()
}

fn version_of(c: &VersionCase, held: &VersionInputs) -> u64 {
    let wire = c.peers.as_deref().unwrap_or_default();
    let entries: Vec<PeerEntry<'_>> = wire
        .iter()
        .enumerate()
        .map(|(i, p)| PeerEntry {
            node_id: &held.ids[i],
            kem_public_key: &held.kems[i],
            dh_public_key: &held.dhs[i],
            dns_name: &p.dns_name,
            endpoint: &p.endpoint,
            home_relay: &held.homes[i],
            allowed_ips: &held.ips[i],
        })
        .collect();
    let inbound_nodes = rule_nodes(c.packet_filter.as_deref().unwrap_or_default());
    let outbound_nodes = rule_nodes(c.egress_filter.as_deref().unwrap_or_default());
    let rules: Vec<FilterRuleView<'_>> = inbound_nodes
        .iter()
        .zip(held.ports.iter())
        .map(|(nodes, ports)| FilterRuleView { nodes, ports })
        .collect();
    let egress: Vec<FilterRuleView<'_>> = outbound_nodes
        .iter()
        .zip(held.egress_ports.iter())
        .map(|(nodes, ports)| FilterRuleView { nodes, ports })
        .collect();

    let relays: Vec<RelayView<'_>> = relays_of(c)
        .iter()
        .enumerate()
        .map(|(i, r)| RelayView {
            address: &r.address,
            tls_server_name: &r.tls_server_name,
            relay_id: &held.relay_ids[i],
            identity_key: &held.relay_keys[i],
            region: &r.region,
        })
        .collect();

    let dns_routes: Vec<DNSRouteView<'_>> = c
        .dns
        .routes
        .iter()
        .map(|route| DNSRouteView {
            match_domain: &route.match_domain,
            resolvers: &route.resolvers,
        })
        .collect();

    let bedrock_hash = unhex(&c.bedrock.hash);

    netmap_version(&NetmapContent {
        psk_epoch: c.psk_epoch,
        node_id: &held.node_id,
        dns_name: &c.dns_name,
        addresses: &held.addresses,
        peers: &entries,
        packet_filter: &rules,
        egress_filter: &egress,
        relays: &relays,
        dns: DNSConfigView {
            nameservers: &c.dns.nameservers,
            search_domains: &c.dns.search_domains,
            routes: &dns_routes,
            zone: &c.dns.zone,
            magic_dns: c.dns.magic_dns,
        },
        bedrock_head: BedrockHeadView {
            hash: &bedrock_hash,
            seq: c.bedrock.seq,
            mode: c.bedrock.mode,
        },
    })
}

/// A node checks its assembled netmap against the version the server reported.
/// If the two implementations drift, **every** netmap is refused — so this
/// failing is the difference between a node that works and one that never
/// gets past its first fetch.
#[test]
fn netmap_version_matches() {
    for (i, c) in vectors().cases.netmap_version.iter().enumerate() {
        let held = inputs(c);
        assert_eq!(
            version_of(c, &held),
            c.version,
            "netmap_version case {i} disagrees with the Go server"
        );
    }
}

/// A relay's id is a digest of its pinned identity key — `ponor-v1.md` §5.2.
///
/// Both ends derive it independently: the Go server when it compiles a registry
/// (`karst/relayreg`), and `karstd` while decoding the netmap, which rejects the
/// **entire netmap** when the two disagree rather than skipping the entry. The
/// relation is checked here against fixtures the Go side produced, so a changed
/// domain label is caught by a test rather than by every node in a deployment
/// failing to apply a netmap it just authenticated.
#[test]
fn a_relay_id_is_the_digest_of_its_identity_key() {
    use sha2::{Digest as _, Sha256};

    let mut checked = 0_usize;
    for c in &vectors().cases.netmap_version {
        for r in relays_of(c) {
            let key = unhex(&r.identity_key);
            assert_eq!(
                key.len(),
                2592,
                "the vector's identity key is not an ML-DSA-87 public key"
            );
            let mut h = Sha256::new();
            h.update(b"karst-relay-id-v1");
            h.update(&key);
            assert_eq!(
                unhex(&r.relay_id),
                h.finalize().as_slice(),
                "relay_id is not SHA-256(\"karst-relay-id-v1\" || identity_key); \
                 karstd would refuse every netmap carrying this registry"
            );
            checked += 1;
        }
    }
    // Guards against the quiet failure: a renamed field deserializes to no
    // relays at all, and a loop over nothing passes every assertion in it.
    assert!(
        checked >= 4,
        "only {checked} relay entries in the vector; the cases carrying \
         registries did not deserialize"
    );
}

/// The version is sent in clear, so it must not be a function of the PSKs. Two
/// vector cases differ only in their PSK bytes and must hash identically.
#[test]
fn the_version_ignores_the_psk_bytes() {
    let v = vectors();
    let mut by_content: std::collections::HashMap<String, Vec<&VersionCase>> =
        std::collections::HashMap::new();
    for c in &v.cases.netmap_version {
        // Everything the hash covers, as a key. Built by blanking the PSK on a
        // clone rather than by listing the fields that matter: a key written
        // out by hand silently stops distinguishing whatever field is added
        // next, and this test then measures that field instead of the PSK.
        let mut key_case = c.clone();
        for p in key_case.peers.iter_mut().flatten() {
            p.psk = String::new();
        }
        key_case.version = 0;
        let key = format!("{key_case:?}");
        by_content.entry(key).or_default().push(c);
    }

    let pairs: Vec<_> = by_content
        .values()
        .filter(|group| group.len() >= 2)
        .collect();
    assert!(
        !pairs.is_empty(),
        "vectors no longer cover two netmaps differing only by PSK"
    );
    for group in pairs {
        let distinct: std::collections::HashSet<&str> = group
            .iter()
            .flat_map(|c| c.peers.as_deref().unwrap_or_default())
            .map(|p| p.psk.as_str())
            .collect();
        assert!(distinct.len() >= 2, "the two cases carry the same PSK");
        for w in group.windows(2) {
            assert_eq!(
                w[0].version, w[1].version,
                "the version changed with the PSK bytes, which are sent in clear"
            );
        }
    }
}

/// A policy edit changes nothing else about a netmap. If the filter were not
/// hashed, every node would be told "unchanged" and the new rules would never
/// arrive — a policy edit that appears to apply and does not.
#[test]
fn the_version_covers_the_packet_filter() {
    let v = vectors();
    let filtered = v
        .cases
        .netmap_version
        .iter()
        .find(|c| !c.packet_filter.as_deref().unwrap_or_default().is_empty())
        .expect("vectors no longer cover a netmap with a packet filter");
    let unfiltered = v
        .cases
        .netmap_version
        .iter()
        .find(|c| {
            c.packet_filter.as_deref().unwrap_or_default().is_empty()
                && c.node_id == filtered.node_id
                && c.peers.as_deref().unwrap_or_default().len()
                    == filtered.peers.as_deref().unwrap_or_default().len()
                && !c.peers.as_deref().unwrap_or_default().is_empty()
        })
        .expect("vectors no longer cover the same netmap without a filter");

    assert_ne!(
        filtered.version, unfiltered.version,
        "adding a rule left the version unchanged, so a policy edit would never be delivered"
    );
}

/// **The reason the hash has a separator between the two rule lists.** Moving
/// a rule from "who may reach me" to "whom may I reach" inverts a policy. If
/// the two lists were concatenated, the byte stream would be identical, the
/// version would not move, every node would be told "unchanged", and the
/// inversion would never be delivered.
#[test]
fn the_version_distinguishes_the_two_directions() {
    let v = vectors();
    let inbound = v
        .cases
        .netmap_version
        .iter()
        .find(|c| !c.packet_filter.as_deref().unwrap_or_default().is_empty())
        .expect("vectors no longer cover an inbound rule");
    let outbound = v
        .cases
        .netmap_version
        .iter()
        .find(|c| !c.egress_filter.as_deref().unwrap_or_default().is_empty())
        .expect("vectors no longer cover an outbound rule");

    // Same rule, same ports, opposite direction.
    assert_eq!(
        rule_nodes(inbound.packet_filter.as_deref().unwrap_or_default()),
        rule_nodes(outbound.egress_filter.as_deref().unwrap_or_default()),
        "vectors no longer carry the same rule in both directions"
    );
    assert_ne!(
        inbound.version, outbound.version,
        "the two directions hash identically, so inverting a policy would go undelivered"
    );
}

/// A Bedrock log that advances changes nothing else about a netmap. If the head
/// were not hashed, the server would answer `unchanged` and every node would go
/// on enforcing against coverage that had since moved — a fail-closed mechanism
/// making stale decisions with nothing anywhere saying so.
#[test]
fn the_version_covers_the_bedrock_head() {
    let v = vectors();
    // Same mode, so this compares sequences and nothing else — the enforcing
    // case is the subject of `the_version_covers_the_bedrock_mode` instead.
    let heads: Vec<&VersionCase> = v
        .cases
        .netmap_version
        .iter()
        .filter(|c| c.bedrock.seq != 0 && c.bedrock.mode == 0)
        .collect();
    assert!(
        heads.len() >= 2,
        "vectors no longer cover two Bedrock heads at the same mode"
    );

    let none = v
        .cases
        .netmap_version
        .iter()
        .find(|c| {
            c.bedrock.seq == 0
                && c.node_id == heads[0].node_id
                && c.addresses == heads[0].addresses
                && c.peers.as_deref().unwrap_or_default().is_empty()
        })
        .expect("vectors no longer cover the same netmap without a head");

    assert_ne!(
        heads[0].version, none.version,
        "publishing a Bedrock head left the version unmoved"
    );

    // Same hash, different sequence. Hashing only the hash would let a rewound
    // log be served at the same tip without the version moving.
    assert_eq!(heads[0].bedrock.hash, heads[1].bedrock.hash);
    assert_ne!(heads[0].bedrock.seq, heads[1].bedrock.seq);
    assert_ne!(
        heads[0].version, heads[1].version,
        "the Bedrock sequence is not part of the version"
    );
}

/// Enabling enforcement changes nothing else about a netmap. If the mode were
/// not hashed, the server would answer `unchanged` and turning on the network
/// lock would be the one change it could never deliver.
#[test]
fn the_version_covers_the_bedrock_mode() {
    let v = vectors();
    let enforcing = v
        .cases
        .netmap_version
        .iter()
        .find(|c| c.bedrock.mode != 0)
        .expect("vectors no longer cover an enforcing netmap");
    let off = v
        .cases
        .netmap_version
        .iter()
        .find(|c| {
            c.bedrock.mode == 0
                && c.bedrock.seq == enforcing.bedrock.seq
                && c.bedrock.hash == enforcing.bedrock.hash
        })
        .expect("vectors no longer cover the same head with enforcement off");

    assert_ne!(
        enforcing.version, off.version,
        "enabling enforcement left the netmap version unmoved"
    );
}
