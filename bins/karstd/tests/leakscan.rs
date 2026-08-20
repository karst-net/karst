// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! No PSK bytes reach anything a person will read.
//!
//! Phase 3 exit criterion (PLAN.md §2.6): *"an automated scan of logs, traces,
//! and a generated `karst bugreport` over a full registration-to-handshake run
//! finds zero PSK bytes."* The server half of that scan lives in
//! `server/management/internals/karst/control/leakscan_test.go`; this is the
//! node half.
//!
//! # What makes a scan like this worth running
//!
//! Two things, and both have been got wrong here before.
//!
//! **It must drive the code that would leak.** An earlier version of the server
//! scan captured zero bytes of output and passed, because nothing it called
//! logged anything. So this one applies a real netmap carrying real PSKs,
//! builds a datapath from it, runs traffic through it, and *then* renders every
//! diagnostic surface a person can reach.
//!
//! **It must be checked against a planted leak.** A scanner that cannot detect
//! a secret it was handed directly proves nothing about the secrets it did not
//! find, so `the_scanner_detects_a_planted_leak` puts one in front of it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // This file's whole job is to render secrets in every shape a careless
    // formatter might, and to concatenate the results. The lints that ask for
    // `fold` or `write!` would make that harder to read for no benefit here.
    clippy::format_collect,
    clippy::format_push_string
)]

use std::sync::Arc;

use karst_control_client::transport::pb;
use karstd::config::{Config, LocalSettings};
use karstd::engine::Engine;
use karstd::netmap::Netmap;

/// The PSK planted in the fixture. Distinctive enough that a partial leak still
/// matches: a run of one repeated byte would collide with padding.
const PSK: [u8; 32] = [
    0xB1, 0x9C, 0x3D, 0x77, 0xE2, 0x04, 0xAB, 0x51, 0x68, 0xFC, 0x2A, 0x90, 0x35, 0xD6, 0x7B, 0x11,
    0x4E, 0xC8, 0x83, 0x27, 0x5F, 0xA0, 0x19, 0xEE, 0x6D, 0x32, 0xB4, 0x08, 0x71, 0xDA, 0x95, 0x63,
];
const PREVIOUS_PSK: [u8; 32] = [
    0x2F, 0x81, 0x44, 0xD9, 0x0B, 0x67, 0xC3, 0x1E, 0xAA, 0x50, 0x9D, 0x36, 0xF2, 0x78, 0x15, 0xBC,
    0x63, 0x0E, 0xD1, 0x8A, 0x47, 0x99, 0x22, 0xFB, 0x54, 0x3C, 0xE7, 0x60, 0x0D, 0xB8, 0x71, 0x2A,
];
/// The AVEN authenticator is independent key material and must receive the
/// same diagnostic treatment as either PHREATIC PSK.
const DISCO_KEY: [u8; 32] = [
    0x5A, 0x16, 0xE3, 0x48, 0x91, 0x2C, 0xB7, 0x04, 0x6D, 0xF0, 0x3A, 0x85, 0xCE, 0x19, 0x72, 0xDB,
    0x24, 0xA8, 0x4F, 0x96, 0x31, 0xED, 0x08, 0xC5, 0x7B, 0x42, 0x9A, 0x65, 0xD0, 0x1E, 0xB4, 0x39,
];

/// Every rendering of a secret a diagnostic might plausibly use.
///
/// A scan for the raw bytes alone would miss the overwhelmingly common leak,
/// which is a `Debug` or a hex formatter — nobody writes a secret to a log as
/// raw binary.
fn encodings(secret: &[u8]) -> Vec<String> {
    let lower: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let upper = lower.to_uppercase();
    // `{:?}` on a byte array or slice.
    let debug = format!("{secret:?}");
    let debug_no_space = debug.replace(' ', "");
    // `{:02x?}` — hex *and* Debug together. Added because the planted-leak
    // check caught the scanner missing it, which is the whole reason that
    // check exists: this is a thoroughly plausible way to write a key into a
    // log, and a scan that did not look for it would have passed while the
    // leak went out the door.
    let hex_debug = format!("{secret:02x?}");
    let hex_debug_upper = format!("{secret:02X?}");
    // base64, standard alphabet.
    let b64 = base64(secret);
    // Half of it: a truncated leak is still a leak, and halving the search
    // space of a 32-byte key is not a defence.
    let half_hex: String = secret[..16].iter().map(|b| format!("{b:02x}")).collect();

    vec![
        lower,
        upper,
        debug,
        debug_no_space,
        hex_debug,
        hex_debug_upper,
        b64,
        half_hex,
        String::from_utf8_lossy(secret).into_owned(),
    ]
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
                out.push(char::from(ALPHABET[idx]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Which encoding of `secret` appears in `haystack`, if any.
fn leak(haystack: &str, secret: &[u8]) -> Option<String> {
    encodings(secret)
        .into_iter()
        // A lossy UTF-8 rendering of random bytes is mostly replacement
        // characters, which would match almost anything. Only the encodings a
        // formatter would actually produce are worth searching for.
        .filter(|e| e.len() >= 16 && !e.contains('\u{FFFD}'))
        .find(|e| haystack.contains(e.as_str()))
}

// ── the fixture ─────────────────────────────────────────────────────────────

/// A netmap carrying two peers, each with a real PSK.
fn netmap_with_psks() -> Netmap {
    use karst_crypto::kem::{Kem as _, MlKem768Backend as MlKem};

    let peer = |id: &str, ip: &str, seed: u8| {
        let (_, kem_pk) = MlKem::keypair_from_seed(&[seed; 64]);
        let dh =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([seed ^ 0xFF; 32]));
        pb::KarstNetmapPeer {
            home_relay: Vec::new(),
            node_id: id.as_bytes().to_vec(),
            allowed_ips: vec![format!("{ip}/32")],
            dns_name: id.to_owned(),
            endpoint: String::new(),
            kem_public_key: MlKem::public_key_bytes(&kem_pk).clone(),
            dh_public_key: dh.as_bytes().to_vec(),
            psk: PSK.to_vec(),
            psk_previous: PREVIOUS_PSK.to_vec(),
            disco_key: DISCO_KEY.to_vec(),
        }
    };

    let mut resp = pb::KarstNetmapResponse {
        psk_epoch: 9,
        node_id: b"self".to_vec(),
        addresses: vec!["100.64.0.1/16".to_owned()],
        dns_name: "self".to_owned(),
        peers: vec![
            peer("alpha", "100.64.0.2", 0x41),
            peer("beta", "100.64.0.3", 0x42),
        ],
        packet_filter: vec![pb::KarstFilterRule {
            srcs: vec!["alpha".to_owned()],
            ports: vec![pb::KarstPortRange {
                first: 22,
                last: 22,
            }],
        }],
        ..pb::KarstNetmapResponse::default()
    };

    let mut projected = Netmap::new();
    projected.apply(resp.clone()).ok();
    resp.version = projected.content_version();

    let mut map = Netmap::new();
    map.apply(resp).expect("the fixture netmap must apply");
    map
}

fn local() -> LocalSettings {
    LocalSettings {
        relay_ca_file: None,
        keys: Arc::new(karst_noise::handshake::StaticKeys::from_seed(
            &[0x11; 64],
            &[0x12; 32],
        )),
        listen: "0.0.0.0:51820".parse().expect("addr"),
        port_mapping: true,
        interface: "karst0".to_owned(),
        network_mode: karstd::config::NetworkMode::Tun,
        userspace_socks5_listen: None,
    }
}

/// Every diagnostic surface a person can reach, concatenated.
///
/// Driving them all matters more than any one of them: a scan that renders
/// nothing passes trivially, which is exactly how the server-side version of
/// this test managed to pass while capturing zero bytes.
/// A stand-in for the live packet device. The scan is about what the reports
/// *say*, not about which device produced them.
fn attachment() -> karstd::run::Attachment<'static> {
    karstd::run::Attachment {
        name: "karst0",
        mtu: 1280,
    }
}

fn every_diagnostic(config: &Arc<Config>, netmap: &Netmap) -> String {
    let engine = Engine::new(config);

    // Traffic first, so the counters and session states are not all zero and
    // the peers have something to say.
    let mut packet = vec![0u8; 24];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&24u16.to_be_bytes());
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[100, 64, 0, 1]);
    packet[16..20].copy_from_slice(&[100, 64, 0, 2]);
    packet[22..24].copy_from_slice(&22u16.to_be_bytes());
    let _ = engine.outbound(&packet, 10);
    let _ = engine.inbound(
        &[0xFF; 64],
        "127.0.0.1:1".parse().expect("addr"),
        11,
        &rand(),
    );
    let _ = engine.poll(12, || [0x5A; 32]);

    let mut out = String::new();
    out.push_str(&karstd::run::status_report(
        config,
        &engine,
        attachment(),
        0,
    ));
    out.push_str(&karstd::run::bug_report_for_test(
        config,
        &engine,
        attachment(),
        0,
    ));

    // The `Debug` implementations, which is where a secret most often escapes:
    // a derived one prints every field, and nobody notices until a support
    // bundle has already been sent.
    out.push_str(&format!("{config:?}"));
    out.push_str(&format!("{netmap:?}"));
    out.push_str(&format!("{engine:?}"));
    for peer in netmap.peers() {
        out.push_str(&format!("{peer:?}"));
    }
    for peer in &config.peers {
        out.push_str(&format!("{peer:?}"));
    }
    for status in engine.status() {
        out.push_str(&format!("{status:?}"));
    }
    out
}

fn rand() -> karst_noise::handshake::ResponderRandomness {
    karst_noise::handshake::ResponderRandomness {
        e_dh_seed: [0xF1; 32],
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    }
}

// ── the scan ────────────────────────────────────────────────────────────────

/// **The exit criterion.** A full netmap-to-datapath run, every diagnostic
/// rendered, and no PSK anywhere in the output.
#[test]
fn no_psk_bytes_reach_any_diagnostic() {
    let netmap = netmap_with_psks();
    let config = Arc::new(Config::from_netmap(local(), &netmap).expect("config"));
    let rendered = every_diagnostic(&config, &netmap);

    assert!(
        rendered.len() > 512,
        "the scan rendered {} bytes, which is too little to have exercised \
         anything — a scan over no output passes for the wrong reason",
        rendered.len()
    );

    for (which, secret) in [
        ("current", &PSK),
        ("previous", &PREVIOUS_PSK),
        ("discovery", &DISCO_KEY),
    ] {
        if let Some(found) = leak(&rendered, secret) {
            panic!("the {which} key reached a diagnostic as {found:?}");
        }
    }
}

/// The **previous** epoch's PSK is just as secret as the current one, and it is
/// the one more likely to be forgotten: it exists only to make a rotation
/// uninterrupted, so nothing routine reads it.
#[test]
fn the_previous_epochs_psk_is_covered_too() {
    let netmap = netmap_with_psks();
    let held = netmap.peer(b"alpha").expect("held");
    assert!(
        held.psk_previous.is_some(),
        "the fixture no longer carries a previous-epoch PSK, so the scan \
         would not be testing anything"
    );

    let config = Arc::new(Config::from_netmap(local(), &netmap).expect("config"));
    assert!(leak(&every_diagnostic(&config, &netmap), &PREVIOUS_PSK).is_none());
}

#[test]
fn the_discovery_key_is_covered_too() {
    let netmap = netmap_with_psks();
    let held = netmap.peer(b"alpha").expect("held");
    assert!(held.disco_key.is_some(), "fixture has no discovery key");

    let config = Arc::new(Config::from_netmap(local(), &netmap).expect("config"));
    assert!(leak(&every_diagnostic(&config, &netmap), &DISCO_KEY).is_none());
}

/// **A scanner that cannot find a secret handed to it directly proves nothing
/// about the secrets it did not find.** This is the check that gives the test
/// above its meaning.
#[test]
fn the_scanner_detects_a_planted_leak() {
    let netmap = netmap_with_psks();
    let config = Arc::new(Config::from_netmap(local(), &netmap).expect("config"));
    let mut rendered = every_diagnostic(&config, &netmap);

    // Exactly the mistake the redacting `Debug` exists to prevent: reaching
    // past it for the bytes and formatting them.
    let held = netmap.peer(b"alpha").expect("held");
    let psk = held.psk.as_ref().expect("a psk");
    rendered.push_str(&format!("peer psk: {:02x?}", psk.as_bytes()));

    assert!(
        leak(&rendered, &PSK).is_some(),
        "the scanner missed a PSK written straight into the output, so it \
         proves nothing about the ones it did not find"
    );

    let disco = held.disco_key.as_ref().expect("a discovery key");
    rendered.push_str(&format!("peer disco key: {:02x?}", disco.as_bytes()));
    assert!(
        leak(&rendered, &DISCO_KEY).is_some(),
        "the scanner missed a discovery key written straight into the output"
    );
}

/// Each encoding the scanner searches for must actually be found when present.
/// A scan for hex alone would miss a `Debug`, which is the most common way a
/// secret escapes.
#[test]
fn every_encoding_the_scanner_looks_for_is_detectable() {
    for rendering in [
        PSK.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        PSK.iter().map(|b| format!("{b:02X}")).collect::<String>(),
        format!("{PSK:?}"),
        format!("{PSK:?}").replace(' ', ""),
        base64(&PSK),
    ] {
        assert!(
            leak(&format!("some log line: {rendering} and more"), &PSK).is_some(),
            "the scanner does not recognise {rendering:.24}…"
        );
    }
}

/// And it must not fire on something that merely resembles a secret, or the
/// scan would be ignored the first time it cried wolf.
#[test]
fn the_scanner_does_not_fire_on_unrelated_output() {
    let netmap = netmap_with_psks();
    let config = Arc::new(Config::from_netmap(local(), &netmap).expect("config"));
    let rendered = every_diagnostic(&config, &netmap);
    // A different 32-byte secret, present nowhere.
    let other = [0x5Au8; 32];
    assert!(leak(&rendered, &other).is_none());
}

/// The bug report is the artefact most likely to be pasted somewhere public,
/// so it says what it does and does not contain.
#[test]
fn the_bug_report_is_useful_and_says_what_it_omits() {
    let netmap = netmap_with_psks();
    let config = Arc::new(Config::from_netmap(local(), &netmap).expect("config"));
    let engine = Engine::new(&config);
    let report = karstd::run::bug_report_for_test(&config, &engine, attachment(), 0);

    assert!(report.contains("no key material"), "{report}");
    // The diagnostics a maintainer actually needs.
    assert!(
        report.contains("psk_epoch = 9"),
        "the epoch must be visible"
    );
    assert!(report.contains("peers_total = 2"));
    assert!(report.contains("enforcing = true"), "the ACL state");
    assert!(report.contains("alpha") && report.contains("beta"));
    assert!(report.contains("decrypt_failures"), "the counters");
    // §7.3: whether a session is lattice-only must be visible.
    assert!(report.contains("peers_lattice_only"));
    assert!(report.contains("psk_fallback"));
}

/// A node with no PSKs is lattice-only, and the report must say so plainly —
/// §7.3 requires it to be surfaced rather than assumed.
#[test]
fn a_lattice_only_node_is_reported_as_such() {
    use karst_crypto::kem::{Kem as _, MlKem768Backend as MlKem};

    let (_, kem_pk) = MlKem::keypair_from_seed(&[0x41; 64]);
    let dh = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0xBEu8; 32]));
    let mut resp = pb::KarstNetmapResponse {
        psk_epoch: 0,
        node_id: b"self".to_vec(),
        addresses: vec!["100.64.0.1/16".to_owned()],
        dns_name: "self".to_owned(),
        peers: vec![pb::KarstNetmapPeer {
            node_id: b"alpha".to_vec(),
            allowed_ips: vec!["100.64.0.2/32".to_owned()],
            dns_name: "alpha".to_owned(),
            endpoint: String::new(),
            home_relay: Vec::new(),
            kem_public_key: MlKem::public_key_bytes(&kem_pk).clone(),
            dh_public_key: dh.as_bytes().to_vec(),
            psk: Vec::new(),
            psk_previous: Vec::new(),
            disco_key: Vec::new(),
        }],
        ..pb::KarstNetmapResponse::default()
    };
    let mut projected = Netmap::new();
    projected.apply(resp.clone()).ok();
    resp.version = projected.content_version();
    let mut map = Netmap::new();
    map.apply(resp).expect("apply");

    let config = Arc::new(Config::from_netmap(local(), &map).expect("config"));
    let engine = Engine::new(&config);
    let report = karstd::run::bug_report_for_test(&config, &engine, attachment(), 0);

    assert!(
        report.contains("peers_lattice_only = 1"),
        "a session resting on ML-KEM alone must not pass unremarked:\n{report}"
    );
    assert!(report.contains("psk_fallback = true"));
}
