// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `relay_worker` against two **real relays**, with traffic that never stops.
//!
//! `home.rs` proves the decision and `MoveCheck` proves the cadence; neither can
//! see whether the send loop actually acts on a changed choice while its queue
//! is never empty — which is the case #233 is about. These drive the real
//! worker, on real sockets, with a feeder that keeps the queue busy throughout.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding as _};
use karst_relay::server::{serve_on, Ctx};
use karst_transport::UdpTransport;

use super::probe_tests::{config, engine};
use super::{
    disco, relay_worker, Engine, NetworkDevice, RelayCommon, RelayContext, RelayRole, RelaySender,
    Relayed, Shutdown,
};
use crate::control::Identity;
use crate::netmap::Relay;

/// More than a move needs: the check is a second and a dial is milliseconds on
/// loopback. A bound this loose still fails if the move waits for idleness,
/// because the feeder never lets the queue go idle.
const MOVE_BOUND: Duration = Duration::from_secs(6);

struct LiveRelay {
    relay: Relay,
    ctx: Arc<Ctx>,
}

struct Dir(std::path::PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(tag: &str) -> Dir {
    let p = std::env::temp_dir().join(format!("karst-rehome-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("mkdir");
    Dir(p)
}

/// Start a relay on loopback that admits `node`, using the shared certificate.
///
/// Each relay has its own ML-DSA identity — that is what the registry entry
/// pins — and they share a TLS certificate only so that one `relay_ca_file`
/// trusts both.
fn start_relay(
    rt: &tokio::runtime::Runtime,
    dir: &Dir,
    n: u8,
    node: &Identity,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> LiveRelay {
    let roster = dir.0.join(format!("roster{n}.toml"));
    std::fs::write(
        &roster,
        format!(
            "[[client]]\nidentity_pk = \"{}\"\naquifer = \"t1\"\n\n",
            Base64::encode_string(
                &<Identity as karst_control_client::transport::Signer>::public_key(node)
            )
        ),
    )
    .expect("roster");
    let cfg = karst_relay::config::Config::parse(&format!(
        "listen = \"127.0.0.1:0\"\nidentity_key = \"{}\"\nroster = \"{}\"\n\
         tls_cert = \"{}\"\ntls_key = \"{}\"\n",
        dir.0.join(format!("relay{n}.key")).display(),
        roster.display(),
        cert.display(),
        key.display()
    ))
    .expect("config");
    cfg.validate().expect("valid");
    let identity =
        Arc::new(karst_relay::sign::Identity::load_or_create(&cfg.identity_key).expect("identity"));
    let roster = Arc::new(karst_relay::roster::FileRoster::load(&cfg.roster).expect("roster"));
    let tls = karst_relay::tls::server_config(&cfg.tls_cert, &cfg.tls_key).expect("tls");
    let ctx = Ctx::new(&cfg, Arc::clone(&identity), roster, tls);
    let listener = rt
        .block_on(tokio::net::TcpListener::bind(cfg.listen))
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serving = Arc::clone(&ctx);
    rt.spawn(async move {
        let _ = serve_on(listener, serving).await;
    });
    let identity_key = identity.public_key().to_vec();
    LiveRelay {
        relay: Relay {
            address: addr.to_string(),
            tls_server_name: "relay.test".to_owned(),
            relay_id: karst_relay::sign::relay_id(&identity_key),
            identity_key,
            region: "test".to_owned(),
        },
        ctx,
    }
}

/// Stops the worker and the feeder however the test ends. Without it a failed
/// assertion leaves both running and `thread::scope` waits on them for ever, so
/// a regression would hang the suite instead of failing it.
struct StopOnDrop<'a>(&'a Shutdown);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.request();
    }
}

fn wait_for(what: &str, bound: Duration, mut done: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < bound, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
    start.elapsed()
}

/// Run the real home worker on relay 1 with an unbroken stream of datagrams,
/// call `change` once it is connected, and return how long the node took to be
/// connected to relay 2 and homed there.
fn move_under_traffic(
    tag: &str,
    change: impl FnOnce(&Engine, &Mutex<crate::home::Selector>, &LiveRelay, &LiveRelay),
) -> Duration {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let dir = temp_dir(tag);
    let cert = rcgen::generate_simple_self_signed(vec!["relay.test".to_owned()]).expect("cert");
    let (cert_path, key_path) = (dir.0.join("relay.crt"), dir.0.join("relay.pem"));
    std::fs::write(&cert_path, cert.cert.pem()).expect("write");
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).expect("write");

    let node = Arc::new(Identity::from_seed(&[0x42; 32]));
    let one = start_relay(&rt, &dir, 1, &node, &cert_path, &key_path);
    let two = start_relay(&rt, &dir, 2, &node, &cert_path, &key_path);

    let engine = engine(vec![one.relay.clone(), two.relay.clone()]);
    engine.set_home_relay(Some(one.relay.relay_id));
    let home = Mutex::new(crate::home::Selector::new());
    home.lock().unwrap().hold(one.relay.relay_id);
    let rtt = Mutex::new(crate::home::Probes::default());
    let disco = Mutex::new(disco::Disco::new(1));
    let socket = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).expect("udp");
    let tun = NetworkDevice::Userspace(
        karst_tun::Userspace::create(&karst_tun::TunConfig::default()).expect("stack"),
    );
    let (queue, outbound) = tokio::sync::mpsc::channel(64);
    let (on_demand, _on_demand_rx) = tokio::sync::mpsc::channel(64);
    let relayed = RelaySender {
        queue,
        on_demand,
        dropped: Arc::new(AtomicU64::new(0)),
    };
    let health = Mutex::new(HashMap::new());
    let shutdown = Shutdown::default();
    let common = RelayCommon {
        shutdown: &shutdown,
        rtt: &rtt,
        home: &home,
        identity: Arc::clone(&node),
        node_id: node.handle().into_bytes(),
        disco: &disco,
        engine: &engine,
        socket: &socket,
        tun: &tun,
        relay_ca_file: Some(cert_path),
        prefer_quic_relay: false,
        relayed: &relayed,
        started: Instant::now(),
        relay_health: &health,
    };

    let sent = AtomicU64::new(0);
    let took = std::thread::scope(|scope| {
        let _stop = StopOnDrop(&shutdown);
        scope.spawn(|| {
            relay_worker(
                RelayContext {
                    common: &common,
                    relay: one.relay.clone(),
                    role: RelayRole::Home,
                },
                outbound,
            );
        });
        // The load: a datagram every millisecond, so the send loop is never
        // idle for the 100 ms the idle path needs.
        scope.spawn(|| {
            while !shutdown.requested() {
                let item = Relayed::Packet {
                    destination: [9; 32],
                    payload: vec![0; 64],
                };
                if relayed.queue.try_send(item).is_ok() {
                    sent.fetch_add(1, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });

        wait_for("the node to reach relay 1", Duration::from_secs(10), || {
            one.ctx.local_clients() == 1
        });
        let busy_before = sent.load(Ordering::Relaxed);
        assert!(busy_before > 0, "the feeder never got going");

        let start = Instant::now();
        change(&engine, &home, &one, &two);
        wait_for("the node to reach relay 2", MOVE_BOUND, || {
            two.ctx.local_clients() == 1
        });
        let took = start.elapsed();
        assert_eq!(engine.home_relay(), Some(two.relay.relay_id));
        // The queue filled while the connection was being replaced, so the
        // feeder was refused for a moment. What matters is that nothing was
        // lost for good: the new connection takes the same queue over and
        // traffic flows on it again.
        let at_move = sent.load(Ordering::Relaxed);
        wait_for(
            "traffic to flow on the new relay",
            Duration::from_secs(5),
            || sent.load(Ordering::Relaxed) > at_move,
        );
        took
    });
    drop(rt);
    took
}

#[test]
fn a_busy_home_connection_follows_a_choice_that_moved() {
    let took = move_under_traffic("chosen", |_, home, _, two| {
        // §9.2 has decided relay 2 is better.
        home.lock().unwrap().hold(two.relay.relay_id);
    });
    assert!(took < MOVE_BOUND, "{took:?}");
}

#[test]
fn a_busy_home_connection_leaves_a_relay_the_netmap_withdrew() {
    let took = move_under_traffic("withdrawn", |engine, home, one, two| {
        // What a netmap refresh and the next probe round do: the registry loses
        // relay 1, and the selector releases a choice it no longer lists.
        engine.reconfigure(&config(vec![two.relay.clone()]));
        home.lock().unwrap().retain(&[two.relay.relay_id]);
        assert!(engine
            .relays()
            .iter()
            .all(|r| r.relay_id != one.relay.relay_id));
    });
    assert!(took < MOVE_BOUND, "{took:?}");
}
