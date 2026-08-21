// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! **A whole aquifer: coordination server, relay, and two daemons.**
//!
//! Everything else in this repository tests a layer, or two layers meeting.
//! This starts four processes — the Go control server, `karst-relay`, and two
//! `karstd` instances in separate network namespaces with real TUN devices —
//! and asserts the thing Phase 4 exists to deliver: **two nodes that begin on
//! the relay end up talking directly, and traffic crosses under an ACL.**
//!
//! It is here because running it by hand found three defects that every unit
//! test passed, and none of them was in a layer:
//!
//! - **Finding 17** — the packet filter was stateless, so a port-scoped ACL
//!   permitted a request and denied its reply. No TCP connection could
//!   complete, while both ends reported `established` and `direct`.
//! - **Finding 19** — a node advertised its candidates once and never again, so
//!   a peer that joined later never learned where it was and the pair stayed
//!   relayed.
//! - **Finding 18** — a relay that could not be reached logged nothing at all,
//!   which is what made the first two take as long to find as they did.
//!
//! Each was invisible from inside a component and obvious from outside one.
//!
//! Needs `CAP_NET_ADMIN` and a Go toolchain, so it is `#[ignore]`d. Run it with:
//!
//! ```text
//! just test-aquifer
//! ```

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding as _};

const NS_A: &str = "karst-tn-a";
const NS_B: &str = "karst-tn-b";
/// The public segment, where the relay and the coordination server always live.
const NS_PUB: &str = "karst-tn-pub";
/// A NAT in front of each node, present only in the shapes that use one.
const NS_NAT_A: &str = "karst-tn-nata";
const NS_NAT_B: &str = "karst-tn-natb";

/// Everything on the public segment hangs off a bridge in [`NS_PUB`], so the
/// same wiring carries two, three or four participants.
const IP_PUB: &str = "51.75.10.10";
/// Where each node sits when it is *on* the public segment.
const IP_A_PUBLIC: &str = "51.75.10.1";
const IP_B_PUBLIC: &str = "51.75.10.20";
/// The outside of each NAT.
const NAT_A_OUTER: &str = "51.75.10.2";
const NAT_B_OUTER: &str = "51.75.10.3";
/// And the inside.
const IP_A_PRIVATE: &str = "10.98.1.2";
const NAT_A_INNER: &str = "10.98.1.1";
const IP_B_PRIVATE: &str = "10.98.2.2";
/// Node B's address when it shares node A's private segment — [`Shape::SameLan`].
const IP_B_SAME_LAN: &str = "10.98.1.3";
const NAT_B_INNER: &str = "10.98.2.1";

const RELAY_PORT: u16 = 8443;
/// A second relay on the same segment, for `ponor-v1.md` §9.1's two rules.
const RELAY_PORT_2: u16 = 8444;
/// The relay's AVEN reflector — `aven-v1.md` §7.6. Its own **UDP** socket,
/// because a NAT maps TCP and UDP separately and the Ponor connection's
/// mapping is not the one AVEN needs.
const REFLECT_PORT: u16 = 3478;
const SERVER_PORT: u16 = 9443;

/// Seeds for the two nodes' control identities. Fixed, so the relay roster can
/// be written before either daemon has ever run.
const SEED_A: u8 = 0xA1;
const SEED_B: u8 = 0xB2;

// ── prerequisites ───────────────────────────────────────────────────────────

fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))?
                .split_whitespace()
                .nth(2)?
                .parse()
                .ok()
        })
        .unwrap_or(1)
}

/// Everything this fixture needs and does not have.
///
/// `miniupnpd` and `nft` are named because two rows are silently *wrong*
/// without them rather than merely absent: rows 8b and 9 turn on a port mapping
/// being served, and a fixture that cannot serve one would report the product
/// failing to reach a path that is in fact unreachable in that fixture. Finding
/// 23 is what an instrument that lies about its own shape costs.
fn missing_prerequisites() -> Vec<&'static str> {
    let mut missing = Vec::new();
    if effective_uid() != 0 {
        missing.push("root");
    }
    // **Probes that need no privilege**, so this reports what is *installed*
    // rather than what this process may do. `nft list ruleset` would fail as an
    // ordinary user and name `nft` as missing when it is present — a message
    // that sends someone to install a package they already have.
    for (tool, probe) in [
        ("ip", "-Version"),
        ("nft", "--version"),
        ("go", "version"),
        ("miniupnpd", "--help"),
    ] {
        // `miniupnpd --help` exits non-zero, as usage output usually does, so
        // the test is whether the program ran at all.
        if Command::new(tool).arg(probe).output().is_err() {
            missing.push(tool);
        }
    }
    missing
}

/// Whether to run, **and a refusal to be quietly green**.
///
/// Skipping is for a developer without the tooling. In CI it must fail instead:
/// a privileged suite that skips itself is a suite that passes while testing
/// nothing, which is the exact failure mode `ci.yml`'s TUN job comments warn
/// about one layer down. `KARST_REQUIRE_PREREQUISITES=1` is how CI says "these
/// are supposed to be here" — so a runner image that stops shipping `miniupnpd`
/// turns the matrix red instead of turning it into a no-op.
fn have_prerequisites() -> bool {
    let missing = missing_prerequisites();
    if missing.is_empty() {
        return true;
    }
    assert!(
        std::env::var_os("KARST_REQUIRE_PREREQUISITES").is_none(),
        "KARST_REQUIRE_PREREQUISITES is set, so skipping is not allowed — \
         missing: {missing:?}"
    );
    eprintln!("skipping: missing {missing:?}");
    false
}

fn sh(args: &[&str]) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn must(args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {args:?}: {e}"));
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn repo() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..").to_owned()
}

fn bin(name: &str) -> String {
    // The test binary is in target/<profile>/deps/; the products are two up.
    let exe = std::env::current_exe().expect("test binary path");
    let dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("target/<profile>");
    let p = dir.join(name);
    assert!(
        p.exists(),
        "{} is missing — build the workspace first",
        p.display()
    );
    p.to_string_lossy().into_owned()
}

// ── the fixture ─────────────────────────────────────────────────────────────

/// Tears down everything, however the test ended.
struct Aquifer {
    dir: PathBuf,
    /// The relay and the coordination server, which run for the whole test.
    services: Vec<Child>,
    /// The daemons, by tag. **Not a `Vec`**: node A is restarted below, and an
    /// earlier version of this popped the most recently spawned child instead —
    /// which was B. The second A then collided with the first one's TUN device
    /// and the whole thing timed out with `TUNSETIFF: Device or resource busy`.
    nodes: Vec<(String, Child)>,
}

impl Drop for Aquifer {
    fn drop(&mut self) {
        for c in self
            .nodes
            .iter_mut()
            .map(|(_, c)| c)
            .chain(&mut self.services)
        {
            let _ = c.kill();
            let _ = c.wait();
        }
        // NS_NAT too, even in the topologies that never create it: deleting a
        // namespace that is not there is free, and an earlier version listed
        // only the two it knew about and left the third behind.
        for ns in [NS_A, NS_B, NS_PUB, NS_NAT_A, NS_NAT_B] {
            let _ = sh(&["ip", "netns", "del", ns]);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Aquifer {
    fn launch(&self, ns: &str, program: &str, args: &[&str], log: &str) -> Child {
        let path = self.dir.join(log);
        let out = std::fs::File::create(&path).expect("log file");
        let err = out.try_clone().expect("log file");
        let mut argv = vec!["netns", "exec", ns, program];
        argv.extend_from_slice(args);
        Command::new("ip")
            .args(&argv)
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {program}: {e}"))
    }

    fn spawn_service(&mut self, ns: &str, program: &str, args: &[&str], log: &str) {
        let child = self.launch(ns, program, args, log);
        self.services.push(child);
    }

    /// Stop a daemon and wait for its TUN device to go with it.
    ///
    /// The device is removed when the last descriptor closes, which is after
    /// the process is reaped — so restarting immediately races the kernel, and
    /// the loser reports `TUNSETIFF: Device or resource busy`.
    fn stop_node(&mut self, tag: &str, ns: &str) {
        let Some(at) = self.nodes.iter().position(|(t, _)| t == tag) else {
            return;
        };
        let (_, mut child) = self.nodes.remove(at);
        let _ = child.kill();
        let _ = child.wait();

        let device = format!("karst-tn{tag}");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if !sh(&["ip", "netns", "exec", ns, "ip", "link", "show", &device]) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("{device} outlived the daemon that created it");
    }

    fn log(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }
}

/// The node's ML-DSA-65 public key, for the relay roster — derived here rather
/// than read back from a running daemon, so the roster exists before it does.
fn node_public(seed: u8) -> Vec<u8> {
    let id = karstd::control::Identity::from_seed(&[seed; 32]);
    <karstd::control::Identity as karst_control_client::transport::Signer>::public_key(&id)
}

fn write_secret(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, text).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Where the two nodes sit relative to one another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    /// Both nodes on the public segment. A direct path needs no hole punching —
    /// the baseline that proves the rest of the stack before a NAT is added.
    Flat,
    /// Node A behind a port-restricted cone; node B public.
    ///
    /// The address A advertises is private and useless to B, so a direct path
    /// can only come from B learning A's *mapped* address from the probe that
    /// arrives through the NAT.
    NatA,
    /// **Both** nodes behind port-restricted cones — two laptops on two home
    /// networks, which is the ordinary case rather than an exotic one.
    ///
    /// Neither can name an address the other can reach, and neither learns its
    /// own mapped address from anywhere, because nothing has yet told it: the
    /// relay speaks TCP and Ponor has no frame for reporting an observed
    /// address. PLAN.md §6 lists "STUN against our relays" as the piece that
    /// closes this and it is unbuilt, so the honest expectation is a permanent
    /// relay path — and this row exists to hold that behaviour to *graceful*,
    /// which is the other half of the exit criterion.
    BothNat,
    /// Node A behind a **symmetric** NAT; node B public.
    ///
    /// A's mapped port differs per destination, so its reflexive address — the
    /// mapping toward the *reflector* — is worthless to B, and every candidate
    /// A can name is either private or wrong. The direct path exists anyway,
    /// and the reason is worth stating: B is publicly reachable, so A's probe
    /// crosses first and B adopts the address it *arrived from*. That address
    /// is the mapping toward B specifically, which is the only one that works.
    ///
    /// This is the row that separates "symmetric NAT" from "hopeless". Half of
    /// the symmetric cases in §6's matrix have a reachable peer on the far
    /// side, and those are direct today with nothing added.
    SymmetricA,
    /// **Both** nodes behind symmetric NATs — the CGNAT-to-CGNAT row the exit
    /// criterion names.
    ///
    /// Neither reflexive address predicts the mapping the other side needs,
    /// because a symmetric NAT allocates per destination and neither node has
    /// ever sent to the other. Port prediction is the piece that would close
    /// it (PLAN.md §6, `aven-v1.md` §12.4) and it is unbuilt, so the honest
    /// expectation today is a permanent relay path.
    ///
    /// **The row is here while it still fails to go direct**, because the
    /// assertion that matters in the meantime is the one that catches the worse
    /// outcome: claiming `direct` on an address that does not carry traffic.
    /// When port prediction lands, this row's expectation changes and nothing
    /// else about it does.
    BothSymmetric,
    /// Node A behind a symmetric NAT that **also offers an explicit port
    /// mapping**; node B behind a different symmetric NAT.
    ///
    /// This is the restated third exit criterion in one row. A's reflexive
    /// address is still the mapping toward the reflector and still useless to
    /// B, but A can now advertise something stronger than a reflexive report:
    /// the port its own gateway is holding open on purpose. B probes that
    /// mapped address, A learns B from the probe that arrives through it, and
    /// the pair upgrades to a direct path without prediction.
    SymmetricAndMapped,
    /// **Both nodes behind the same NAT, on one private segment.**
    ///
    /// Two laptops on one home network — as ordinary as [`Shape::BothNat`] and
    /// missing from the matrix until now. The interesting part is that the
    /// obvious path does *not* work: both nodes learn a reflexive address from
    /// the relay, both advertise it, and both then probe **the NAT's own outer
    /// address**, which Linux does not loop back.
    /// `crates/karst-disco/tests/nat_matrix.rs` pins that separately —
    /// `a_masquerading_nat_does_not_hairpin`.
    ///
    /// So this row goes direct over the **private** addresses, and that is what
    /// it asserts: each node must end up holding the other's `10.98.1.x`
    /// address, not the NAT's. It is the row that makes `aven-v1.md` §7.2's
    /// interface-address tier load-bearing rather than decorative — on this
    /// topology it is the only tier that works, and a node advertising only
    /// reflexive addresses would relay two machines on the same desk through
    /// the internet.
    SameLan,
    /// Node A behind a NAT that forwards **no UDP at all**; node B public.
    ///
    /// The corporate-firewall case, and the only row that tests the second exit
    /// criterion on its own terms: AVEN cannot work, so the relay is not a
    /// fallback that discovery happens to lose out to — it is the only path
    /// there is, and traffic has to cross it losslessly and stay there.
    UdpBlocked,
    /// Node A behind a symmetric NAT; node B behind an **address-restricted**
    /// cone.
    ///
    /// The row that shows [`Shape::BothSymmetric`] is a statement about a
    /// *pair*, not about symmetric NATs. A's mapped port is unpredictable, so B
    /// can never name it — but an address-restricted cone does not ask it to.
    /// It admits any port from an address it has already sent to, and B has
    /// sent to A's outer address, so A's probe is let in on the first attempt
    /// from a port nobody predicted.
    ///
    /// **The reflector is load-bearing here in a way that is easy to miss.**
    /// A's reflexive address is the mapping toward the reflector and is a dead
    /// letter as a destination — B's probe to it is dropped. Its value is that
    /// it makes B *send toward A's outer address at all*, which is what opens
    /// B's filter. A useless candidate doing useful work, and the reason
    /// §7.2's tiers keep addresses that have never answered.
    SymmetricAndAddressRestricted,
    /// Node A behind a symmetric NAT; node B behind a **port-restricted** cone.
    ///
    /// Tailscale's "hard/easy" pairing, and the common real one: a subscriber
    /// on CGNAT talking to somebody on an ordinary home router. It is missing
    /// from the first six rows and it is the case the literature's
    /// birthday-paradox technique actually targets.
    ///
    /// Contrast with [`Shape::SymmetricAndAddressRestricted`], which differs by
    /// one word in B's filter and goes direct. Here B's NAT checks the source
    /// *port* as well as the address, and A's probe arrives from a port B never
    /// sent to, so nothing crosses in either direction.
    SymmetricAndPortRestricted,
    /// The same pairing, with **B's home router offering a port mapping** —
    /// row 8 with the one capability the real version of B usually has.
    ///
    /// This row exists because the row above it is not, in the end, a statement
    /// about what Karst can reach: it is a statement about what a NAT with no
    /// port-mapping service can be made to admit. Separating the two is the
    /// point. The pairing is the common one, so leaving it recorded as "does
    /// not connect" without saying *under what conditions* is the kind of
    /// summary that is true and useless.
    ///
    /// **What closes it is not a new address.** A cone's external port is
    /// stable, so B already advertises a reachable address in the reflexive
    /// tier and A already probes it; the row fails because B's NAT refuses a
    /// datagram from a source port B never sent to. The mapping's inbound half
    /// is an endpoint-independent DNAT, and *that* is what lets A's probe
    /// through — after which B adopts the source it arrived from, which is A's
    /// symmetric mapping toward B specifically, the one allocation that works.
    ///
    /// So the fourth candidate tier (`aven-v1.md` §7.2) is **not** the operative
    /// part here, which is the opposite of [`Shape::SymmetricAndMapped`]. Both
    /// rows need a mapping and they need it for different reasons; a summary
    /// that said "explicit port mapping fixes both" would be right by accident.
    SymmetricAndPortRestrictedMapped,
}

/// How a NAT allocates external ports, and what it lets back through.
///
/// The distinction that matters to AVEN is whether one external port is reused
/// across destinations. `crates/karst-disco/tests/nat_matrix.rs` pins each of
/// these behaviours with a negative assertion before any of them is used to
/// draw a conclusion about the product — finding 23 is what that discipline
/// costs when it is skipped.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavour {
    /// Linux's default masquerade: one external port reused across
    /// destinations, return traffic accepted per flow.
    PortRestrictedCone,
    /// `masquerade fully-random`: a fresh, unpredictable external port per
    /// destination.
    Symmetric,
    /// A symmetric NAT that also runs `miniupnpd`, so the node behind it can
    /// reserve its datapath port explicitly.
    SymmetricWithPortMapping,
    /// A port-restricted cone that also runs `miniupnpd` — **an ordinary home
    /// router**, which is the point of the flavour.
    ///
    /// The mapping does something different here than it does on a symmetric
    /// NAT, and the difference is the whole of row 8b. A cone's external port
    /// is already stable, so the node behind it already advertises a *correct*
    /// address; what it cannot do is accept a datagram from a port it has never
    /// sent to. The mapping's **inbound** half — an endpoint-independent DNAT —
    /// is what removes that filter. On a symmetric NAT the mapping is valuable
    /// for the opposite reason: it makes an address knowable that otherwise is
    /// not.
    PortRestrictedWithPortMapping,
    /// A cone that drops every forwarded UDP datagram in both directions. TCP
    /// still crosses, so Ponor and the control channel are unaffected.
    UdpBlocked,
    /// Endpoint-independent mapping **and** endpoint-independent *port*
    /// filtering: any source port from an address this NAT has sent to is
    /// admitted.
    ///
    /// Linux gives no such mode, so it is built rather than configured — a
    /// static `dnat` for the datapath port, and a `seen` set of contacted
    /// addresses driving the forward chain. The same construction as
    /// `nat_matrix.rs`'s row of the same name, which pins that it admits a new
    /// port and still refuses a new address.
    AddressRestrictedCone,
}

/// What a topology is expected to reach, and how long it is given to get there.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// A direct path in both directions, within `budget`.
    Direct,
    /// The relay, permanently. Traffic must still cross it, and the pair must
    /// **not** claim a direct path it cannot actually use.
    Relay,
}

impl Shape {
    fn expect(self) -> Expect {
        match self {
            Self::Flat
            | Self::NatA
            | Self::BothNat
            | Self::SymmetricA
            | Self::SymmetricAndMapped
            | Self::SymmetricAndAddressRestricted
            | Self::SymmetricAndPortRestrictedMapped
            | Self::SameLan => Expect::Direct,
            // **Not "not yet".** §7.7's birthday-paradox port search is the
            // only technique that reaches this row without help from the NAT,
            // and it was specified, implemented, measured and then *declined*
            // on 2026-08-19 — 64% after eight minutes at §7.5's allowance, and
            // it needs a datapath change against §4's single shared socket
            // (finding 28). The row above it is what the same pairing does when
            // B's router offers a mapping, which is the answer this project
            // adopted for it.
            Self::BothSymmetric | Self::UdpBlocked | Self::SymmetricAndPortRestricted => {
                Expect::Relay
            }
        }
    }

    /// How long the pair is given to reach [`Expect::Direct`].
    ///
    /// Longer for the doubly-NATed row: it needs a `Reflect` round trip to each
    /// node before either has anything worth advertising.
    fn budget(self) -> Duration {
        Duration::from_secs(match self {
            Self::BothNat
            | Self::SymmetricAndMapped
            | Self::SymmetricAndAddressRestricted
            | Self::SymmetricAndPortRestrictedMapped => 210,
            _ => 150,
        })
    }
}

/// One end of a veth, and where it goes.
#[derive(Clone, Copy)]
struct End<'a> {
    dev: &'a str,
    ns: &'a str,
    ip: Option<&'a str>,
}

/// Build the namespaces, and return the addresses the two nodes listen on.
fn build_topology(net: &mut Aquifer, shape: Shape) -> (&'static str, &'static str) {
    for ns in [NS_A, NS_B, NS_PUB, NS_NAT_A, NS_NAT_B] {
        let _ = sh(&["ip", "netns", "del", ns]);
    }
    for ns in [NS_A, NS_B, NS_PUB] {
        must(&["ip", "netns", "add", ns]);
        must(&nsr(ns, &["ip", "link", "set", "lo", "up"]));
    }

    // The public segment: a bridge the servers and everything public attach to.
    must(&nsr(
        NS_PUB,
        &["ip", "link", "add", "ktn-br", "type", "bridge"],
    ));
    must(&nsr(NS_PUB, &["ip", "link", "set", "ktn-br", "up"]));
    let cidr = format!("{IP_PUB}/24");
    must(&nsr(NS_PUB, &["ip", "addr", "add", &cidr, "dev", "ktn-br"]));

    // One NAT with both nodes behind it is a different shape rather than a
    // different flavour, so it gets its own builder instead of a third arm in
    // each of the two matches below.
    if shape == Shape::SameLan {
        return build_same_lan(net);
    }

    // Node A is behind a NAT in every shape but `Flat`; only the flavour
    // changes.
    let ip_a = match shape {
        // Handled by `build_same_lan` above, which returns before this match.
        // Spelled out rather than caught by a wildcard so that adding a shape
        // is a compile error here, which is how every other arm behaves.
        Shape::SameLan => unreachable!("same-LAN is built by its own function"),
        Shape::Flat => {
            public_leg("ktn-a", NS_A, IP_A_PUBLIC);
            IP_A_PUBLIC
        }
        Shape::NatA
        | Shape::BothNat
        | Shape::SymmetricA
        | Shape::BothSymmetric
        | Shape::SymmetricAndMapped
        | Shape::UdpBlocked
        | Shape::SymmetricAndAddressRestricted
        | Shape::SymmetricAndPortRestricted
        | Shape::SymmetricAndPortRestrictedMapped => {
            let flavour = match shape {
                Shape::SymmetricAndMapped => Flavour::SymmetricWithPortMapping,
                Shape::SymmetricA
                | Shape::BothSymmetric
                | Shape::SymmetricAndAddressRestricted
                | Shape::SymmetricAndPortRestricted
                | Shape::SymmetricAndPortRestrictedMapped => Flavour::Symmetric,
                Shape::UdpBlocked => Flavour::UdpBlocked,
                _ => Flavour::PortRestrictedCone,
            };
            nat_in_front_of(
                net,
                "a",
                NS_NAT_A,
                NAT_A_OUTER,
                NAT_A_INNER,
                NS_A,
                IP_A_PRIVATE,
                flavour,
            );
            IP_A_PRIVATE
        }
    };
    let ip_b = match shape {
        // Handled by `build_same_lan` above, which returns before this match.
        // Spelled out rather than caught by a wildcard so that adding a shape
        // is a compile error here, which is how every other arm behaves.
        Shape::SameLan => unreachable!("same-LAN is built by its own function"),
        Shape::Flat | Shape::NatA | Shape::SymmetricA | Shape::UdpBlocked => {
            public_leg("ktn-b", NS_B, IP_B_PUBLIC);
            IP_B_PUBLIC
        }
        Shape::BothNat
        | Shape::BothSymmetric
        | Shape::SymmetricAndMapped
        | Shape::SymmetricAndAddressRestricted
        | Shape::SymmetricAndPortRestricted
        | Shape::SymmetricAndPortRestrictedMapped => {
            let flavour = match shape {
                Shape::SymmetricAndMapped | Shape::BothSymmetric => Flavour::Symmetric,
                Shape::SymmetricAndAddressRestricted => Flavour::AddressRestrictedCone,
                Shape::SymmetricAndPortRestrictedMapped => Flavour::PortRestrictedWithPortMapping,
                _ => Flavour::PortRestrictedCone,
            };
            nat_in_front_of(
                net,
                "b",
                NS_NAT_B,
                NAT_B_OUTER,
                NAT_B_INNER,
                NS_B,
                IP_B_PRIVATE,
                flavour,
            );
            IP_B_PRIVATE
        }
    };
    (ip_a, ip_b)
}

/// Both nodes on one private segment behind a single NAT.
///
/// The inside is a bridge rather than two routed subnets, because two laptops
/// on one home network are on one segment — and the distinction is the whole
/// row. Across two subnets the NAT would merely *forward* between them, which
/// works trivially and would prove nothing about the case being measured.
fn build_same_lan(net: &mut Aquifer) -> (&'static str, &'static str) {
    must(&["ip", "netns", "add", NS_NAT_A]);
    must(&nsr(NS_NAT_A, &["ip", "link", "set", "lo", "up"]));

    // Outside: one leg to the public bridge, as every other NATed shape.
    veth(
        End {
            dev: "ktn-ao",
            ns: NS_NAT_A,
            ip: Some(NAT_A_OUTER),
        },
        End {
            dev: "ktn-aop",
            ns: NS_PUB,
            ip: None,
        },
    );
    must(&nsr(
        NS_PUB,
        &["ip", "link", "set", "ktn-aop", "master", "ktn-br"],
    ));
    must(&nsr(
        NS_NAT_A,
        &["ip", "route", "add", "default", "via", IP_PUB],
    ));

    // Inside: a bridge holding both nodes.
    must(&nsr(
        NS_NAT_A,
        &["ip", "link", "add", "ktn-lan", "type", "bridge"],
    ));
    must(&nsr(NS_NAT_A, &["ip", "link", "set", "ktn-lan", "up"]));
    let inner = format!("{NAT_A_INNER}/24");
    must(&nsr(
        NS_NAT_A,
        &["ip", "addr", "add", &inner, "dev", "ktn-lan"],
    ));
    for (ns, dev, br, ip) in [
        (NS_A, "ktn-an", "ktn-ai", IP_A_PRIVATE),
        (NS_B, "ktn-bn", "ktn-bi", IP_B_SAME_LAN),
    ] {
        veth(
            End {
                dev,
                ns,
                ip: Some(ip),
            },
            End {
                dev: br,
                ns: NS_NAT_A,
                ip: None,
            },
        );
        must(&nsr(
            NS_NAT_A,
            &["ip", "link", "set", br, "master", "ktn-lan"],
        ));
        must(&nsr(
            ns,
            &["ip", "route", "add", "default", "via", NAT_A_INNER],
        ));
    }

    must(&nsr(
        NS_NAT_A,
        &["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
    ));
    let _ = net;
    nat_rules(
        NS_NAT_A,
        "ktn-ao",
        "ktn-lan",
        IP_A_PRIVATE,
        NAT_A_OUTER,
        Flavour::PortRestrictedCone,
    );
    (IP_A_PRIVATE, IP_B_SAME_LAN)
}

/// Attach a namespace directly to the public bridge.
fn public_leg(dev: &str, ns: &str, ip: &str) {
    let peer = format!("{dev}-p");
    veth(
        End {
            dev,
            ns,
            ip: Some(ip),
        },
        End {
            dev: &peer,
            ns: NS_PUB,
            ip: None,
        },
    );
    must(&nsr(
        NS_PUB,
        &["ip", "link", "set", &peer, "master", "ktn-br"],
    ));
    must(&nsr(ns, &["ip", "route", "add", "default", "via", IP_PUB]));
}

/// Put a NAT of the given flavour between a node and the public segment.
///
/// **No route from the public side into the private prefix**, which is what
/// makes this a NAT rather than a router. An earlier version added one "so the
/// relay's replies can get back" — they do not need it, because they return
/// through conntrack's translation — and with it the far node reached the
/// private address directly and reported a direct path no real NAT would allow.
#[allow(clippy::too_many_arguments)]
fn nat_in_front_of(
    net: &mut Aquifer,
    tag: &str,
    nat_ns: &str,
    outer: &str,
    inner: &str,
    node_ns: &str,
    node: &str,
    flavour: Flavour,
) {
    must(&["ip", "netns", "add", nat_ns]);
    must(&nsr(nat_ns, &["ip", "link", "set", "lo", "up"]));

    let out_dev = format!("ktn-{tag}o");
    let out_peer = format!("ktn-{tag}op");
    veth(
        End {
            dev: &out_dev,
            ns: nat_ns,
            ip: Some(outer),
        },
        End {
            dev: &out_peer,
            ns: NS_PUB,
            ip: None,
        },
    );
    must(&nsr(
        NS_PUB,
        &["ip", "link", "set", &out_peer, "master", "ktn-br"],
    ));
    must(&nsr(
        nat_ns,
        &["ip", "route", "add", "default", "via", IP_PUB],
    ));

    let in_dev = format!("ktn-{tag}i");
    let node_dev = format!("ktn-{tag}n");
    veth(
        End {
            dev: &in_dev,
            ns: nat_ns,
            ip: Some(inner),
        },
        End {
            dev: &node_dev,
            ns: node_ns,
            ip: Some(node),
        },
    );
    must(&nsr(
        node_ns,
        &["ip", "route", "add", "default", "via", inner],
    ));

    // Written to `/proc` rather than shelled out to `sysctl`, which lives in
    // `/usr/sbin` and so depends on how `sudo` was invoked.
    must(&nsr(
        nat_ns,
        &["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
    ));
    nat_rules(nat_ns, &out_dev, &in_dev, node, outer, flavour);
    if matches!(
        flavour,
        Flavour::SymmetricWithPortMapping | Flavour::PortRestrictedWithPortMapping
    ) {
        start_miniupnpd(net, tag, nat_ns, &out_dev, &in_dev, node);
    }
}

/// The datapath port every node listens on. A NAT that has to name a port
/// names this one.
const DATA_PORT: u16 = 51820;

/// Build an address-restricted cone, which Linux does not offer as a mode.
///
/// Two halves, and both are needed. A static `dnat` makes the mapping
/// endpoint-*independent* — `outer:51820` reaches the node whatever the source,
/// which plain masquerade will not do, because masquerade's reverse translation
/// only exists for a flow the inside started. A `seen` set then restores the
/// restriction that gives the flavour its name: an address the node has sent to
/// may come back **on any port**, and an address it has not may not come back
/// at all.
///
/// The timeout on the set matters. Without one an address is admitted forever
/// once contacted, which is a full cone wearing this row's name — and finding
/// 23 is what a fixture that lies about its own shape costs.
fn address_restricted(nat_ns: &str, out_dev: &str, in_dev: &str, node: &str) {
    must(&nsr(
        nat_ns,
        &[
            "nft",
            "add",
            "chain",
            "ip",
            "karst",
            "pre",
            "{ type nat hook prerouting priority -100 ; }",
        ],
    ));
    let dnat = format!("iifname {out_dev} udp dport {DATA_PORT} dnat to {node}:{DATA_PORT}");
    must(&nsr(
        nat_ns,
        &["nft", "add", "rule", "ip", "karst", "pre", &dnat],
    ));

    must(&nsr(
        nat_ns,
        &[
            "nft",
            "add",
            "set",
            "ip",
            "karst",
            "seen",
            "{ type ipv4_addr ; flags timeout ; timeout 60s ; }",
        ],
    ));
    // Not `fwd`: that is a reserved word in nft and the chain creation fails
    // with a syntax error pointing at the name.
    must(&nsr(
        nat_ns,
        &[
            "nft",
            "add",
            "chain",
            "ip",
            "karst",
            "filt",
            "{ type filter hook forward priority 0 ; }",
        ],
    ));
    for rule in [
        format!("iifname {in_dev} update @seen {{ ip daddr }} accept"),
        format!("iifname {out_dev} ip saddr @seen accept"),
        format!("iifname {out_dev} drop"),
    ] {
        must(&nsr(
            nat_ns,
            &["nft", "add", "rule", "ip", "karst", "filt", &rule],
        ));
    }
}

/// The translation and filtering rules, which are all that distinguishes one
/// [`Flavour`] from another.
fn nat_rules(nat_ns: &str, out_dev: &str, in_dev: &str, node: &str, outer: &str, flavour: Flavour) {
    // Linux conntrack's default masquerade: one external port reused across
    // destinations, return traffic accepted per flow — a port-restricted cone,
    // which `karst-disco`'s NAT matrix pins as behaving the way that name says.
    // `fully-random` is the one word that turns it symmetric, and the matrix
    // pins that too, with an assertion that fails if the ports come out equal.
    must(&nsr(nat_ns, &["nft", "add", "table", "ip", "karst"]));
    must(&nsr(
        nat_ns,
        &[
            "nft",
            "add",
            "chain",
            "ip",
            "karst",
            "post",
            "{ type nat hook postrouting priority 100 ; }",
        ],
    ));
    // **The outbound half of the mapping, installed by the fixture.** A real
    // NAT-PMP or PCP grant is bidirectional: the external port is reserved for
    // the internal one in both directions. `miniupnpd` writes the inbound DNAT
    // when the node asks; this pins the matching source translation so the pair
    // is consistent rather than dependent on masquerade's port-availability
    // heuristic. It grants nothing on its own — with the mapping refused, the
    // inbound side is still dropped, which is what the defect check turns on.
    if matches!(
        flavour,
        Flavour::SymmetricWithPortMapping | Flavour::PortRestrictedWithPortMapping
    ) {
        let fixed = format!(
            "oifname {out_dev} ip saddr {node} udp sport {DATA_PORT} snat to {outer}:{DATA_PORT}"
        );
        must(&nsr(
            nat_ns,
            &["nft", "add", "rule", "ip", "karst", "post", &fixed],
        ));
    }

    let rule = match flavour {
        Flavour::Symmetric | Flavour::SymmetricWithPortMapping => {
            format!("oifname {out_dev} masquerade fully-random")
        }
        Flavour::PortRestrictedCone
        | Flavour::PortRestrictedWithPortMapping
        | Flavour::UdpBlocked
        | Flavour::AddressRestrictedCone => {
            format!("oifname {out_dev} masquerade")
        }
    };
    must(&nsr(
        nat_ns,
        &["nft", "add", "rule", "ip", "karst", "post", &rule],
    ));

    if flavour == Flavour::AddressRestrictedCone {
        address_restricted(nat_ns, out_dev, in_dev, node);
    }

    // The firewall that forwards TCP and nothing else. Dropping UDP in the
    // **forward** hook rather than on one interface is deliberate: it blocks
    // the datapath socket in both directions, so AVEN cannot probe, cannot be
    // probed, and cannot reach the reflector either. That is the whole point of
    // the row — the relay has to be the answer, not merely the current best.
    if flavour == Flavour::UdpBlocked {
        must(&nsr(
            nat_ns,
            &[
                "nft",
                "add",
                "chain",
                "ip",
                "karst",
                "crossing",
                "{ type filter hook forward priority 0 ; }",
            ],
        ));
        must(&nsr(
            nat_ns,
            &[
                "nft", "add", "rule", "ip", "karst", "crossing", "meta", "l4proto", "udp", "drop",
            ],
        ));
    }

    // **Drop unsolicited inbound on the outer interface**, which is what makes
    // this a NAT rather than a host that happens to masquerade — and it is
    // load-bearing in a way that is not obvious.
    //
    // Without it, a peer's probe to this NAT's outer address is delivered to
    // the NAT namespace itself, which has no listener, so the kernel answers
    // ICMP unreachable and — the part that matters — **confirms a conntrack
    // entry for it**. That entry occupies the reply tuple
    // `(peer:51820 → outer:51820)`, so when the inside host later sends to that
    // same peer, masquerade cannot keep port 51820 and allocates a random one.
    // The node then advertises the mapped address it learned from the reflector
    // while actually sending from a different port, the two directions never
    // meet, and a port-restricted cone behaves like a symmetric NAT.
    //
    // A DROP here runs at filter priority 0, well before conntrack's confirm
    // hook, so the entry is never confirmed and the tuple is never taken. That
    // is also what a real NAT does, and `crates/karst-disco/tests/nat_matrix.rs`
    // already pins the forwarded half of the same rule.
    must(&nsr(
        nat_ns,
        &[
            "nft",
            "add",
            "chain",
            "ip",
            "karst",
            "input",
            "{ type filter hook input priority 0 ; }",
        ],
    ));
    for rule in [
        format!("iifname {out_dev} ct state established,related accept"),
        format!("iifname {out_dev} drop"),
    ] {
        must(&nsr(
            nat_ns,
            &["nft", "add", "rule", "ip", "karst", "input", &rule],
        ));
    }
}

/// Start `miniupnpd` on a NAT namespace whose outside address is globally
/// routable-looking, so PCP and NAT-PMP are actually served.
fn start_miniupnpd(
    net: &mut Aquifer,
    tag: &str,
    nat_ns: &str,
    out_dev: &str,
    in_dev: &str,
    node: &str,
) {
    must(&nsr(nat_ns, &["nft", "add", "table", "inet", "miniupnpd"]));
    for (chain, spec) in [
        ("prerouting", "{ type nat hook prerouting priority -100 ; }"),
        (
            "postrouting",
            "{ type nat hook postrouting priority 100 ; }",
        ),
        ("forward", "{ type filter hook forward priority 0 ; }"),
        ("miniupnpd", ""),
        ("prerouting-miniupnpd", ""),
        ("postrouting-miniupnpd", ""),
    ] {
        let mut args = vec!["nft", "add", "chain", "inet", "miniupnpd", chain];
        if !spec.is_empty() {
            args.push(spec);
        }
        must(&nsr(nat_ns, &args));
    }

    // miniupnpd writes the mapping rules into these named subchains. The hook
    // chains still need to jump to them, or the packets reach the NAT's outer
    // interface, hit no DNAT, and die on the namespace itself instead of ever
    // reaching the node behind it. That was measured in this row with a packet
    // capture: probes to the mapped port arrived on `ktn-ao`, but no reply was
    // possible because nothing forwarded them any further.
    must(&nsr(
        nat_ns,
        &[
            "nft",
            "add",
            "rule",
            "inet",
            "miniupnpd",
            "prerouting",
            "jump prerouting-miniupnpd",
        ],
    ));
    must(&nsr(
        nat_ns,
        &[
            "nft",
            "add",
            "rule",
            "inet",
            "miniupnpd",
            "postrouting",
            "jump postrouting-miniupnpd",
        ],
    ));
    must(&nsr(
        nat_ns,
        &[
            "nft",
            "add",
            "rule",
            "inet",
            "miniupnpd",
            "forward",
            "jump miniupnpd",
        ],
    ));

    let conf = net.dir.join(format!("miniupnpd-{tag}.conf"));
    std::fs::write(
        &conf,
        format!(
            "ext_ifname={out_dev}\n\
             listening_ip={in_dev}\n\
             enable_natpmp=yes\n\
             enable_upnp=no\n\
             secure_mode=no\n\
             system_uptime=yes\n\
             upnp_table_name=miniupnpd\n\
             upnp_nat_table_name=miniupnpd\n\
             upnp_forward_chain=miniupnpd\n\
             upnp_nat_chain=prerouting-miniupnpd\n\
             upnp_nat_postrouting_chain=postrouting-miniupnpd\n\
             allow 1024-65535 {node}/32 1024-65535\n\
             deny 0-65535 0.0.0.0/0 0-65535\n"
        ),
    )
    .expect("write miniupnpd config");
    net.spawn_service(
        nat_ns,
        "miniupnpd",
        &["-d", "-f", &conf.to_string_lossy()],
        &format!("miniupnpd-{tag}.log"),
    );
    std::thread::sleep(Duration::from_millis(800));
}

/// A veth pair, each end placed and optionally addressed.
fn veth(a: End<'_>, b: End<'_>) {
    must(&[
        "ip", "link", "add", a.dev, "type", "veth", "peer", "name", b.dev,
    ]);
    for end in [&a, &b] {
        must(&["ip", "link", "set", end.dev, "netns", end.ns]);
        if let Some(ip) = end.ip {
            let cidr = format!("{ip}/24");
            must(&nsr(end.ns, &["ip", "addr", "add", &cidr, "dev", end.dev]));
        }
        must(&nsr(end.ns, &["ip", "link", "set", end.dev, "up"]));
    }
}

/// `ip netns exec` with a leaked argv, for setup commands only.
fn nsr(ns: &str, args: &[&str]) -> Vec<&'static str> {
    let mut v: Vec<String> = vec!["ip".into(), "netns".into(), "exec".into(), ns.into()];
    v.extend(args.iter().map(|s| (*s).to_owned()));
    v.into_iter()
        .map(|s| &*Box::leak(s.into_boxed_str()))
        .collect()
}

/// Everything a node needs to reach the server and the relay.
struct Pins {
    kem: String,
    verify: String,
}

/// TLS material for the relays, written once and shared by all of them.
///
/// **One certificate, however many relays.** A node trusts a single
/// `relay_ca_file`, and what §4.2 pins is the relay's ML-DSA-65 identity rather
/// than its certificate — the TLS hop underneath is an ordinary validated one.
/// Two self-signed certificates would need the node to trust two anchors, which
/// tests the CA file rather than anything in the protocol.
fn relay_tls(net: &Aquifer) -> (PathBuf, PathBuf) {
    let cert_path = net.dir.join("relay.crt");
    let key_path = net.dir.join("relay.pem");
    if !cert_path.exists() {
        // Self-signed, which §4.2 makes fine and finding 16 made expressible:
        // this is the deployment `ponor-v1.md` calls the realistic self-hosted
        // one.
        let cert = rcgen::generate_simple_self_signed(vec!["relay.test".to_owned()])
            .expect("self-signed certificate");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        write_secret(&key_path, &cert.signing_key.serialize_pem());
    }
    (cert_path, key_path)
}

/// The roster both relays admit, written once.
///
/// From keys derived here rather than read back from a daemon that has not
/// started. A relay cannot verify a node it has not been told about (§5.3), so
/// it has to be told first.
fn relay_roster(net: &Aquifer) -> PathBuf {
    let roster_path = net.dir.join("roster.toml");
    if roster_path.exists() {
        return roster_path;
    }
    let mut roster = String::new();
    for seed in [SEED_A, SEED_B] {
        use std::fmt::Write as _;
        let _ = write!(
            roster,
            "[[client]]\nidentity_pk = \"{}\"\naquifer = \"t1\"\n\n",
            Base64::encode_string(&node_public(seed))
        );
    }
    std::fs::write(&roster_path, roster).expect("write roster");

    // **Renewed, because a relay that is not told its roster is current stops
    // admitting anyone** — `roster::MAX_AGE`, and deliberately so: a roster is
    // a membership list, and one nobody is refreshing is one nobody is
    // maintaining. A real deployment's control plane rewrites it; here a thread
    // touches it, which moves the fingerprint's mtime and renews the lease.
    //
    // The thread ends when the file does, which is when the fixture's directory
    // is removed. Rows that finish inside ninety seconds never needed this and
    // never noticed it was missing.
    let renewing = roster_path.clone();
    std::thread::spawn(move || {
        while renewing.exists() {
            std::thread::sleep(Duration::from_secs(20));
            let _ = filetime_now(&renewing);
        }
    });
    roster_path
}

/// Touch a file, so a watcher that fingerprints mtime sees it as renewed.
fn filetime_now(path: &Path) -> std::io::Result<()> {
    let contents = std::fs::read(path)?;
    std::fs::write(path, contents)
}

/// Start one relay on the public segment, and return its ML-DSA-65 public key
/// in hex — which the coordination server publishes in its registry.
///
/// `reflect` gives it AVEN's §7.7 reflector. Only the first relay needs one:
/// a second relay exists here to be *chosen* rather than to be discovered
/// through, and a reflector on it would be a second vantage point the tests
/// that use two relays do not exercise.
fn spawn_relay(net: &mut Aquifer, tag: &str, port: u16, reflect: bool) -> String {
    let (cert_path, key_path) = relay_tls(net);
    let roster_path = relay_roster(net);
    let relay_key = net.dir.join(format!("relay{tag}.key"));
    let relay_conf = net.dir.join(format!("relay{tag}.toml"));
    let reflect = if reflect {
        format!("\n[reflect]\nlisten = \"{IP_PUB}:{REFLECT_PORT}\"\n")
    } else {
        String::new()
    };
    std::fs::write(
        &relay_conf,
        format!(
            "listen = \"{IP_PUB}:{port}\"\n\
             identity_key = \"{}\"\n\
             roster = \"{}\"\n\
             tls_cert = \"{}\"\n\
             tls_key = \"{}\"\n\
             {reflect}",
            relay_key.display(),
            roster_path.display(),
            cert_path.display(),
            key_path.display()
        ),
    )
    .expect("write relay config");

    // Created here so the server can advertise it. The registry entry names the
    // key and the id is *derived* from it (§5.2), so the two cannot disagree.
    let identity = karst_relay::sign::Identity::load_or_create(&relay_key).expect("relay identity");
    let relay_pk = hex(identity.public_key());

    net.spawn_service(
        NS_PUB,
        &bin("karst-relay"),
        &["--config", &relay_conf.to_string_lossy()],
        &format!("relay{tag}.log"),
    );
    relay_pk
}

/// The relay every topology has: reflector and all.
fn start_relay(net: &mut Aquifer) -> (PathBuf, String) {
    let relay_pk = spawn_relay(net, "", RELAY_PORT, true);
    (net.dir.join("relay.crt"), relay_pk)
}

/// Build and start the Go coordination server, advertising the running relay.
fn start_server(net: &mut Aquifer, relay_pk: &str) -> Pins {
    start_server_with(
        net,
        &[(format!("{IP_PUB}:{RELAY_PORT}"), relay_pk.to_owned())],
    )
}

/// The same, advertising a registry of several relays.
///
/// **Order is meaningful.** A node with nothing measured holds the first entry,
/// so listing a relay first is how a test decides where both nodes begin.
fn start_server_with(net: &mut Aquifer, relays: &[(String, String)]) -> Pins {
    let server_bin = format!("{}/target/karst-testserver", repo());
    let build = Command::new("go")
        .args([
            "build",
            "-o",
            &server_bin,
            "./management/internals/karst/testserver/",
        ])
        .current_dir(format!("{}/server", repo()))
        .output()
        .expect("run `go build`");
    assert!(
        build.status.success(),
        "go build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let listen = format!("{IP_PUB}:{SERVER_PORT}");
    let mut argv: Vec<String> = [
        "netns",
        "exec",
        NS_PUB,
        &server_bin,
        "--netmap",
        "0",
        "--listen",
        &listen,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    for (address, key) in relays {
        argv.push("--relay".to_owned());
        argv.push(address.clone());
        argv.push(key.clone());
    }
    let relay_addr = relays.first().map(|(a, _)| a.clone()).unwrap_or_default();
    let mut server = Command::new("ip")
        .args(&argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            std::fs::File::create(net.dir.join("server.log")).expect("server log"),
        ))
        .spawn()
        .expect("spawn the coordination server");

    let stdout = server.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read the server's pins");
    net.services.push(server);
    // **Report what the server actually said.** An empty line here means it
    // exited before printing, and "EOF while parsing a value" names the JSON
    // parser rather than the process that failed to start.
    let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|e| {
        panic!(
            "the coordination server printed no pins ({e}); it was asked to \
             listen on {listen} and advertise a relay at {relay_addr}. Its \
             stdout was {line:?} and its stderr was:\n{}\n\
             addresses in {NS_PUB}:\n{}\n\
             relay.log:\n{}",
            std::fs::read_to_string(net.dir.join("server.log")).unwrap_or_default(),
            String::from_utf8_lossy(
                &Command::new("ip")
                    .args(["netns", "exec", NS_PUB, "ip", "-br", "addr"])
                    .output()
                    .map(|o| o.stdout)
                    .unwrap_or_default()
            ),
            std::fs::read_to_string(net.dir.join("relay.log")).unwrap_or_default()
        )
    });
    Pins {
        kem: v["static_kem"].as_str().expect("static_kem").to_owned(),
        verify: v["verify_key"].as_str().expect("verify_key").to_owned(),
    }
}

/// Write both daemons' keys and configuration.
fn write_node_configs(net: &Aquifer, pins: &Pins, ca: &Path, ips: (&str, &str)) {
    let port_mapping = if std::env::var_os("KARST_AQUIFER_DISABLE_PORT_MAPPING").is_some() {
        "false"
    } else {
        "true"
    };
    for (tag, seed, ip) in [("a", SEED_A, ips.0), ("b", SEED_B, ips.1)] {
        let d = net.dir.join(tag);
        std::fs::create_dir_all(&d).expect("node dir");
        write_secret(&d.join("identity.key"), &hex(&[seed; 32]));
        write_secret(&d.join("private.key"), &hex(&[seed; 96]));
        std::fs::write(
            d.join("karstd.toml"),
            format!(
                "[node]\n\
                 listen = \"{ip}:51820\"\n\
                 port_mapping = {port_mapping}\n\
                 interface = \"karst-tn{tag}\"\n\
                 private_key_file = \"{}\"\n\
                 psk_epoch = 7\n\n\
                 [control]\n\
                 server = \"http://{IP_PUB}:{SERVER_PORT}\"\n\
                 server_kem_pin = \"{}\"\n\
                 server_verify_pin = \"{}\"\n\
                 identity_key_file = \"{}\"\n\
                 setup_key = \"fixture\"\n\
                 cache_file = \"{}\"\n\
                 relay_ca_file = \"{}\"\n",
                d.join("private.key").display(),
                pins.kem,
                pins.verify,
                d.join("identity.key").display(),
                d.join("cache.bin").display(),
                ca.display(),
            ),
        )
        .expect("write node config");
    }
}

fn start_node(net: &mut Aquifer, tag: &str, ns: &str) {
    let conf = net.dir.join(tag).join("karstd.toml");
    let sock = net.dir.join(format!("{tag}.sock"));
    let _ = std::fs::remove_file(&sock);
    let child = net.launch(
        ns,
        &bin("karstd"),
        &[
            "--config",
            &conf.to_string_lossy(),
            "--socket",
            &sock.to_string_lossy(),
        ],
        &format!("{tag}.log"),
    );
    net.nodes.push((tag.to_owned(), child));
}

/// `karst status` from inside a namespace.
fn status(net: &Aquifer, tag: &str, ns: &str) -> String {
    let sock = net.dir.join(format!("{tag}.sock"));
    let out = Command::new("ip")
        .args([
            "netns",
            "exec",
            ns,
            &bin("karst"),
            "status",
            "--socket",
            &sock.to_string_lossy(),
        ])
        .output();
    out.map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Poll until `f` holds, or fail with everything that might explain why not.
///
/// **The diagnostic is the point.** Four processes in two namespaces fail in
/// ways no assertion message can anticipate, and the temporary directory is
/// gone by the time anyone reads the output — so a timeout prints both nodes'
/// status and every log, which is exactly what a person would go looking for.
/// Finding 18 exists because a silent relay failure was diagnosed by adding a
/// log line by hand; this is that lesson applied to the harness.
fn wait_for(net: &Aquifer, what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!(
        "timed out after {timeout:?} waiting for {what}\n\
         ── node A ──\n{}\n── node B ──\n{}\n\
         ── a.log ──\n{}\n── b.log ──\n{}\n── relay.log ──\n{}\
         {}",
        status(net, "a", NS_A),
        status(net, "b", NS_B),
        net.log("a.log"),
        net.log("b.log"),
        net.log("relay.log"),
        nat_state(),
    );
}

/// What each NAT is actually holding, at the moment the assertion gave up.
///
/// **The mapping is the thing under test in the NAT rows**, and it lives in the
/// kernel rather than in any process this fixture starts — so a failure with
/// four logs and no conntrack table names every component except the one that
/// decided the outcome. Empty when `conntrack` is not installed, which is a
/// missing tool rather than a reason to fail differently.
fn nat_state() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for ns in [NS_NAT_A, NS_NAT_B] {
        // `/proc/net/nf_conntrack` rather than the `conntrack` command,
        // which is a separate package and not installed on every CI image. The
        // file is there whenever the module is, which it is by the time a
        // masquerade rule has matched anything.
        let Ok(o) = Command::new("ip")
            .args([
                "netns",
                "exec",
                ns,
                "sh",
                "-c",
                "grep udp /proc/net/nf_conntrack || true",
            ])
            .output()
        else {
            return String::new();
        };
        let _ = write!(
            out,
            "\n── {ns} udp conntrack ──\n{}",
            String::from_utf8_lossy(&o.stdout)
        );
    }
    out
}

fn field(status: &str, key: &str) -> Option<String> {
    status
        .lines()
        .find(|l| l.starts_with(&format!("{key} = ")))
        .map(|l| {
            l.trim_start_matches(&format!("{key} = "))
                .trim_matches('"')
                .to_owned()
        })
}

// ── the test ────────────────────────────────────────────────────────────────

/// **The Phase 4 deliverable, end to end.**
///
/// Enrolment, a netmap carrying disco keys and a relay registry, a Ponor
/// connection over TLS, a PHREATIC handshake **through the relay**, an AVEN
/// rendezvous over it, probes on the shared UDP socket, the upgrade to a direct
/// path, and a TCP conversation under a port-scoped ACL.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn two_nodes_meet_on_the_relay_and_end_up_direct() {
    run(Shape::Flat);
}

/// **The same thing with a NAT in the way**, which is what §6 measures.
///
/// Node A is behind a port-restricted cone. Every address it can name is
/// private, so the direct path can only come from the sequence AVEN exists for:
/// B advertises a reachable address, A probes it through the NAT, and B learns
/// A's *mapped* address from the probe that arrives — the rule finding 20 added.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn two_nodes_punch_through_a_port_restricted_cone() {
    run(Shape::NatA);
}

/// **Both nodes behind NATs — two laptops on two home networks.**
///
/// The ordinary case, and the one that needed §7.6. Neither node can see its
/// own mapped address and neither can learn it from the other, because no probe
/// can cross until one of them has already advertised something reachable —
/// the reflexive mechanism needing a working path to bootstrap a working path.
/// That was finding 21, and this row is what it produced.
///
/// The reflector breaks the cycle from outside: each node asks the relay, over
/// **UDP from its datapath socket**, what address it is seen at, advertises
/// that, and the pair punches through in both directions at once.
///
/// **This row is the one that proves the reflector is load-bearing.** Every
/// other topology reaches a direct path without it — `Flat` needs no mapping at
/// all, and `NatA` gets one from finding 20's probe-source rule, because the
/// public node's probe crosses first. Removing `[reflect]` from the relay's
/// configuration fails this test and only this one.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn two_nodes_behind_nats_punch_through_with_a_reflector() {
    run(Shape::BothNat);
}

/// **A symmetric NAT is not the end of the road when the peer is reachable.**
///
/// Node A is behind a NAT that allocates a fresh external port per destination,
/// so nothing A knows about itself is useful: its interface addresses are
/// private and its reflexive address is the mapping toward the *reflector*,
/// which no peer shares. Every candidate A advertises is wrong.
///
/// The pair goes direct anyway, and the mechanism is finding 20's rule doing
/// the work `CallMeMaybe` cannot: A probes B's public address, and B takes the
/// address the probe **arrived from** in preference to anything A claimed. That
/// address is the mapping toward B, the one allocation of A's NAT that is
/// relevant, and it is knowable only by receiving a packet through it.
///
/// This row is why "symmetric NAT" is not a single number in §6. It is only
/// fatal when *both* ends are behind one — see
/// [`two_symmetric_nats_stay_on_the_relay_until_port_prediction_lands`].
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn a_symmetric_nat_reaches_a_reachable_peer_directly() {
    run(Shape::SymmetricA);
}

/// **One mapped side is enough for the doubly-symmetric case.**
///
/// A and B are both behind symmetric NATs, so the reflexive addresses each
/// learns from the reflector are still wrong for the peer. The difference from
/// [`two_symmetric_nats_stay_on_the_relay_until_port_prediction_lands`] is
/// that A's NAT also runs `miniupnpd`, and the daemon asks it for an explicit
/// mapping on the datapath port. B probes the mapped address A advertises, A
/// learns B from the probe that arrives, and the pair upgrades without any port
/// prediction at all.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn a_symmetric_nat_with_an_explicit_mapping_reaches_another_symmetric_nat_directly() {
    run(Shape::SymmetricAndMapped);
}

/// **The CGNAT-to-CGNAT row, asserting today's behaviour rather than the
/// intended one.**
///
/// Both nodes are behind symmetric NATs, so each reflexive address predicts a
/// mapping toward the reflector and neither predicts the mapping toward the
/// other. Port prediction is the piece that closes this (`aven-v1.md` §12.4)
/// and it is unbuilt, so the pair stays on the relay.
///
/// **The failure mode being guarded against is not "no direct path".** It is a
/// node advertising a reflexive address, a peer believing it, and the pair
/// reporting `direct` over an address that carries nothing — which looks like
/// success in `karst status` and is a black hole in practice. The settle window
/// exists for that, and the traffic assertion at the end is what makes the
/// relay path a *degradation* rather than an outage.
///
/// When port prediction lands, the expectation in [`Shape::expect`] changes and
/// nothing else here does.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn two_symmetric_nats_stay_on_the_relay_until_port_prediction_lands() {
    run(Shape::BothSymmetric);
}

/// **The second exit criterion, on its own terms: no UDP at all.**
///
/// Every other row lets AVEN work and watches the relay lose to it. Here the
/// NAT in front of A forwards TCP and drops every UDP datagram in both
/// directions, so there is no discovery to lose to: no probe leaves, no probe
/// arrives, and the reflector is unreachable, which also means A never learns a
/// reflexive address to advertise.
///
/// What has to hold is that the tunnel does not notice. Ponor is TCP, PHREATIC
/// rides it, and `Engine::via` picks the relay because no direct endpoint
/// exists — so the pair establishes, stays established, and carries a TCP
/// conversation under the ACL with nothing dropped.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn a_node_with_no_udp_at_all_still_carries_traffic_over_the_relay() {
    run(Shape::UdpBlocked);
}

/// **A symmetric NAT reaches a peer behind a NAT, when that NAT restricts
/// by address rather than by port.**
///
/// The row that keeps [`two_symmetric_nats_stay_on_the_relay_until_port_prediction_lands`]
/// from being read as "symmetric NAT means relayed". Nobody predicts A's mapped
/// port here either; the difference is that B's NAT does not require anyone to.
/// It admits any port from an address B has sent to, and B sends to A's outer
/// address because A advertised a reflexive candidate — one that is itself a
/// dead letter, and that earns its keep anyway.
///
/// Port prediction, when it lands, changes
/// [`Shape::BothSymmetric`] and leaves this row exactly as it is.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn a_symmetric_nat_reaches_an_address_restricted_peer_directly() {
    run(Shape::SymmetricAndAddressRestricted);
}

/// **The hard/easy pairing, which is where the literature's technique lives.**
///
/// A is behind a symmetric NAT, B behind a port-restricted cone — a CGNAT
/// subscriber talking to somebody on a home router. One word separates this
/// from [`a_symmetric_nat_reaches_an_address_restricted_peer_directly`]: B's
/// NAT checks the source port too.
///
/// **Stays relayed, and that is a settled answer rather than a pending one.**
/// The technique for it — §7.7's port search — was built, measured and declined
/// (finding 28). The row below is the same pairing when B's router offers a
/// port mapping, which is the answer this project did adopt; read the two
/// together or neither says anything useful.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn a_symmetric_nat_and_a_port_restricted_peer_stay_on_the_relay() {
    run(Shape::SymmetricAndPortRestricted);
}

/// **The same pairing, with the router offering a port mapping — and it goes
/// direct.**
///
/// The row above and this one differ by whether B's home router serves
/// NAT-PMP/PCP, and that is the whole distance between "relayed" and "direct"
/// for the commonest hard pairing there is. Recording only the row above would
/// be true and would misinform: it would read as a limit of the protocol when
/// it is a property of one NAT with nothing to ask.
///
/// **The mapping's inbound half is what does the work**, which is worth being
/// precise about because it is not why the mapping matters on
/// [`a_symmetric_nat_with_an_explicit_mapping_reaches_another_symmetric_nat_directly`].
/// B is a cone, so B's external port is already stable and A is already
/// probing the right address; B's NAT simply refuses a source port it has
/// never sent to. The DNAT removes that refusal. A's probe lands, B adopts the
/// source it arrived from — A's symmetric mapping toward B, the one allocation
/// that works — and the pair is direct.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn a_symmetric_nat_reaches_a_port_restricted_peer_that_can_map_a_port() {
    run(Shape::SymmetricAndPortRestrictedMapped);
}

/// **Two laptops on one home network.**
///
/// As ordinary as any row here, and missing until now. Both nodes learn a
/// reflexive address from the relay, both advertise it, and both then probe the
/// NAT's own outer address — which does not work, because Linux does not
/// hairpin (`nat_matrix.rs`'s `a_masquerading_nat_does_not_hairpin` pins that
/// with no Karst code involved).
///
/// The pair goes direct anyway, over the private segment, and the assertion is
/// that each node holds the other's `10.98.1.x` address. That makes
/// `aven-v1.md` §7.2's interface-address tier load-bearing rather than
/// decorative: on this topology it is the **only** tier that works, so a node
/// advertising reflexive addresses alone — the tempting simplification once
/// §7.6 exists, since they work on every other row — would relay two machines
/// on the same desk through the internet.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn two_nodes_on_one_home_network_go_direct_over_the_lan() {
    run(Shape::SameLan);
}

fn run(shape: Shape) {
    if !have_prerequisites() {
        return;
    }
    let mut net = Aquifer {
        dir: std::env::temp_dir().join(format!("karst-aquifer-{}", std::process::id())),
        services: Vec::new(),
        nodes: Vec::new(),
    };
    let _ = std::fs::remove_dir_all(&net.dir);
    std::fs::create_dir_all(&net.dir).expect("temp dir");
    let ips = build_topology(&mut net, shape);
    let (ca, relay_pk) = start_relay(&mut net);
    let pins = start_server(&mut net, &relay_pk);
    write_node_configs(&net, &pins, &ca, ips);

    // **A first, then B, then A again.** Each node's netmap is a snapshot taken
    // when it asks, and the server has no way to push. Starting A, letting it
    // enrol, then starting B gives B a netmap that already names A; restarting A
    // gives A one that names B. The alternative is waiting out the sixty-second
    // refresh, which is a real property of the daemon and a poor use of a test's
    // time.
    start_node(&mut net, "a", NS_A);
    wait_for(&net, "node A to come up", Duration::from_secs(30), || {
        net.log("a.log").contains("up, mtu")
    });
    start_node(&mut net, "b", NS_B);
    wait_for(
        &net,
        "node B to see its peer",
        Duration::from_secs(30),
        || field(&status(&net, "b", NS_B), "name").is_some(),
    );

    // Restart A so its first netmap includes B.
    net.stop_node("a", NS_A);
    start_node(&mut net, "a", NS_A);

    // Both begin on the relay: neither has an address for the other, because
    // the server never learned one. This is finding 12's whole point — a peer
    // with no endpoint is reachable, not dropped.
    converge(&net, shape);
    assert_endpoints(&net, shape);
    exchange_tcp_under_the_acl(&mut net);
}

/// Read both nodes' `transport` field at one moment.
fn transports(net: &Aquifer) -> (Option<String>, Option<String>) {
    (
        field(&status(net, "a", NS_A), "transport"),
        field(&status(net, "b", NS_B), "transport"),
    )
}

/// Hold the pair to what its topology permits — and only to that.
fn converge(net: &Aquifer, shape: Shape) {
    match shape.expect() {
        Expect::Direct => {
            let mut saw_relay = false;
            wait_for(
                net,
                "both nodes to reach a direct path",
                shape.budget(),
                || {
                    let (a, b) = transports(net);
                    if a.as_deref() == Some("relay") || b.as_deref() == Some("relay") {
                        saw_relay = true;
                    }
                    a.as_deref() == Some("direct") && b.as_deref() == Some("direct")
                },
            );
            assert!(
                saw_relay,
                "the pair never appeared on the relay, so this test did not \
                 observe the transition it exists to observe"
            );
        }
        Expect::Relay => {
            wait_for(
                net,
                "both sessions to establish",
                Duration::from_secs(60),
                || {
                    let (a, b) = transports(net);
                    a.as_deref() == Some("relay") && b.as_deref() == Some("relay")
                },
            );
            // **Then wait, and keep watching.** Establishing on the relay is
            // the easy half; the assertion worth making is that discovery does
            // not talk itself into a direct path it cannot use. Long enough for
            // several `Reflect` round trips (§7.5, ten seconds), a candidate's
            // whole probe backoff, and one re-probe of every alternative
            // (thirty seconds) — so a wrong candidate has had every chance to
            // be believed.
            let settle = Instant::now();
            while settle.elapsed() < Duration::from_secs(75) {
                let (a, b) = transports(net);
                assert_eq!(
                    (a.as_deref(), b.as_deref()),
                    (Some("relay"), Some("relay")),
                    "the pair claimed a direct path {:?} into the settle window, \
                     on a topology where no direct path exists — a node that \
                     advertises an address it is not reachable at is worse than \
                     one that stays relayed",
                    settle.elapsed()
                );
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

/// Both sessions are up, and each holds an address that can actually reach the
/// other.
///
/// **Behind a NAT that is not the address the peer advertised**: A's candidates
/// are all private, so B must be pointing at the mapped address the NAT
/// assigned — which is what hole punching produces, and the assertion that
/// would still pass if AVEN had merely copied what it was told.
fn assert_endpoints(net: &Aquifer, shape: Shape) {
    for (tag, ns) in [("a", NS_A), ("b", NS_B)] {
        let s = status(net, tag, ns);
        assert_eq!(field(&s, "state").as_deref(), Some("established"), "{s}");
    }
    if shape == Shape::SameLan {
        // **The assertion the row exists for.** Both nodes advertise a
        // reflexive address and both probe the NAT's outer address with it;
        // neither can work, because Linux does not hairpin. So a direct path
        // here is proof that the *interface* tier carried it — and holding the
        // peer's `10.98.1.x` address is what distinguishes that from a hairpin
        // that happened to work.
        for (tag, ns, want) in [("a", NS_A, IP_B_SAME_LAN), ("b", NS_B, IP_A_PRIVATE)] {
            let s = status(net, tag, ns);
            let endpoint = field(&s, "endpoint").unwrap_or_default();
            assert!(
                endpoint.starts_with(want),
                "node {tag} should hold its peer's private address {want}, not {endpoint}"
            );
            assert!(
                !endpoint.starts_with(NAT_A_OUTER),
                "node {tag} reached its peer at the NAT's outer address, which \
                 would mean this NAT hairpins and the row measures something \
                 else: {endpoint}"
            );
        }
        return;
    }

    if matches!(
        shape,
        Shape::NatA
            | Shape::BothNat
            | Shape::SymmetricA
            | Shape::SymmetricAndMapped
            | Shape::SymmetricAndAddressRestricted
            | Shape::SymmetricAndPortRestrictedMapped
    ) {
        let s = status(net, "b", NS_B);
        let endpoint = field(&s, "endpoint").unwrap_or_default();
        assert!(
            endpoint.starts_with(NAT_A_OUTER),
            "B should hold A's mapped address {NAT_A_OUTER}, not {endpoint}"
        );
        assert!(
            !endpoint.starts_with(IP_A_PRIVATE),
            "B is using A's private address, which cannot be reachable: {endpoint}"
        );
    }
    if matches!(
        shape,
        Shape::BothNat | Shape::SymmetricAndMapped | Shape::SymmetricAndAddressRestricted
    ) {
        // And symmetrically, which is the half only this row can check: A must
        // hold B's *mapped* address, learned from a reflector rather than from
        // a probe that arrived — because no probe from B could arrive until A
        // had already advertised something reachable.
        let s = status(net, "a", NS_A);
        let endpoint = field(&s, "endpoint").unwrap_or_default();
        assert!(
            endpoint.starts_with(NAT_B_OUTER),
            "A should hold B's mapped address {NAT_B_OUTER}, not {endpoint}"
        );
        assert!(
            !endpoint.starts_with(IP_B_PRIVATE),
            "A is using B's private address, which cannot be reachable: {endpoint}"
        );
    }
    if shape == Shape::SymmetricAndMapped {
        let s = status(net, "a", NS_A);
        let mapped = field(&s, "portmap_external").unwrap_or_default();
        assert!(
            mapped.starts_with(NAT_A_OUTER),
            "A should report its explicit mapping on {NAT_A_OUTER}, not {mapped}:\n{s}"
        );
        assert_eq!(field(&s, "portmap_protocol").as_deref(), Some("pcp"), "{s}");
    }
    if shape == Shape::SymmetricAndPortRestrictedMapped {
        // **The mapping is on B here, not on A** — the router side, not the
        // CGNAT side, which is what makes this row the realistic one. A is
        // behind carrier equipment it cannot ask for anything.
        let s = status(net, "b", NS_B);
        let mapped = field(&s, "portmap_external").unwrap_or_default();
        assert!(
            mapped.starts_with(NAT_B_OUTER),
            "B should report its explicit mapping on {NAT_B_OUTER}, not {mapped}:\n{s}"
        );
        assert_eq!(field(&s, "portmap_protocol").as_deref(), Some("pcp"), "{s}");
        // And A must have got nothing, which is the asymmetry the row is
        // about: one mapping, on one side, is enough.
        let s = status(net, "a", NS_A);
        assert_eq!(
            field(&s, "portmap_external").as_deref(),
            Some("-"),
            "A's NAT served a mapping, so this row is not the one-sided case \
             it claims to be:\n{s}"
        );
    }
}

/// A request **and its reply**, under a policy that permits `*:22` and nothing
/// else.
///
/// Split out because it is the half that finding 17 broke, and because it is
/// the only part of this test that would still be worth running if discovery
/// were removed entirely.
fn exchange_tcp_under_the_acl(net: &mut Aquifer) {
    // `allowed_ips = ["100.64.0.3/32"]` — the address, without the prefix
    // length, which is what a socket wants.
    let ranges = field(&status(net, "a", NS_A), "allowed_ips").expect("the peer's ranges");
    let peer_ip = ranges
        .trim_matches(|c: char| !c.is_ascii_digit())
        .split('/')
        .next()
        .expect("an address")
        .to_owned();
    assert!(
        peer_ip.parse::<std::net::Ipv4Addr>().is_ok(),
        "could not read the peer's overlay address out of {ranges:?}"
    );
    let listener = format!(
        "import socket\n\
         s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
         s.bind(('{peer_ip}',22)); s.listen(1)\n\
         c,_=s.accept(); c.sendall(b'over the tunnel'); c.close()\n"
    );
    net.spawn_service(NS_B, "python3", &["-c", &listener], "listener.log");
    std::thread::sleep(Duration::from_millis(1500));

    let client = format!(
        "import socket\n\
         s=socket.create_connection(('{peer_ip}',22),timeout=15)\n\
         print(s.recv(64).decode())\n"
    );
    let out = Command::new("ip")
        .args(["netns", "exec", NS_A, "python3", "-c", &client])
        .output()
        .expect("run the client");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("over the tunnel"),
        // **The counters, not just the traceback.** A timeout here says a
        // packet did not arrive and nothing about which end stopped carrying
        // it; `tx_packets` against `rx_packets` at both ends separates "never
        // sent" from "sent and lost" from "arrived and dropped by the ACL",
        // which are three different bugs that look identical from Python.
        "no TCP conversation across the tunnel: {} {}\n── node A ──\n{}\n\
         ── node B ──\n{}\n── a.log ──\n{}\n── b.log ──\n{}\n\
         ── relay.log ──\n{}\n── relay2.log ──\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        status(net, "a", NS_A),
        status(net, "b", NS_B),
        net.log("a.log"),
        net.log("b.log"),
        net.log("relay.log"),
        net.log("relay2.log"),
    );

    // Nothing was dropped by the ACL on the way. A reply denied here is exactly
    // what finding 17 looked like from the outside, and the counter is the only
    // place it was visible.
    for (tag, ns) in [("a", NS_A), ("b", NS_B)] {
        let s = status(net, tag, ns);
        assert_eq!(
            field(&s, "acl_denied_out").as_deref(),
            Some("0"),
            "node {tag} denied its own traffic:\n{s}"
        );
    }
}

/// **Two nodes on two relays, reaching each other — `ponor-v1.md` §9.1 end to
/// end.**
///
/// Every other row in this file has one relay, and with one relay §9.1's second
/// rule can never fire: both nodes hold the same connection and the relay
/// forwards between them. This row is the one that puts them on different
/// relays and makes the pair depend on the published `home_relay` — the field
/// that crosses the control plane, enters both content hashes, and until now
/// was never *read* by anything that carried a packet.
///
/// **How the two are separated is itself the point.** Node B cannot reach relay
/// 1 at all: a filter in its namespace drops the connection, which is what a
/// relay a node is not admitted to looks like from the outside (§10.1 makes a
/// roster miss deliberately indistinguishable from a relay that is down). So B
/// has to leave the relay its registry lists first and take the other, which is
/// the behaviour a per-region or per-tenant registry needs and which nothing
/// else here exercises.
///
/// Then A — still on relay 1, and with no way to know where B is — has to
/// discover B's absence by addressing it, read the relay B published, dial that
/// relay on demand, and carry a TCP conversation over it.
///
/// The topology is [`Shape::UdpBlocked`] so that the pair *stays* relayed:
/// on any shape where AVEN can work the direct path would displace the relay
/// within seconds, and this row would stop testing the thing it is here for.
#[test]
#[ignore = "needs root, network namespaces and a Go toolchain"]
fn two_nodes_on_two_relays_reach_each_other() {
    if !have_prerequisites() {
        return;
    }
    let mut net = Aquifer {
        dir: std::env::temp_dir().join(format!("karst-aquifer-{}", std::process::id())),
        services: Vec::new(),
        nodes: Vec::new(),
    };
    let _ = std::fs::remove_dir_all(&net.dir);
    std::fs::create_dir_all(&net.dir).expect("temp dir");

    let ips = build_topology(&mut net, Shape::UdpBlocked);
    let (ca, relay_pk) = start_relay(&mut net);
    let relay_pk_2 = spawn_relay(&mut net, "2", RELAY_PORT_2, false);
    let pins = start_server_with(
        &mut net,
        &[
            (format!("{IP_PUB}:{RELAY_PORT}"), relay_pk),
            (format!("{IP_PUB}:{RELAY_PORT_2}"), relay_pk_2),
        ],
    );
    write_node_configs(&net, &pins, &ca, ips);

    // **Relay 1 is unreachable from node B, and only from node B.** Dropped in
    // B's own namespace rather than at the relay, so that what B sees is a
    // connection that will not complete — which is all §10.1 lets a node see of
    // a relay that will not have it.
    must(&nsr(NS_B, &["nft", "add", "table", "ip", "karst"]));
    must(&nsr(
        NS_B,
        &[
            "nft",
            "add",
            "chain",
            "ip",
            "karst",
            "out",
            "{ type filter hook output priority 0 ; }",
        ],
    ));
    must(&nsr(
        NS_B,
        &[
            "nft",
            "add",
            "rule",
            "ip",
            "karst",
            "out",
            "tcp",
            "dport",
            &RELAY_PORT.to_string(),
            "drop",
        ],
    ));

    start_node(&mut net, "a", NS_A);
    wait_for(&net, "node A to come up", Duration::from_secs(30), || {
        net.log("a.log").contains("up, mtu")
    });
    start_node(&mut net, "b", NS_B);

    // B gives up on the relay it cannot reach and takes the other. Without
    // this a node whose registry lists a relay it is not admitted to first
    // would retry that one for the life of the process — nothing measures a
    // relay it has no connection to, so the alternatives would never be tried.
    wait_for(
        &net,
        "node B to leave the relay it cannot reach",
        Duration::from_secs(120),
        || net.log("b.log").contains("giving up on relay"),
    );
    wait_for(
        &net,
        "node B to see its peer",
        Duration::from_secs(60),
        || field(&status(&net, "b", NS_B), "name").is_some(),
    );

    // B publishes its move as soon as it happens, so restarting A here — the
    // same trick every other row uses for peers — gives A a netmap whose entry
    // for B already names relay 2. Without the restart A would wait out its own
    // sixty-second refresh, which is a real property of the daemon and a poor
    // use of a test's time.
    net.stop_node("a", NS_A);
    start_node(&mut net, "a", NS_A);

    // **The assertion this row exists for.** A is on relay 1, B is on relay 2,
    // and the only way a packet crosses is A reading what B published and
    // dialling it.
    wait_for(
        &net,
        "node A to dial the relay its peer published",
        Duration::from_secs(90),
        || {
            net.log("a.log")
                .contains("to reach a peer that published it as its home relay")
        },
    );
    wait_for(
        &net,
        "both nodes to establish over two relays",
        Duration::from_secs(90),
        || {
            let (a, b) = transports(&net);
            a.as_deref() == Some("relay")
                && b.as_deref() == Some("relay")
                && field(&status(&net, "a", NS_A), "state").as_deref() == Some("established")
                && field(&status(&net, "b", NS_B), "state").as_deref() == Some("established")
        },
    );

    // And traffic crosses it, which is the difference between a path that is
    // reported and a path that carries.
    exchange_tcp_under_the_acl(&mut net);

    // Node A never left the relay it started on: the second rule is about
    // reaching a peer elsewhere, not about following it.
    assert!(
        !net.log("a.log").contains("giving up on relay"),
        "node A moved relay too, so this row did not test two nodes on two \
         relays:\n{}",
        net.log("a.log")
    );
}
