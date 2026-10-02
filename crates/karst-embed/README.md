<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# `karst-embed` — embed a mesh node in your own process

`karst-embed` lets a Rust (or, via `bindings/go/karst`, Go) backend service
link in a Karst mesh node directly and become a reachable mesh peer itself —
no `karstd` process running alongside it, no kernel TUN device, no root.
This is GitHub issue #214's own scope; see
`docs/adr/0044-embedded-library-mode.md` for the design this README
describes.

This is **not** the same thing as `crates/karst-ffi`. That crate is for
mobile app shells (Swift/Kotlin) and the macOS `NEPacketTunnelProvider`
sandboxed-extension case — a GUI app adopting a platform-handed tunnel file
descriptor. `karst-embed` is for a headless backend process that wants to
*be* a mesh peer, driving ordinary TCP/UDP sockets over the mesh itself.

## How it works, in one paragraph

Under the hood, `karst-embed` runs the exact same engine `karstd` runs
(`bins/karstd/src/run.rs`), on a background thread, in
`network_mode = "userspace"` — the same pure-Rust, no-kernel-device IP stack
(`crates/karst-tun::Userspace`) already used for "containers that cannot
create a TUN device." Instead of a SOCKS5 proxy or published local ports
(what `karstd` itself offers an operator in that mode), `karst-embed` hands
your application direct TCP/UDP socket calls against that same stack.

## 1. Get an invitation

Before any of this, your application needs a **Karst enrollment
invitation** — the same `karst-invite-v1:...` string a human pastes into
`karst-setup`/`Karst.app`'s "Enroll…" screen (see `enrollment-process.md`
for the full administrator/user workflow this reuses verbatim). An
administrator mints one per device from the console/portal, scoped to an
account and permitted groups; it is a bearer credential; treat it
accordingly (not logged, not stored beyond the one enrollment call).

Your embedding application needs to get that string into its own process —
an environment variable, a secrets manager, a one-time setup flag — the same
way any other `karstd`-adjacent client does. `karst-embed` does not mint
invitations or talk to the console; it only *consumes* one, exactly once per
device identity.

## 2. Enroll

```rust
karst_embed::enroll(
    &invitation,                 // the pasted "karst-invite-v1:..." string
    Path::new("/srv/myapp/karst/config.toml"),
    Path::new("/srv/myapp/karst/state"),
)?;
```

This writes `config.toml` and creates this device's identity key under
`state/` — the same `karstd::enrollment::enroll_invitation` call
`karst-setup`'s bash script and `crates/karst-ffi`'s mobile boundary both
use, so you get the same bundle-parsing, control-plane handshake, and
config-publishing behavior they do, not a second, divergent path. Refuses if
`config.toml` already exists; use [`karst_embed::re_enroll`] to explicitly
replace an existing enrollment.

**Run this once per device, not on every process start.** A typical
embedding application checks whether `config.toml` already exists (or calls
[`karst_embed::identity_handle`] to check for an existing identity) and only
calls `enroll` the first time a given deployment comes up.

## 3. Make the config embeddable

`enroll` writes a config with `network_mode` defaulting to `"tun"` (a kernel
device your process almost certainly cannot or should not create) and no
`listen`-port deconfliction for a second node on the same host. Before
calling [`karst_embed::MeshNode::start`], your deployment tooling (or your
own code, reading and rewriting the file) needs to ensure the config has:

```toml
[node]
network_mode = "userspace"

# Required by karstd's own config validation (`validate_userspace`): a
# userspace stack with no attachment carries packets nothing can read. A
# karst-embed application doesn't use either feature — it attaches directly
# via MeshNode's own TCP/UDP calls — so a single harmless placeholder
# satisfies the check:
[[node.userspace_publish]]
port = 65535
to = "127.0.0.1:1"

# **The one setting every embedding caller needs to set explicitly.** Left
# absent, this defaults to a root-owned, fixed host path
# (/var/lib/karst/exit-route on Linux) meant for a single system-wide
# karstd. A non-root embedding process — or more than one embedded node on
# one host — will fail to start with a permission error trying to read it.
# Point it inside your own state directory instead:
exit_node_state_file = "/srv/myapp/karst/state/exit-route"
```

(Exit-node/managed-device functionality itself is out of scope for
`karst-embed` entirely — see the ADR's "minimal viable scope" — these two
settings exist only to satisfy `karstd`'s own general-purpose config
validation, which does not know it is being loaded by an embedder rather
than a full daemon.)

`listen` is also always written as `"0.0.0.0:51820"` — the same literal
default every `karstd` uses. If this host already runs a `karstd` (or
anything else) on that port, or you are embedding more than one node in one
process, give each node its own `listen` port by rewriting that line too, the
same way the `network_mode`/`exit_node_state_file` rewrites above work.

## 4. Start, use, stop

```rust
let node = karst_embed::MeshNode::start(
    Path::new("/srv/myapp/karst/config.toml"),
    Path::new("/srv/myapp/karst/control.sock"), // this process's own private socket
)?;

// Status, the same JSON `karst status --json` reports:
println!("{}", node.status_json()?);

// **Wait for the peer to be `established` before your first connect/send.**
// `connect_tcp`/`bind_udp` only set up a local socket — they have no way to
// know whether a session with the destination exists yet. A SYN or
// datagram sent before one does is silently dropped, and nothing times it
// out for you: poll `status_json()`'s `peers[].established` (or `karst
// status --json`'s identical field) until it's `true` first. Skip this and
// you get a hang, not an error — found running this crate's own
// `tests/two_nodes.rs` against a real deployment, see
// `docs/adr/0044-embedded-library-mode.md` item 7.

// Act as a server on the mesh:
let mut listener = node.listen_tcp(9000)?;
let (mut stream, peer_addr) = listener.accept()?;   // blocks until a peer connects
// `stream` implements std::io::Read/Write.

// Or act as a client:
let mut stream = node.connect_tcp("100.64.0.7".parse()?, 9000)?;
stream.write_all(b"hello")?;

// UDP works the same way:
let socket = node.bind_udp(5353)?;
socket.send_to(b"hi", "100.64.0.7:5353".parse()?)?;
let (data, from) = socket.recv_from();

node.stop(); // or just let it drop — stop() blocks until it's actually down
```

See `examples/mesh_echo.rs` for a complete, runnable program (enroll if
needed, start, either listen-and-echo or connect-and-send, print status) —
meant to be run by hand against a real deployed `karst-control`, with two
copies on two hosts (or two ports on one host, like the test below) talking
to each other.

## Scope: what this does not do (yet)

Per the ADR's "minimal viable scope": no exit-node consent, no
managed-device/MDM coexistence, no DNS resolution over the mesh. The
underlying `Userspace` stack supports both TCP and UDP; nothing here is a
half-finished protocol, only a deliberately narrow first slice of the
engine's full feature set.

## Verifying this actually works, not just compiles

`tests/two_nodes.rs` is the real proof, not a stub: it builds and starts the
actual Go coordination server on loopback (no namespaces, no root —
`network_mode = "userspace"` creates no kernel device), enrolls two
embedded nodes against it with real invitations, and asserts a real TCP
byte exchange between them with no `karstd` process anywhere. It passes.
See `docs/adr/0044-embedded-library-mode.md` item 7 for what it took to get
there — a real ordering race, a real root-owned-path gotcha, and one test-
fixture detail (its egress policy only grants port 22) that looked like a
connectivity bug until it wasn't. Run it yourself with:

```sh
cargo test -p karst-embed --test two_nodes -- --ignored
```

**One ordering rule this test had to learn the hard way, and your own code
needs too**: wait for `status_json`'s `peers[].established` to be `true`
before your first `connect_tcp`/`bind_udp` call. `connect_tcp` only sets up
a local socket — it has no way to know whether a session with the
destination exists yet — and a SYN sent too early is silently dropped, with
`smoltcp`'s own retry backoff then running on a clock unrelated to when the
session actually comes up. Skip this and you get a hang, not an error.

## Go

`bindings/go/karst` cgo-wraps a hand-rolled C ABI
(`crates/karst-embed-capi`) over this same crate, for Go backend services —
see that package's own doc comment for the build steps and its API, which
mirrors this one (`Enroll`/`Start`/`DialTCP`/`ListenTCP`/`BindUDP`, a
`net.Conn`/`net.Listener`/`net.PacketConn`-shaped surface).
