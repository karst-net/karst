// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `karst-relay` configuration.
//!
//! Every default here is chosen so that a *missing* setting is the safe one.
//! Where that is impossible — a TLS certificate has no safe default — the
//! field is required and [`Config::validate`] says so by name rather than
//! letting the relay start and fail on the first connection.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::hub;
use crate::limits::Budget;

/// Errors reading a configuration.
#[derive(Debug)]
pub enum Error {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file is not valid TOML, or a field has the wrong type.
    Syntax(String),
    /// A setting is missing, or cannot be satisfied.
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "config: {e}"),
            Self::Syntax(m) | Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// A relay's settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where to listen. Port 443 by default so the relay survives networks
    /// that permit only HTTPS, and so it can share a listener with the
    /// coordination server (spec §4.1).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// The relay's ML-DSA-65 identity seed. Created on first run.
    ///
    /// Its own path, never a node's: §5.2 forbids sharing a key between the
    /// two roles even when the processes share a host.
    #[serde(default = "default_identity")]
    pub identity_key: PathBuf,

    /// The signed roster of admitted nodes and configured mesh peers.
    ///
    /// **Required.** There is no default, because every default is wrong: an
    /// empty path would start a relay that admits nobody and looks broken, and
    /// any built-in path would be a guess about somebody's deployment.
    pub roster: PathBuf,

    /// PEM certificate chain.
    pub tls_cert: PathBuf,
    /// PEM private key.
    pub tls_key: PathBuf,

    /// Rate limits and queueing.
    #[serde(default)]
    pub limits: Limits,

    /// The AVEN reflector — `aven-v1.md` §7.6, `ponor-v1.md` §7.7.
    ///
    /// **Off unless configured**, which is the safe default here in the
    /// ordinary sense: a reflector is a UDP service that answers datagrams, and
    /// an operator who did not ask for one should not be running one.
    #[serde(default)]
    pub reflect: Option<Reflect>,

    /// Where to serve Prometheus metrics, if anywhere.
    ///
    /// **Its own listener, and off by default.** Sharing the client port would
    /// put an unauthenticated `GET` on the socket that carries the tailnet's
    /// traffic, and §5.3's admission is structural precisely so that port
    /// answers nothing it cannot verify. Off by default because a metrics
    /// endpoint is a disclosure surface — bounded, since it carries no
    /// per-node dimension, but one an operator should choose rather than
    /// inherit. Bind it to a management address.
    #[serde(default)]
    pub metrics: Option<Metrics>,

    /// Outbound mesh dialling — §8. Absent means this relay only accepts mesh
    /// connections and never opens one.
    #[serde(default)]
    pub mesh: Option<Mesh>,

    /// Which region this relay serves — §8, §9.
    ///
    /// **Mesh is within a region**, and §8 gives the reason: cross-region
    /// relay-to-relay forwarding would make every relay's bandwidth spendable
    /// by every other region's operator. A relay refuses to mesh with a peer
    /// whose region differs, so a peer from the wrong region in the mesh list
    /// is a startup-visible mistake rather than a slow bandwidth transfer.
    ///
    /// The default is deliberately a name rather than empty: a single-region
    /// deployment then works untouched, and two relays that both left it alone
    /// mesh with each other, which is what an operator who has never heard of
    /// regions expects.
    #[serde(default = "default_region")]
    pub region: String,
}

fn default_region() -> String {
    "default".to_owned()
}

/// How this relay dials its mesh peers — §8.
///
/// *Which* peers, and their addresses, come from the roster: they are admission
/// facts and belong with the identity keys they are checked against. This is
/// only what dialling needs that admission does not.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mesh {
    /// The certificate to trust when dialling a mesh peer.
    ///
    /// Required, with no fallback to system roots. §4.2 declines to trust
    /// certificates for relay identity, and a mesh that fell back to public
    /// roots would quietly accept anything a public CA had issued for the
    /// name — which is the trust §4.2 declines to place. For a self-signed
    /// peer, point this at that certificate.
    pub ca: PathBuf,
}

/// Where the metrics endpoint listens.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Address to serve `GET /metrics` on.
    pub listen: SocketAddr,
}

/// Where the reflector listens, and where clients are told to reach it.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reflect {
    /// The UDP address to bind. Its own socket, never the Ponor listener's:
    /// AVEN needs a **UDP** mapping and Ponor's is TCP, which a NAT maps
    /// separately.
    pub listen: SocketAddr,

    /// What to advertise in `ReflectOffer`, if not `listen`.
    ///
    /// Needed whenever `listen` is not reachable as written — an unspecified
    /// address, a container's internal address, a host behind a NAT of its own.
    /// A relay that advertised `0.0.0.0:3478` would send every client's
    /// `Reflect` into the void with nothing in any log to explain the silence,
    /// so [`Config::validate`] refuses that rather than shipping it.
    #[serde(default)]
    pub advertise: Option<SocketAddr>,
}

impl Reflect {
    /// The address to put in `ReflectOffer`.
    #[must_use]
    pub fn advertised(&self) -> SocketAddr {
        self.advertise.unwrap_or(self.listen)
    }
}

/// §7.3 and §7.4.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Sustained bytes per second, per node.
    #[serde(default = "default_bytes_per_sec")]
    pub bytes_per_sec: u64,
    /// Bytes a node may burst.
    #[serde(default = "default_byte_burst")]
    pub byte_burst: u64,
    /// Sustained frames per second, per node.
    #[serde(default = "default_frames_per_sec")]
    pub frames_per_sec: u64,
    /// Frames a node may burst.
    #[serde(default = "default_frame_burst")]
    pub frame_burst: u64,
    /// Per-destination write queue depth.
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        let b = Budget::default();
        Self {
            bytes_per_sec: b.bytes_per_sec,
            byte_burst: b.byte_burst,
            frames_per_sec: b.frames_per_sec,
            frame_burst: b.frame_burst,
            queue_depth: default_queue_depth(),
        }
    }
}

fn default_listen() -> SocketAddr {
    // Unspecified address, port 443 — spec §4.1.
    SocketAddr::from(([0, 0, 0, 0], 443))
}
fn default_identity() -> PathBuf {
    PathBuf::from("/etc/karst/relay.key")
}
fn default_bytes_per_sec() -> u64 {
    Budget::default().bytes_per_sec
}
fn default_byte_burst() -> u64 {
    Budget::default().byte_burst
}
fn default_frames_per_sec() -> u64 {
    Budget::default().frames_per_sec
}
fn default_frame_burst() -> u64 {
    Budget::default().frame_burst
}
fn default_queue_depth() -> usize {
    karst_relay_proto::consts::WRITE_QUEUE_DEPTH
}

impl Config {
    /// Parse a configuration from TOML.
    ///
    /// # Errors
    /// [`Error::Syntax`] for malformed TOML, a missing required field, or an
    /// unrecognized one.
    pub fn parse(text: &str) -> Result<Self, Error> {
        // `deny_unknown_fields`, so a mistyped key is an error rather than a
        // setting that silently does nothing. A relay whose rate limit is
        // spelled `byte_per_sec` should not start.
        toml::from_str(text).map_err(|e| Error::Syntax(format!("config: {e}")))
    }

    /// Read a configuration from disk.
    ///
    /// # Errors
    /// [`Error::Io`] if the file cannot be read, plus everything
    /// [`Self::parse`] returns.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(Error::Io)?;
        Self::parse(&text)
    }

    /// Check the things that can be checked without listening.
    ///
    /// # Errors
    /// [`Error::Invalid`] naming the setting at fault.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(metrics) = self.metrics {
            // **Refuse a metrics listener that shares the client port.** It
            // would put an unauthenticated `GET` on the socket carrying the
            // tailnet's traffic, and §5.3's admission is structural precisely
            // so that port answers nothing it cannot verify. A misconfiguration
            // that only shows up as a strange response to a scraper is one
            // worth refusing at startup.
            if metrics.listen == self.listen {
                return Err(Error::Invalid(
                    "config: metrics.listen must not be the Ponor listener's \
                     address; give it a management address of its own"
                        .to_owned(),
                ));
            }
            if let Some(reflect) = self.reflect {
                if metrics.listen == reflect.listen {
                    return Err(Error::Invalid(
                        "config: metrics.listen collides with reflect.listen".to_owned(),
                    ));
                }
            }
        }
        if self.limits.queue_depth == 0 {
            // Not merely useless: a zero-depth queue silently discards every
            // frame, which is a relay that accepts connections and forwards
            // nothing. Better to refuse to start.
            return Err(Error::Invalid(
                "config: limits.queue_depth must be at least 1".to_owned(),
            ));
        }
        if self.limits.bytes_per_sec == 0 || self.limits.frames_per_sec == 0 {
            return Err(Error::Invalid(
                "config: a zero rate admits nothing; omit the field for the \
                 default, or set it high for no practical limit"
                    .to_owned(),
            ));
        }
        if let Some(r) = &self.reflect {
            let a = r.advertised();
            if a.ip().is_unspecified() || a.port() == 0 {
                // A client told to send `Reflect` to 0.0.0.0 sends it nowhere,
                // and the symptom is a node that never gets a direct path with
                // nothing in any log to explain why. Binding the unspecified
                // address is fine and usual; advertising it is not.
                return Err(Error::Invalid(format!(
                    "config: reflect.advertise = {a} is not an address a client \
                     can reach; set reflect.advertise to this relay's public \
                     UDP address"
                )));
            }
        }
        for (name, path) in [
            ("roster", &self.roster),
            ("tls_cert", &self.tls_cert),
            ("tls_key", &self.tls_key),
        ] {
            if !path.exists() {
                return Err(Error::Invalid(format!(
                    "config: {name} = {} does not exist",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// The hub configuration these settings imply.
    #[must_use]
    pub fn hub(&self) -> hub::Config {
        hub::Config {
            client_budget: Budget {
                bytes_per_sec: self.limits.bytes_per_sec,
                byte_burst: self.limits.byte_burst,
                frames_per_sec: self.limits.frames_per_sec,
                frame_burst: self.limits.frame_burst,
            },
            // A meshed relay carries many nodes' traffic and cannot share a
            // node's allowance. It is configured infrastructure rather than an
            // admitted stranger, so the operator's own limits apply upstream.
            mesh_budget: Budget::unlimited(),
            queue_depth: self.limits.queue_depth,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    const MINIMAL: &str = r#"
roster = "/etc/karst/roster.toml"
tls_cert = "/etc/karst/relay.crt"
tls_key = "/etc/karst/relay.key"
"#;

    #[test]
    fn a_minimal_config_takes_the_documented_defaults() {
        let c = Config::parse(MINIMAL).expect("parses");
        assert_eq!(c.listen, SocketAddr::from(([0, 0, 0, 0], 443)));
        assert_eq!(c.identity_key, PathBuf::from("/etc/karst/relay.key"));
        assert_eq!(c.limits.queue_depth, 32);
        assert_eq!(c.limits.bytes_per_sec, 25 * 1_000_000 / 8);
    }

    #[test]
    fn the_roster_path_is_required() {
        // No default is right: an empty path admits nobody and looks broken,
        // and a built-in path is a guess about somebody's deployment.
        let err = Config::parse("tls_cert = \"a\"\ntls_key = \"b\"\n").expect_err("no roster");
        assert!(matches!(err, Error::Syntax(_)), "{err:?}");
        assert!(format!("{err}").contains("roster"), "{err}");
    }

    #[test]
    fn a_mistyped_key_is_an_error() {
        // Otherwise a relay whose rate limit is spelled `byte_per_sec` starts
        // happily with the default and nobody finds out until it matters.
        let text = format!("{MINIMAL}\n[limits]\nbyte_per_sec = 100\n");
        let err = Config::parse(&text).expect_err("unknown field");
        assert!(format!("{err}").contains("byte_per_sec"), "{err}");
    }

    #[test]
    fn a_zero_queue_depth_is_refused() {
        // A zero-depth queue accepts connections and forwards nothing.
        let text = format!("{MINIMAL}\n[limits]\nqueue_depth = 0\n");
        let c = Config::parse(&text).expect("parses");
        let err = c.validate().expect_err("zero depth");
        assert!(format!("{err}").contains("queue_depth"), "{err}");
    }

    #[test]
    fn a_zero_rate_is_refused_rather_than_read_as_unlimited() {
        // The recurring rule: an absent or zeroed value must never read as
        // permissive — but here it reads as *prohibitive*, which is equally
        // surprising, so the operator is told instead of guessed at.
        let text = format!("{MINIMAL}\n[limits]\nbytes_per_sec = 0\n");
        let c = Config::parse(&text).expect("parses");
        assert!(c.validate().is_err());

        let text = format!("{MINIMAL}\n[limits]\nframes_per_sec = 0\n");
        let c = Config::parse(&text).expect("parses");
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_names_the_file_that_is_missing() {
        let c = Config::parse(MINIMAL).expect("parses");
        let err = c.validate().expect_err("nothing exists");
        let text = format!("{err}");
        assert!(text.contains("roster"), "{text}");
        assert!(text.contains("/etc/karst/roster.toml"), "{text}");
    }

    #[test]
    fn limits_reach_the_hub() {
        let text = format!("{MINIMAL}\n[limits]\nbytes_per_sec = 1234\nqueue_depth = 7\n");
        let c = Config::parse(&text).expect("parses");
        let h = c.hub();
        assert_eq!(h.client_budget.bytes_per_sec, 1234);
        assert_eq!(h.queue_depth, 7);
        // The mesh allowance is deliberately not the client's.
        assert_eq!(h.mesh_budget, Budget::unlimited());
    }

    #[test]
    fn the_reflector_is_off_unless_configured() {
        // A reflector answers UDP datagrams. An operator who did not ask for
        // one should not be running one.
        let c = Config::parse(MINIMAL).expect("parses");
        assert!(c.reflect.is_none());
    }

    #[test]
    fn an_unreachable_advertised_reflector_address_is_refused() {
        // Binding the unspecified address is usual; advertising it sends every
        // client's `Reflect` into the void, and the symptom is a node that
        // never gets a direct path with nothing in any log to say why.
        let text = format!("{MINIMAL}\n[reflect]\nlisten = \"0.0.0.0:3478\"\n");
        let c = Config::parse(&text).expect("parses");
        let err = c.validate().expect_err("unspecified advertise");
        assert!(format!("{err}").contains("reflect.advertise"), "{err}");

        // With an explicit advertise address it gets past this check and on to
        // the file checks, which is what should stop it next.
        let text = format!(
            "{MINIMAL}\n[reflect]\nlisten = \"0.0.0.0:3478\"\n\
             advertise = \"203.0.113.7:3478\"\n"
        );
        let c = Config::parse(&text).expect("parses");
        let err = c.validate().expect_err("files are missing");
        assert!(format!("{err}").contains("roster"), "{err}");
    }

    #[test]
    fn a_reflector_advertises_its_listen_address_by_default() {
        let text = format!("{MINIMAL}\n[reflect]\nlisten = \"203.0.113.7:3478\"\n");
        let c = Config::parse(&text).expect("parses");
        let r = c.reflect.expect("configured");
        assert_eq!(r.advertised(), r.listen);
    }

    #[test]
    fn a_listen_address_can_be_overridden() {
        let text = format!("{MINIMAL}\nlisten = \"127.0.0.1:8443\"\n");
        let c = Config::parse(&text).expect("parses");
        assert_eq!(c.listen, "127.0.0.1:8443".parse().expect("addr"));
    }
}
