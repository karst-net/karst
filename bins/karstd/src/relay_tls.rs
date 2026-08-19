// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! TLS configuration for node-to-relay Ponor connections.
//!
//! TLS authenticates the HTTPS endpoint and protects the hop. It does **not**
//! authenticate the relay: that remains [`crate::relay::Session`]'s pinned
//! ML-DSA-65 Ponor handshake. Keeping the two checks separate is §4.2's
//! central rule, especially for self-hosted relays behind shared TLS
//! termination.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};

use crate::netmap::Relay;

/// The hybrid key exchange required by Ponor §4.1.
const REQUIRED_GROUP: rustls::NamedGroup = rustls::NamedGroup::X25519MLKEM768;

/// TLS setup error for a relay connection.
#[derive(Debug)]
pub enum Error {
    /// The build was changed so it no longer offers the required hybrid group.
    NoPostQuantum,
    /// The host supplied no usable certificate authority roots.
    NoTrustRoots,
    /// The configured CA bundle could not be read.
    CaFile {
        /// Which file.
        path: std::path::PathBuf,
        /// Why not.
        source: std::io::Error,
    },
    /// The configured CA bundle held no certificate rustls would accept.
    ///
    /// Distinguished from a read failure because the two have different fixes,
    /// and because a bundle that parses to nothing would otherwise leave a node
    /// silently trusting only the system roots it was configured to supplement.
    NoUsableCa(std::path::PathBuf),
    /// The registry TLS name cannot be passed to rustls as SNI.
    ServerName(String),
    /// rustls rejected the narrow TLS 1.3-only configuration.
    Rustls(rustls::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPostQuantum => f.write_str(
                "relay TLS: this build does not offer X25519MLKEM768; refusing a classical fallback",
            ),
            Self::NoTrustRoots => {
                f.write_str("relay TLS: the host has no usable certificate authority roots")
            }
            Self::CaFile { path, source } => {
                write!(f, "relay TLS: cannot read {}: {source}", path.display())
            }
            Self::NoUsableCa(path) => write!(
                f,
                "relay TLS: {} contains no usable certificate authority",
                path.display()
            ),
            Self::ServerName(name) => write!(f, "relay TLS: invalid server name {name:?}"),
            Self::Rustls(error) => write!(f, "relay TLS: {error}"),
        }
    }
}

impl std::error::Error for Error {}

/// Build the TLS 1.3 configuration shared by relay connections.
///
/// `extra_ca` names a PEM bundle whose certificate authorities are trusted
/// **in addition to** the operating system's, for the self-signed and
/// internal-CA deployments `ponor-v1.md` §4.2 names. The Ponor identity pin
/// remains required after TLS succeeds and cannot be replaced by any of them —
/// what a CA here decides is which certificates the hop will accept, not who
/// the relay is.
///
/// # Errors
/// [`Error::NoPostQuantum`] when this binary cannot offer the required hybrid
/// KX; [`Error::NoTrustRoots`] when the operating system supplies no usable
/// roots; [`Error::CaFile`] or [`Error::NoUsableCa`] for a configured bundle
/// that cannot be read or holds nothing usable.
pub fn client_config(extra_ca: Option<&std::path::Path>) -> Result<Arc<ClientConfig>, Error> {
    use rustls::pki_types::pem::PemObject as _;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    if !provider
        .kx_groups
        .iter()
        .any(|group| group.name() == REQUIRED_GROUP)
    {
        return Err(Error::NoPostQuantum);
    }

    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (native, _invalid) = roots.add_parsable_certificates(loaded.certs);

    let mut configured = 0;
    if let Some(path) = extra_ca {
        // Every certificate in the bundle, not just the first: a chain to an
        // intermediate is the ordinary shape of an internal PKI, and taking one
        // would fail later as an unexplained verification error.
        let certs = rustls::pki_types::CertificateDer::pem_file_iter(path)
            .map_err(|source| Error::CaFile {
                path: path.to_owned(),
                source: std::io::Error::other(source.to_string()),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| Error::CaFile {
                path: path.to_owned(),
                source: std::io::Error::other(source.to_string()),
            })?;
        let (added, _invalid) = roots.add_parsable_certificates(certs);
        // **A bundle that parses to nothing is an error, not a no-op.** The
        // alternative is a node that was configured to trust a relay's CA,
        // silently does not, and fails every connection with a verification
        // error that names the wrong problem.
        if added == 0 {
            return Err(Error::NoUsableCa(path.to_owned()));
        }
        configured = added;
    }

    // Native roots are optional *only* when a bundle supplied some: a container
    // with no ca-certificates package is a normal place to run a node against a
    // self-hosted relay, and refusing there would make the configuration
    // useless exactly where it is most needed.
    if native == 0 && configured == 0 {
        return Err(Error::NoTrustRoots);
    }

    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(Error::Rustls)
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
        .map(Arc::new)
}

/// The SNI and certificate-validation name for a pinned relay.
///
/// This is intentionally not derived from [`Relay::address`], which names a
/// reachable socket and may be an IP or load-balancer target.
///
/// # Errors
/// Returns [`Error::ServerName`] for a malformed registry value.
pub fn server_name(relay: &Relay) -> Result<ServerName<'static>, Error> {
    ServerName::try_from(relay.tls_server_name.clone())
        .map_err(|_| Error::ServerName(relay.tls_server_name.clone()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn the_build_offers_the_required_hybrid_group() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        assert!(provider
            .kx_groups
            .iter()
            .any(|group| group.name() == REQUIRED_GROUP));
    }

    use crate::scratch::Scratch;

    #[test]
    fn the_system_roots_alone_are_a_valid_configuration() {
        // The default, and the right one for a relay with a public certificate.
        assert!(client_config(None).is_ok());
    }

    #[test]
    fn an_unreadable_ca_file_is_named_rather_than_ignored() {
        let dir = Scratch::new("missing");
        let path = dir.join("does-not-exist.pem");
        assert!(matches!(
            client_config(Some(&path)),
            Err(Error::CaFile { .. })
        ));
    }

    /// **A bundle that parses to nothing must fail loudly.** The alternative is
    /// a node that was configured to trust a relay's CA, silently does not, and
    /// reports every subsequent connection as a certificate verification
    /// failure — an error that names the wrong problem entirely.
    #[test]
    fn a_ca_file_with_no_usable_certificate_is_refused() {
        let dir = Scratch::new("empty");
        let path = dir.join("ca.pem");
        std::fs::write(&path, b"# a comment and nothing else\n").expect("write");
        assert!(matches!(
            client_config(Some(&path)),
            Err(Error::NoUsableCa(_))
        ));

        std::fs::write(&path, b"-----BEGIN CERTIFICATE-----\nnot base64\n").expect("write");
        assert!(client_config(Some(&path)).is_err());
    }

    /// Every certificate in the bundle is added, not just the first: a chain to
    /// an intermediate is the ordinary shape of an internal PKI, and taking one
    /// would surface later as an unexplained verification error.
    #[test]
    fn a_bundle_of_several_certificates_is_read_whole() {
        let Some(pem) = self_signed_pem(2) else {
            eprintln!("skipping: no certificate generator in this build");
            return;
        };
        let dir = Scratch::new("bundle");
        let path = dir.join("ca.pem");
        std::fs::write(&path, pem).expect("write");
        assert!(client_config(Some(&path)).is_ok());
    }

    /// Two self-signed certificates concatenated, or `None` if this build has
    /// no generator to make them with.
    fn self_signed_pem(count: usize) -> Option<String> {
        let mut out = String::new();
        for n in 0..count {
            let cert = rcgen::generate_simple_self_signed(vec![format!("relay{n}.test")]).ok()?;
            out.push_str(&cert.cert.pem());
        }
        Some(out)
    }
}
