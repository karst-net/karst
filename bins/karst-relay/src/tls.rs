// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! TLS for the relay listener — `spec/ponor-v1.md` §4.1.
//!
//! Two things this module is responsible for, and one it deliberately is not.
//!
//! It **enforces the post-quantum key exchange**. §4.1 makes
//! `X25519MLKEM768` a MUST-offer because a relay is where a whole network's
//! metadata converges, which makes recording that hop the cheapest possible
//! harvest-now-decrypt-later target. [`provider`] checks the negotiated
//! provider actually offers it and refuses to start otherwise, so a
//! feature-flag change cannot quietly turn a post-quantum relay into a
//! classical one.
//!
//! It **loads the certificate**, which is required and validated because it is
//! what makes the connection behave like HTTPS.
//!
//! It does **not** establish the relay's identity. §4.2: that is an ML-DSA-65
//! signature over a key from the relay registry, and a client MUST NOT treat
//! certificate validation as authentication of the relay. The certificate here
//! could be self-signed and the protocol would be no weaker.

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// The key exchange §4.1 requires.
const REQUIRED_GROUP: rustls::NamedGroup = rustls::NamedGroup::X25519MLKEM768;

/// Errors setting up TLS.
#[derive(Debug)]
pub enum Error {
    /// A certificate or key file could not be read.
    Io(std::io::Error),
    /// A PEM file held no certificate, or no private key.
    Pem(String),
    /// The build does not offer the post-quantum key exchange.
    NoPostQuantum,
    /// `rustls` refused the certificate and key.
    Rustls(rustls::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "tls: {e}"),
            Self::Pem(m) => f.write_str(m),
            Self::NoPostQuantum => f.write_str(
                "tls: this build does not offer X25519MLKEM768, which \
                 spec/ponor-v1.md §4.1 requires. Rebuild with the aws-lc-rs \
                 provider and the prefer-post-quantum feature.",
            ),
            Self::Rustls(e) => write!(f, "tls: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// The crypto provider, checked to offer the hybrid group.
///
/// # Errors
/// [`Error::NoPostQuantum`] if `X25519MLKEM768` is absent. This is a startup
/// assertion rather than a comment: the group is supplied by a Cargo feature,
/// and a feature is exactly the kind of thing that gets changed by somebody
/// solving an unrelated build problem.
pub fn provider() -> Result<Arc<CryptoProvider>, Error> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    if !provider
        .kx_groups
        .iter()
        .any(|g| g.name() == REQUIRED_GROUP)
    {
        return Err(Error::NoPostQuantum);
    }
    Ok(Arc::new(provider))
}

/// Whether the hybrid group is *preferred* rather than merely available.
///
/// Offered-but-last is a real configuration and a weak one: the client picks,
/// and a client that prefers speed gets a classical exchange from a relay that
/// believed it was post-quantum. Reported at startup rather than enforced,
/// because ordering is rustls's to choose and a future release reordering it
/// should be visible rather than fatal.
#[must_use]
pub fn post_quantum_is_preferred(provider: &CryptoProvider) -> bool {
    provider
        .kx_groups
        .first()
        .is_some_and(|g| g.name() == REQUIRED_GROUP)
}

/// Build the listener's TLS configuration.
///
/// # Errors
/// [`Error::Io`] if a file cannot be read, [`Error::Pem`] if it holds no
/// certificate or key, [`Error::Rustls`] if the pair is not usable.
pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, Error> {
    let provider = provider()?;

    // A file that does not exist and a file with no certificate in it are
    // different problems with different fixes, so they get different errors —
    // `pem_file_iter` collapses both into one variant, hence the explicit
    // existence check first.
    if !cert.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} not found", cert.display()),
        )));
    }
    if !key.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} not found", key.display()),
        )));
    }

    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| Error::Pem(format!("tls: {}: {e}", cert.display())))?
        .collect::<Result<_, _>>()
        .map_err(|e| Error::Pem(format!("tls: {}: {e}", cert.display())))?;
    if chain.is_empty() {
        return Err(Error::Pem(format!(
            "tls: {} contains no certificate",
            cert.display()
        )));
    }

    let private = PrivateKeyDer::from_pem_file(key).map_err(|e| {
        Error::Pem(format!(
            "tls: {} contains no private key: {e}",
            key.display()
        ))
    })?;

    let config = ServerConfig::builder_with_provider(provider)
        // TLS 1.3 only. §4.1 is about the key exchange, and 1.2 cannot express
        // the hybrid group at all — leaving it enabled would be leaving the
        // requirement negotiable.
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(Error::Rustls)?
        // The relay does not authenticate clients with certificates. It
        // authenticates them with §5.3's roster, after the upgrade, which is
        // the only mechanism that can express "this node, in this tailnet".
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .map_err(Error::Rustls)?;

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_provider_offers_the_post_quantum_group() {
        // §4.1's MUST, checked against the build rather than assumed from the
        // Cargo.toml comment next to the feature flag.
        let p = provider().expect("the build offers X25519MLKEM768");
        assert!(p.kx_groups.iter().any(|g| g.name() == REQUIRED_GROUP));
    }

    #[test]
    fn the_post_quantum_group_is_preferred() {
        // Offered-but-last would let a client that prefers speed get a
        // classical exchange from a relay that believed it was post-quantum.
        let p = provider().expect("provider");
        assert!(
            post_quantum_is_preferred(&p),
            "kx groups are {:?}",
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_missing_certificate_is_named() {
        let err = server_config(Path::new("/nonexistent.crt"), Path::new("/nonexistent.key"))
            .expect_err("no such file");
        assert!(matches!(err, Error::Io(_)), "{err:?}");
    }

    #[test]
    fn a_pem_file_with_no_certificate_is_refused() {
        let dir = std::env::temp_dir().join(format!("karst-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let cert = dir.join("empty.crt");
        let key = dir.join("empty.key");
        std::fs::write(&cert, "# nothing here\n").expect("write");
        std::fs::write(&key, "# nothing here\n").expect("write");

        let err = server_config(&cert, &key).expect_err("empty pem");
        assert!(matches!(err, Error::Pem(_)), "{err:?}");
        assert!(format!("{err}").contains("no certificate"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
