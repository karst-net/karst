// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! TLS configuration for DoT connections, and SPKI pin hashing — ADR-0034.
//!
//! Deliberately not `bins/karstd/src/relay_tls.rs`'s config: that module
//! requires `X25519MLKEM768` because both TLS peers there are Karst's own
//! relay software. A DoT upstream is a third party — a public resolver
//! (Cloudflare, Quad9, ...) or a self-hosted one an admin names — and will
//! never offer Karst's PQ/CNSA suite.

use std::io;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};

/// The shared TLS 1.3 configuration for an unpinned DoT upstream, built once:
/// loading the system trust store is not free, and every unpinned upstream
/// trusts the same roots.
pub(super) fn shared_config() -> Result<Arc<ClientConfig>, io::Error> {
    static CONFIG: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| build_config().map_err(|error| error.to_string()))
        .clone()
        .map_err(io::Error::other)
}

fn build_config() -> Result<Arc<ClientConfig>, io::Error> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (native, _invalid) = roots.add_parsable_certificates(loaded.certs);
    if native == 0 {
        return Err(io::Error::other(
            "DoT: the host has no usable certificate authority roots",
        ));
    }
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
        .map(Arc::new)
}

/// A TLS 1.3 configuration for a pinned DoT upstream: ordinary CA-chain
/// verification is replaced entirely by a leaf-SPKI pin check, which is the
/// point of pinning — a self-hosted resolver with no public CA cert is
/// exactly the case ADR-0034's pinning option exists for, so requiring chain
/// validation to *also* pass would make pinning unusable for it. Built fresh
/// per call: unlike [`shared_config`], this does no I/O (no native-cert
/// loading), so there is nothing worth caching.
pub(super) fn pinned_config(pin: [u8; 32]) -> Result<Arc<ClientConfig>, io::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin, provider }))
                .with_no_client_auth()
        })
        .map(Arc::new)
}

/// Verifies a DoT resolver's certificate by SPKI pin alone, not by CA chain
/// or hostname — see [`pinned_config`].
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let hash = spki_sha256(end_entity).map_err(|error| TlsError::General(error.to_string()))?;
        if hash == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "DoT: resolver certificate does not match the configured pin".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// SHA-256 of a leaf certificate's DER-encoded SubjectPublicKeyInfo — the
/// conventional cert-pinning digest (curl `--pinnedpubkey`, historical HPKP),
/// independent of ADR-0018's CNSA hash choices, which govern PHREATIC only.
pub(super) fn spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32], io::Error> {
    let parsed = x509_cert::Certificate::from_der(cert.as_ref())
        .map_err(|error| io::Error::other(format!("DoT: malformed peer certificate: {error}")))?;
    let spki = parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|error| io::Error::other(format!("DoT: could not re-encode SPKI: {error}")))?;
    Ok(Sha256::digest(spki).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_roots_alone_are_a_valid_configuration() {
        assert!(shared_config().is_ok());
    }

    #[test]
    fn spki_hash_is_stable_for_the_same_certificate() {
        let cert = rcgen::generate_simple_self_signed(vec!["dot.test".to_owned()])
            .expect("self-signed cert");
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let first = spki_sha256(&der).expect("hash");
        let second = spki_sha256(&der).expect("hash again");
        assert_eq!(first, second);
    }

    #[test]
    fn spki_hash_differs_for_different_keys() {
        let a = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("cert a");
        let b = rcgen::generate_simple_self_signed(vec!["b.test".to_owned()]).expect("cert b");
        let der_a = CertificateDer::from(a.cert.der().to_vec());
        let der_b = CertificateDer::from(b.cert.der().to_vec());
        assert_ne!(
            spki_sha256(&der_a).expect("hash a"),
            spki_sha256(&der_b).expect("hash b")
        );
    }
}
