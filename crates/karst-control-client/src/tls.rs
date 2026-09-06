// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! TLS for the control channel, when `[control] server` names an `https://`
//! endpoint.
//!
//! This is transport wrapping, not authentication. ADR-0011's whole point is
//! that the control channel authenticates itself: an ML-KEM-768 encapsulation
//! keys the session, and the server's ML-DSA-65 signature over
//! `ChannelHello` (checked in [`crate::transport::Session::open`], which
//! returns [`crate::transport::Error::ServerAuth`] on failure) proves who it
//! is — independently of whatever carries the bytes. A validated TLS
//! certificate would duplicate a check the channel already makes, and a node
//! sitting behind a certificate the operator did not personally choose (an
//! `on_demand` cert from a reverse proxy, say) has no weaker guarantee than
//! one that chained to a root store. So this verifier accepts whatever
//! certificate the server presents — there is no CA to provision or rotate —
//! and leaves the actual authentication to the pins, exactly as
//! `relay_tls.rs` leaves relay identity to the pinned Ponor handshake rather
//! than the certificate chain.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// A [`ServerCertVerifier`] that accepts every certificate. See the module
/// docs for why that is the right call for this one channel.
#[derive(Debug)]
pub(crate) struct AcceptAny {
    provider: Arc<CryptoProvider>,
}

impl AcceptAny {
    pub(crate) fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// The one behavior this module exists for: a certificate with no chain
    /// to any root, for a name nobody asked about, still verifies. A strict
    /// verifier would reject this on both counts — self-signed and a name
    /// mismatch — which is exactly why control-channel identity cannot be
    /// allowed to rest on this check.
    #[test]
    fn a_self_signed_certificate_for_an_unrelated_name_still_verifies() {
        let cert = rcgen::generate_simple_self_signed(vec!["not-the-host.example".to_owned()])
            .expect("self-signed cert");
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let name = ServerName::try_from("totally-different-host.example").expect("server name");

        assert!(AcceptAny::new()
            .verify_server_cert(&der, &[], &name, &[], UnixTime::now())
            .is_ok());
    }
}
