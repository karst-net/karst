// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The relay's ML-DSA-65 identity — `spec/ponor-v1.md` §5.2 and §5.5.

use std::path::Path;

use rand_core::{TryCryptoRng, TryRng};

use karst_relay_proto::consts::{IDENTITY_PK_LEN, ID_LEN, SIG_LEN};
use karst_relay_proto::{Signer, Verifier};
use sha2::{Digest, Sha256};

/// FIPS 204 context string.
///
/// Distinct from `karst-control-v1`'s, and that is load-bearing rather than
/// tidy: a node's Ponor and control-channel signatures are made with the **same
/// identity key**, so without separation a signature produced for one protocol
/// would be a valid value in the other.
const CTX: &[u8] = b"ponor-v1";

/// Domain label for a relay identifier — §5.2.
const RELAY_ID_LABEL: &[u8] = b"karst-relay-id-v1";

/// Domain label for a node identifier. The same value as the KARST-CONTROL
/// handle (§5.1); the handle is its base64 presentation.
const NODE_ID_LABEL: &[u8] = b"karst-node-handle-v1";

/// Seed from which the identity key is expanded.
pub const SEED_LEN: usize = 32;

/// `SHA-256("karst-relay-id-v1" ‖ relay_identity_pk)`.
#[must_use]
pub fn relay_id(identity_pk: &[u8]) -> [u8; ID_LEN] {
    let mut h = Sha256::new();
    h.update(RELAY_ID_LABEL);
    h.update(identity_pk);
    h.finalize().into()
}

/// `SHA-256("karst-node-handle-v1" ‖ identity_pk)`.
///
/// Separate label from [`relay_id`], and the disjointness is what makes §8's
/// role separation structural: a node id can never be found in the mesh
/// directory, so a role-confused `ClientAuth` fails on the lookup.
#[must_use]
pub fn node_id(identity_pk: &[u8]) -> [u8; ID_LEN] {
    let mut h = Sha256::new();
    h.update(NODE_ID_LABEL);
    h.update(identity_pk);
    h.finalize().into()
}

/// Errors loading an identity.
#[derive(Debug)]
pub enum Error {
    /// The seed file could not be read or written.
    Io(std::io::Error),
    /// The seed file is not 32 hex-encoded bytes.
    Malformed(String),
    /// The seed file is readable by somebody other than its owner.
    Permissions(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "identity: {e}"),
            Self::Malformed(m) | Self::Permissions(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// The relay's signing identity.
///
/// §5.2: this MUST NOT be the same key as any node identity, even when the
/// relay is co-located with the coordination server. The type system cannot
/// enforce that across process boundaries, so the seed lives in its own file
/// with its own path and [`Identity::load_or_create`] never reads a node's.
pub struct Identity {
    signing: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>,
    public: Vec<u8>,
    id: [u8; ID_LEN],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The id, not the key: it names the relay in a log line without
        // printing 1952 bytes, and the private half never renders at all.
        f.debug_struct("Identity")
            .field("relay_id", &hex(&self.id))
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Expand an identity from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let signing = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&(*seed).into());
        let public = signing.verifying_key().encode().to_vec();
        let id = relay_id(&public);
        Self {
            signing,
            public,
            id,
        }
    }

    /// Load the seed, creating one on first run.
    ///
    /// # Errors
    /// [`Error::Permissions`] if an existing file is readable beyond its owner,
    /// [`Error::Malformed`] if it is not 32 hex bytes, [`Error::Io`] otherwise.
    pub fn load_or_create(path: &Path) -> Result<Self, Error> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                check_permissions(path)?;
                let seed = unhex(text.trim())?;
                let seed: [u8; SEED_LEN] = seed.try_into().map_err(|_| {
                    Error::Malformed(format!("{}: seed is not 32 bytes", path.display()))
                })?;
                Ok(Self::from_seed(&seed))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut seed = [0u8; SEED_LEN];
                getrandom::fill(&mut seed)
                    .map_err(|e| Error::Io(std::io::Error::other(format!("no entropy: {e}"))))?;
                write_secret(path, &hex(&seed))?;
                Ok(Self::from_seed(&seed))
            }
            Err(source) => Err(Error::Io(source)),
        }
    }

    /// This relay's 32-byte identifier — §5.2.
    #[must_use]
    pub const fn relay_id(&self) -> [u8; ID_LEN] {
        self.id
    }

    /// The ML-DSA-65 verification key, for publication in the relay registry.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }
}

impl Signer for Identity {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>> {
        // **Hedged**, per §5.5. FIPS 204 permits either form; the randomized
        // one does not hand a fault-injection attacker a repeatable target.
        //
        // Note that `karstd`'s control-channel signer uses `sign_deterministic`
        // while `karst-control-v1.md` §6.3 carries the same SHOULD. That
        // divergence is real and predates this file; it is not copied here.
        let sig = self
            .signing
            .sign_randomized(message, CTX, &mut OsEntropy)
            .map_err(|_| "signing the Ponor handshake failed")?;
        Ok(sig.encode().to_vec())
    }
}

/// The operating system's CSPRNG, as `ml-dsa` wants it.
///
/// `rand_core` 0.10 ships no `OsRng`, and pulling in `rand` for one function
/// would add a dependency tree to call `getrandom` — which is already here.
/// Fifteen lines is the cheaper trade.
struct OsEntropy;

/// `getrandom::Error` does not implement `std::error::Error`, which
/// `TryRng::Error` requires.
#[derive(Debug)]
pub struct EntropyFailure(getrandom::Error);

impl std::fmt::Display for EntropyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the operating system refused entropy: {}", self.0)
    }
}

impl std::error::Error for EntropyFailure {}

impl TryRng for OsEntropy {
    type Error = EntropyFailure;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).map_err(EntropyFailure)
    }
}

// Sound: `getrandom` is the platform CSPRNG.
impl TryCryptoRng for OsEntropy {}

/// Verifies a peer's ML-DSA-65 signature against a key from the roster or the
/// relay registry.
#[derive(Debug, Clone, Copy)]
pub struct PonorVerifier;

impl Verifier for PonorVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Both arrive from the wire or from a roster file, so every failure is
        // `false` rather than a panic.
        let Ok(pk) = <[u8; IDENTITY_PK_LEN]>::try_from(public_key) else {
            return false;
        };
        let Ok(sg) = <[u8; SIG_LEN]>::try_from(signature) else {
            return false;
        };
        let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk.into());
        let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sg.into()) else {
            return false;
        };
        vk.verify_with_context(message, CTX, &sig)
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(text: &str) -> Result<Vec<u8>, Error> {
    if text.len() % 2 != 0 {
        return Err(Error::Malformed("odd number of hex digits".to_owned()));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let s = std::str::from_utf8(pair).map_err(|_| Error::Malformed("not hex".to_owned()))?;
        out.push(u8::from_str_radix(s, 16).map_err(|_| Error::Malformed("not hex".to_owned()))?);
    }
    Ok(out)
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path).map_err(Error::Io)?;
    let mode = meta.permissions().mode() & 0o077;
    if mode != 0 {
        return Err(Error::Permissions(format!(
            "{}: readable by group or other (mode {:o}); chmod 600 it",
            path.display(),
            meta.permissions().mode() & 0o777
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_: &Path) -> Result<(), Error> {
    Ok(())
}

fn write_secret(path: &Path, text: &str) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(Error::Io)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        // Created 0600 rather than created and then chmod-ed: between those
        // two steps the seed is world-readable, and that window is exactly
        // long enough on a busy machine.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(Error::Io)?;
        writeln!(f, "{text}").map_err(Error::Io)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, format!("{text}\n")).map_err(Error::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use karst_relay_proto::{client_auth_signing_input, Role};

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(&[seed; SEED_LEN])
    }

    #[test]
    fn a_signature_verifies_against_the_matching_key() {
        let k = identity(1);
        let msg = client_auth_signing_input(&[1; 32], &[2; 32], &[3; 32], &[4; 32], Role::Client);
        let sig = k.sign(&msg).expect("signing");
        assert_eq!(sig.len(), SIG_LEN);
        assert!(PonorVerifier.verify(k.public_key(), &msg, &sig));
    }

    #[test]
    fn a_signature_does_not_verify_against_another_key() {
        let a = identity(1);
        let b = identity(2);
        let msg = [7u8; 64];
        let sig = a.sign(&msg).expect("signing");
        assert!(!PonorVerifier.verify(b.public_key(), &msg, &sig));
    }

    #[test]
    fn a_signature_does_not_verify_over_another_message() {
        let k = identity(1);
        let sig = k.sign(&[7u8; 64]).expect("signing");
        assert!(!PonorVerifier.verify(k.public_key(), &[8u8; 64], &sig));
    }

    #[test]
    fn signing_is_hedged() {
        // §5.5 asks for the randomized form. Two signatures over the same
        // message must differ, and both must verify.
        let k = identity(1);
        let msg = [7u8; 64];
        let a = k.sign(&msg).expect("signing");
        let b = k.sign(&msg).expect("signing");
        assert_ne!(a, b, "signatures are deterministic — not hedged");
        assert!(PonorVerifier.verify(k.public_key(), &msg, &a));
        assert!(PonorVerifier.verify(k.public_key(), &msg, &b));
    }

    #[test]
    fn a_control_channel_signature_is_not_a_ponor_signature() {
        // The whole reason for the context string: the same identity key
        // signs in both protocols.
        let k = identity(1);
        let msg = [7u8; 64];
        let control = k
            .signing
            .sign_deterministic(&msg, b"karst-control-v1")
            .expect("signing")
            .encode()
            .to_vec();
        assert!(!PonorVerifier.verify(k.public_key(), &msg, &control));
    }

    #[test]
    fn malformed_keys_and_signatures_are_false_not_panics() {
        let k = identity(1);
        let msg = [7u8; 64];
        let sig = k.sign(&msg).expect("signing");
        assert!(!PonorVerifier.verify(&[], &msg, &sig));
        assert!(!PonorVerifier.verify(&[0; 10], &msg, &sig));
        assert!(!PonorVerifier.verify(k.public_key(), &msg, &[]));
        assert!(!PonorVerifier.verify(k.public_key(), &msg, &[0; SIG_LEN]));
        assert!(!PonorVerifier.verify(&[0; IDENTITY_PK_LEN], &msg, &sig));
    }

    #[test]
    fn node_and_relay_identifiers_never_collide() {
        // §8's role separation rests on this: a node id must never be findable
        // in the mesh directory.
        let pk = identity(1).public_key().to_vec();
        assert_ne!(node_id(&pk), relay_id(&pk));
    }

    #[test]
    fn the_relay_id_matches_the_specified_construction() {
        let pk = identity(3).public_key().to_vec();
        let mut h = Sha256::new();
        h.update(b"karst-relay-id-v1");
        h.update(&pk);
        let expected: [u8; ID_LEN] = h.finalize().into();
        assert_eq!(identity(3).relay_id(), expected);
    }

    #[test]
    fn a_seed_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("karst-relay-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("relay.key");

        let first = Identity::load_or_create(&path).expect("create");
        let second = Identity::load_or_create(&path).expect("load");
        assert_eq!(first.relay_id(), second.relay_id());
        assert_eq!(first.public_key(), second.public_key());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_seed_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("karst-relay-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.key");
        std::fs::write(&path, hex(&[9u8; SEED_LEN])).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        assert!(matches!(
            Identity::load_or_create(&path),
            Err(Error::Permissions(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_created_seed_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("karst-relay-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("relay.key");
        let _ = Identity::load_or_create(&path).expect("create");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o077, 0, "created mode {:o}", mode & 0o777);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
