// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The set of peers this relay will speak to — `spec/ponor-v1.md` §5.3.
//!
//! This file is the whole of admission control, and §5.3's claim rests on one
//! property of it: **`ClientAuth` carries no public key**, so the relay
//! verifies against a key it finds here or it does not verify at all. There is
//! deliberately no constructor, no flag and no fallback that admits a peer this
//! file has not been told about.
//!
//! # The format derives, it does not repeat
//!
//! An entry names an ML-DSA-65 public key and nothing else. The node id and
//! relay id are **computed** from it (§5.1, §5.2) rather than stored beside it,
//! so an entry whose id disagrees with its key is not a thing that can be
//! written. The alternative — carrying both — makes a silent mismatch a
//! two-character typo away, and the failure mode is a node that cannot connect
//! for reasons no log line explains.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use base64ct::{Base64, Encoding as _};
use karst_relay_proto::consts::{IDENTITY_PK_LEN, ID_LEN};
use karst_relay_proto::{RelayEntry, Roster, RosterEntry, TailnetId};
use serde::Deserialize;

use crate::hub::Id;
use crate::sign::{node_id, relay_id, Identity, SEED_LEN};

/// Errors loading a roster.
#[derive(Debug)]
pub enum Error {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file is not valid TOML.
    Syntax(String),
    /// An entry's key is not a 1952-byte ML-DSA-65 public key.
    BadKey(String),
    /// Two entries derive the same identifier.
    Duplicate(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "roster: {e}"),
            Self::Syntax(m) | Self::BadKey(m) | Self::Duplicate(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Deserialize)]
struct File {
    #[serde(default)]
    client: Vec<ClientRow>,
    #[serde(default)]
    mesh: Vec<MeshRow>,
}

#[derive(Debug, Deserialize)]
struct ClientRow {
    /// Standard base64 of the 1952-byte ML-DSA-65 identity key.
    identity_pk: String,
    /// The tailnet this node belongs to. Forwarding is scoped by it (§5.4).
    tailnet: String,
}

#[derive(Debug, Deserialize)]
struct MeshRow {
    identity_pk: String,
}

/// A roster loaded from a file.
///
/// The decoy key is generated when the roster is built and is never written
/// anywhere. See [`Roster::decoy_key`] and §10.1: without it, an unknown id is
/// rejected by a map lookup while a known one with a bad signature costs a full
/// ML-DSA verification, and the difference is a membership oracle any
/// unauthenticated caller can read at one connection per guess.
pub struct FileRoster {
    clients: HashMap<Id, RosterEntry>,
    mesh: HashMap<Id, RelayEntry>,
    decoy: Vec<u8>,
}

/// A roster file watched by the relay's reload loop.
///
/// The source intentionally treats an atomically replaced file with identical
/// content as a refresh. Revocation safety depends on the distribution agent
/// proving that it is still alive, not merely on whether membership changed.
#[derive(Debug)]
pub struct Source {
    path: PathBuf,
    fingerprint: Fingerprint,
    last_valid: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    contents: Vec<u8>,
    modified: Option<SystemTime>,
}

/// A roster must be renewed within this interval or the relay fails closed.
pub const MAX_AGE: Duration = Duration::from_secs(90);

impl Source {
    /// Load the first roster and start its freshness lease.
    ///
    /// # Errors
    ///
    /// Returns an error when the roster cannot be read, is not UTF-8, or does
    /// not satisfy the roster format and validation rules.
    pub fn open(path: &Path) -> Result<(Self, FileRoster), Error> {
        let (roster, fingerprint) = load_with_fingerprint(path)?;
        Ok((
            Self {
                path: path.to_owned(),
                fingerprint,
                last_valid: Instant::now(),
            },
            roster,
        ))
    }

    /// Parse a replacement only when the file changed.
    ///
    /// A syntax or I/O failure leaves the last valid roster and its lease
    /// untouched. The caller therefore continues safely for at most
    /// [`MAX_AGE`], then replaces admission with an empty roster.
    ///
    /// # Errors
    ///
    /// Returns an error when the current roster file cannot be read, is not
    /// UTF-8, or does not satisfy the roster format and validation rules.
    pub fn reload(&mut self) -> Result<Option<FileRoster>, Error> {
        let (roster, fingerprint) = load_with_fingerprint(&self.path)?;
        if fingerprint == self.fingerprint {
            return Ok(None);
        }
        self.fingerprint = fingerprint;
        self.last_valid = Instant::now();
        Ok(Some(roster))
    }

    /// Whether the last successfully parsed roster is too old to trust.
    #[must_use]
    pub fn expired(&self) -> bool {
        self.last_valid.elapsed() >= MAX_AGE
    }
}

impl std::fmt::Debug for FileRoster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Counts, not contents: a roster is a membership list and dumping it
        // into a log is the disclosure §5.3 exists to control.
        f.debug_struct("FileRoster")
            .field("clients", &self.clients.len())
            .field("mesh_peers", &self.mesh.len())
            .finish_non_exhaustive()
    }
}

impl FileRoster {
    /// An empty roster, which admits nobody.
    ///
    /// Stated as a test rather than a convenience: an absent configuration
    /// must never read as permissive, and this is the shape that says so.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            clients: HashMap::new(),
            mesh: HashMap::new(),
            decoy: fresh_decoy(),
        }
    }

    /// Parse a roster from TOML.
    ///
    /// # Errors
    /// [`Error::Syntax`] for malformed TOML, [`Error::BadKey`] for a key that
    /// is not a 1952-byte ML-DSA-65 public key, [`Error::Duplicate`] for two
    /// entries deriving the same identifier.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let file: File = toml::from_str(text).map_err(|e| Error::Syntax(format!("roster: {e}")))?;

        let mut clients = HashMap::new();
        for (n, row) in file.client.iter().enumerate() {
            let pk = decode_key(&row.identity_pk, "client", n)?;
            let id = node_id(&pk);
            if clients
                .insert(
                    id,
                    RosterEntry {
                        identity_pk: pk,
                        tailnet: TailnetId(row.tailnet.clone()),
                    },
                )
                .is_some()
            {
                return Err(Error::Duplicate(format!(
                    "roster: client #{n} repeats an identity already listed"
                )));
            }
        }

        let mut mesh = HashMap::new();
        for (n, row) in file.mesh.iter().enumerate() {
            let pk = decode_key(&row.identity_pk, "mesh", n)?;
            let id = relay_id(&pk);
            if mesh.insert(id, RelayEntry { identity_pk: pk }).is_some() {
                return Err(Error::Duplicate(format!(
                    "roster: mesh peer #{n} repeats an identity already listed"
                )));
            }
        }

        Ok(Self {
            clients,
            mesh,
            decoy: fresh_decoy(),
        })
    }

    /// Load a roster from disk.
    ///
    /// # Errors
    /// [`Error::Io`] if the file cannot be read, plus everything
    /// [`Self::parse`] returns.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(Error::Io)?;
        Self::parse(&text)
    }

    /// Admitted nodes.
    #[must_use]
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Configured mesh peers.
    #[must_use]
    pub fn mesh_count(&self) -> usize {
        self.mesh.len()
    }
}

fn load_with_fingerprint(path: &Path) -> Result<(FileRoster, Fingerprint), Error> {
    let contents = std::fs::read(path).map_err(Error::Io)?;
    let text = std::str::from_utf8(&contents)
        .map_err(|e| Error::Syntax(format!("roster: file is not UTF-8: {e}")))?;
    let roster = FileRoster::parse(text)?;
    let modified = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
    Ok((roster, Fingerprint { contents, modified }))
}

impl Roster for FileRoster {
    fn client(&self, id: &[u8; ID_LEN]) -> Option<RosterEntry> {
        self.clients.get(id).cloned()
    }

    fn mesh_peer(&self, id: &[u8; ID_LEN]) -> Option<RelayEntry> {
        self.mesh.get(id).cloned()
    }

    fn decoy_key(&self) -> &[u8] {
        &self.decoy
    }
}

/// A syntactically valid ML-DSA-65 public key whose private half is discarded
/// the moment it is generated.
fn fresh_decoy() -> Vec<u8> {
    let mut seed = [0u8; SEED_LEN];
    // A failure here would leave a *constant* decoy, which still costs the
    // right amount of work — the decoy is a timing counterweight, not a
    // secret — so this does not need to be fallible to the caller.
    let _ = getrandom::fill(&mut seed);
    Identity::from_seed(&seed).public_key().to_vec()
}

fn decode_key(text: &str, kind: &str, n: usize) -> Result<Vec<u8>, Error> {
    let raw = Base64::decode_vec(text.trim())
        .map_err(|_| Error::BadKey(format!("roster: {kind} #{n}: identity_pk is not base64")))?;
    if raw.len() != IDENTITY_PK_LEN {
        return Err(Error::BadKey(format!(
            "roster: {kind} #{n}: identity_pk is {} bytes, expected {IDENTITY_PK_LEN}",
            raw.len()
        )));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn key(seed: u8) -> String {
        Base64::encode_string(Identity::from_seed(&[seed; SEED_LEN]).public_key())
    }

    fn pk(seed: u8) -> Vec<u8> {
        Identity::from_seed(&[seed; SEED_LEN]).public_key().to_vec()
    }

    #[test]
    fn an_empty_roster_admits_nobody() {
        let r = FileRoster::empty();
        assert!(r.client(&node_id(&pk(1))).is_none());
        assert!(r.mesh_peer(&relay_id(&pk(1))).is_none());
        // And it still has a decoy, so a miss costs the same as a hit.
        assert_eq!(r.decoy_key().len(), IDENTITY_PK_LEN);
    }

    #[test]
    fn an_absent_file_section_admits_nobody() {
        // The empty-means-permissive trap, in its most likely form: a roster
        // with a mesh section and no clients.
        let r = FileRoster::parse(&format!("[[mesh]]\nidentity_pk = \"{}\"\n", key(9)))
            .expect("parses");
        assert_eq!(r.client_count(), 0);
        assert_eq!(r.mesh_count(), 1);
        assert!(r.client(&node_id(&pk(1))).is_none());
    }

    #[test]
    fn a_listed_client_is_found_by_its_derived_id() {
        let r = FileRoster::parse(&format!(
            "[[client]]\nidentity_pk = \"{}\"\ntailnet = \"acme\"\n",
            key(1)
        ))
        .expect("parses");

        let entry = r.client(&node_id(&pk(1))).expect("admitted");
        assert_eq!(entry.identity_pk, pk(1));
        assert_eq!(entry.tailnet, TailnetId("acme".to_owned()));
    }

    #[test]
    fn a_client_is_not_a_mesh_peer() {
        // §8's role separation. The ids are hashed under different labels, so
        // a client's id is not findable in the mesh directory even when the
        // same key appears in both sections.
        let r = FileRoster::parse(&format!(
            "[[client]]\nidentity_pk = \"{k}\"\ntailnet = \"acme\"\n\n[[mesh]]\nidentity_pk = \"{k}\"\n",
            k = key(1)
        ))
        .expect("parses");

        assert!(r.client(&node_id(&pk(1))).is_some());
        assert!(r.mesh_peer(&node_id(&pk(1))).is_none());
        assert!(r.mesh_peer(&relay_id(&pk(1))).is_some());
        assert!(r.client(&relay_id(&pk(1))).is_none());
    }

    #[test]
    fn tailnets_are_carried_through() {
        let r = FileRoster::parse(&format!(
            "[[client]]\nidentity_pk = \"{}\"\ntailnet = \"a\"\n\n[[client]]\nidentity_pk = \"{}\"\ntailnet = \"b\"\n",
            key(1),
            key(2)
        ))
        .expect("parses");
        assert_eq!(
            r.client(&node_id(&pk(1))).expect("a").tailnet,
            TailnetId("a".to_owned())
        );
        assert_eq!(
            r.client(&node_id(&pk(2))).expect("b").tailnet,
            TailnetId("b".to_owned())
        );
    }

    #[test]
    fn a_repeated_identity_is_an_error() {
        // Silently keeping the last would make a tailnet reassignment depend
        // on file order.
        let err = FileRoster::parse(&format!(
            "[[client]]\nidentity_pk = \"{k}\"\ntailnet = \"a\"\n\n[[client]]\nidentity_pk = \"{k}\"\ntailnet = \"b\"\n",
            k = key(1)
        ))
        .expect_err("duplicate");
        assert!(matches!(err, Error::Duplicate(_)), "{err:?}");
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused_at_load() {
        // Better here than as a verification failure per connection, which
        // looks identical to a wrong key and is untraceable to the file.
        let err = FileRoster::parse(&format!(
            "[[client]]\nidentity_pk = \"{}\"\ntailnet = \"a\"\n",
            Base64::encode_string(&[0u8; 100])
        ))
        .expect_err("short key");
        assert!(matches!(err, Error::BadKey(_)), "{err:?}");
    }

    #[test]
    fn a_key_that_is_not_base64_is_refused_at_load() {
        let err = FileRoster::parse(
            "[[client]]\nidentity_pk = \"not base64 at all!!\"\ntailnet = \"a\"\n",
        )
        .expect_err("bad base64");
        assert!(matches!(err, Error::BadKey(_)), "{err:?}");
    }

    #[test]
    fn malformed_toml_is_an_error_not_an_empty_roster() {
        // The dangerous failure would be the opposite of the usual one: a
        // roster that parses to nothing admits nobody and looks like an
        // outage, which is survivable. A roster that *silently* parses to
        // nothing is the same outage with no explanation.
        let err = FileRoster::parse("[[client]\nnope").expect_err("syntax");
        assert!(matches!(err, Error::Syntax(_)), "{err:?}");
    }

    #[test]
    fn two_rosters_have_different_decoys() {
        // Generated per load and never written. A constant would still cost
        // the right work, but a per-process value costs nothing extra and
        // leaves nothing to recognise across relays.
        let a = FileRoster::empty();
        let b = FileRoster::empty();
        assert_ne!(a.decoy_key(), b.decoy_key());
    }

    #[test]
    fn the_decoy_is_a_well_formed_key_that_verifies_nothing() {
        // It has to be well-formed or the verification it exists to force
        // would fail early and give the timing back.
        use karst_relay_proto::Verifier as _;
        let r = FileRoster::empty();
        assert_eq!(r.decoy_key().len(), IDENTITY_PK_LEN);

        let real = Identity::from_seed(&[5; SEED_LEN]);
        let msg = [1u8; 64];
        let sig = karst_relay_proto::Signer::sign(&real, &msg).expect("signing");
        assert!(!crate::sign::PonorVerifier.verify(r.decoy_key(), &msg, &sig));
    }

    #[test]
    fn a_roster_does_not_print_its_contents() {
        let r = FileRoster::parse(&format!(
            "[[client]]\nidentity_pk = \"{}\"\ntailnet = \"secret-tailnet\"\n",
            key(1)
        ))
        .expect("parses");
        let rendered = format!("{r:?}");
        assert!(!rendered.contains("secret-tailnet"), "{rendered}");
        assert!(!rendered.contains(&key(1)[..32]), "{rendered}");
        assert!(rendered.contains("clients: 1"), "{rendered}");
    }

    #[test]
    fn a_changed_roster_reloads_without_restarting_the_relay() {
        let dir = std::env::temp_dir().join(format!("karst-roster-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roster.toml");
        std::fs::write(
            &path,
            format!(
                "[[client]]\nidentity_pk = \"{}\"\ntailnet = \"a\"\n",
                key(1)
            ),
        )
        .expect("write first roster");
        let (mut source, first) = Source::open(&path).expect("open");
        assert_eq!(first.client_count(), 1);

        std::fs::write(
            &path,
            format!(
                "[[client]]\nidentity_pk = \"{}\"\ntailnet = \"a\"\n\n[[client]]\nidentity_pk = \"{}\"\ntailnet = \"a\"\n",
                key(1),
                key(2)
            ),
        )
        .expect("replace roster");
        let second = source.reload().expect("reload").expect("changed");
        assert_eq!(second.client_count(), 2);
        assert!(source.reload().expect("unchanged").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
