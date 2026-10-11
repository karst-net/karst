// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Immutable, bounded batch files. Only a durable control-plane acknowledgment
//! permits removal. Epoch allocation and batch signing live above this layer.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SPOOL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_BATCHES: usize = 1024;

/// Names contain only encoded epoch bytes and a sequence, never external paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatchId {
    pub epoch: [u8; 16],
    pub sequence: u64,
}

impl BatchId {
    fn parse(name: &str) -> io::Result<Self> {
        if name.len() != 59 || !name.is_ascii() {
            return Err(invalid("invalid batch filename"));
        }
        let (epoch_text, rest) = name.split_at(32);
        let sequence_text = rest
            .strip_prefix('-')
            .and_then(|s| s.strip_suffix(".batch"))
            .ok_or_else(|| invalid("invalid batch filename"))?;
        let mut epoch = [0; 16];
        for (byte, pair) in epoch.iter_mut().zip(epoch_text.as_bytes().chunks_exact(2)) {
            let text = std::str::from_utf8(pair).map_err(|_| invalid("invalid epoch"))?;
            *byte = u8::from_str_radix(text, 16).map_err(|_| invalid("invalid epoch"))?;
        }
        let sequence = sequence_text
            .parse()
            .map_err(|_| invalid("invalid sequence"))?;
        let id = Self { epoch, sequence };
        if id.name() != name {
            return Err(invalid("noncanonical batch filename"));
        }
        Ok(id)
    }

    fn name(self) -> String {
        let epoch = self
            .epoch
            .iter()
            .fold(String::with_capacity(32), |mut out, byte| {
                use std::fmt::Write as _;
                let _ = write!(out, "{byte:02x}");
                out
            });
        format!("{epoch}-{:020}.batch", self.sequence)
    }
}

#[derive(Debug)]
pub struct Spool {
    path: PathBuf,
    _lock: File,
    epoch: [u8; 16],
    next_sequence: u64,
    was_unclean: bool,
}

impl Spool {
    /// Current producer epoch, unique to this process lifetime.
    #[must_use]
    pub const fn epoch(&self) -> [u8; 16] {
        self.epoch
    }

    /// True when the previous process did not record a clean stop. Callers
    /// must mark affected coverage incomplete before reporting subsequent data.
    #[must_use]
    pub const fn recovered_unclean(&self) -> bool {
        self.was_unclean
    }

    /// Reserve and durably advance the next identity before creating its batch.
    /// A crash can leave a sequence gap, which is explicit and safe; it can
    /// never reuse an identity that may already have reached the server.
    /// # Errors
    /// Returns state persistence errors or sequence exhaustion.
    pub fn reserve(&mut self) -> io::Result<BatchId> {
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("sequence exhausted"))?;
        self.persist_state(false)?;
        Ok(BatchId {
            epoch: self.epoch,
            sequence,
        })
    }

    /// Record clean producer shutdown after the final window is sealed. Any
    /// failure leaves the on-disk state unclean for the next process.
    /// # Errors
    /// Returns state persistence errors.
    pub fn clean_shutdown(&mut self) -> io::Result<()> {
        self.persist_state(true)
    }

    /// Discover all retained batch identities after restart, in stable order.
    /// Corrupt names and nonregular entries are errors, not silently lost usage.
    /// Contents are integrity-checked separately by [`Self::read`].
    /// # Errors
    /// Returns invalid filenames, excessive batch count, or filesystem errors.
    pub fn pending(&self) -> io::Result<Vec<BatchId>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "spool.lock" || name == "pending" || name == "producer.state" {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(invalid("nonregular spool entry"));
            }
            let name = name
                .to_str()
                .ok_or_else(|| invalid("invalid spool filename"))?;
            ids.push(BatchId::parse(name)?);
            if ids.len() > MAX_BATCHES {
                return Err(invalid("too many retained batches"));
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    /// Open an operator-owned private directory with an exclusive process lock.
    /// # Errors
    /// Returns filesystem or lock errors; never steals an active writer's lock.
    pub fn open(path: &Path) -> io::Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        let lock = options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.join("spool.lock"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        let prior_state = read_state(path)?;
        let was_unclean = prior_state.as_ref().is_some_and(|state| !state.2);
        let epoch = {
            let mut bytes = [0; 16];
            getrandom::fill(&mut bytes)
                .map_err(|_| io::Error::other("producer epoch entropy unavailable"))?;
            bytes
        };
        let spool = Self {
            path: path.to_owned(),
            _lock: lock,
            epoch,
            next_sequence: 0,
            was_unclean,
        };
        // Mark this process dirty before touching recovery files. A crash at
        // any later point must be visible to the next process.
        spool.persist_state(false)?;
        // A pending file was never published. Epoch recovery must still mark
        // an unclean producer incomplete; removing it is not evidence of zero.
        match fs::remove_file(path.join("pending")) {
            Ok(()) => spool.sync_directory()?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        match fs::remove_file(path.join("state.pending")) {
            Ok(()) => spool.sync_directory()?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(spool)
    }

    /// Seal bytes before upload. Identical retries are safe; conflicting content
    /// under one identity is rejected. A failed sync requires retrying this call.
    /// # Errors
    /// Returns bounds, conflict, integrity, or filesystem errors.
    pub fn put(&mut self, id: BatchId, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() || payload.len() > MAX_BATCH_BYTES {
            return Err(invalid("batch size"));
        }
        match self.read(id) {
            Ok(existing) if existing == payload => return self.sync_directory(),
            Ok(_) => return Err(invalid("conflicting batch identity")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut count = 0usize;
        let mut bytes = 0u64;
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if entry.path().extension().is_some_and(|ext| ext == "batch") {
                count += 1;
                bytes = bytes
                    .checked_add(entry.metadata()?.len())
                    .ok_or_else(|| invalid("spool size overflow"))?;
            }
        }
        if count >= MAX_BATCHES || bytes > MAX_SPOOL_BYTES.saturating_sub(payload.len() as u64 + 32)
        {
            return Err(io::Error::other("usage spool is full"));
        }
        let pending = self.path.join("pending");
        // A previous failed write is replaceable; the published files are not.
        let mut file = options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&pending)?;
        file.write_all(&Sha256::digest(payload))?;
        file.write_all(payload)?;
        file.sync_all()?;
        fs::rename(&pending, self.path.join(id.name()))?;
        self.sync_directory()
    }

    /// Read bounded, integrity-checked bytes for exact replay.
    /// # Errors
    /// Missing, truncated, corrupt, oversized, or unreadable files are errors.
    pub fn read(&self, id: BatchId) -> io::Result<Vec<u8>> {
        let file = options().read(true).open(self.path.join(id.name()))?;
        let mut bytes = Vec::new();
        file.take((MAX_BATCH_BYTES + 33) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() <= 32 || bytes.len() > MAX_BATCH_BYTES + 32 {
            return Err(invalid("invalid batch size"));
        }
        let (digest, payload) = bytes.split_at(32);
        if digest != Sha256::digest(payload).as_slice() {
            return Err(invalid("batch integrity failure"));
        }
        Ok(payload.to_vec())
    }

    /// Remove only after the caller has verified a durable acknowledgment for
    /// this exact identity and digest. A mismatched acknowledgment cannot erase
    /// the stored batch.
    /// # Errors
    /// Returns integrity, digest mismatch, or filesystem errors.
    pub fn acknowledge(&mut self, id: BatchId, digest: &[u8; 32]) -> io::Result<()> {
        let payload = match self.read(id) {
            Ok(payload) => payload,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return self.sync_directory(),
            Err(e) => return Err(e),
        };
        if Sha256::digest(&payload).as_slice() != digest {
            return Err(invalid("acknowledgment digest mismatch"));
        }
        fs::remove_file(self.path.join(id.name()))?;
        self.sync_directory()
    }

    fn sync_directory(&self) -> io::Result<()> {
        File::open(&self.path)?.sync_all()
    }

    fn persist_state(&self, clean: bool) -> io::Result<()> {
        let mut state = Vec::with_capacity(49);
        state.extend_from_slice(&self.epoch);
        state.extend_from_slice(&self.next_sequence.to_be_bytes());
        state.push(u8::from(clean));
        state.extend_from_slice(&Sha256::digest(&state));
        let path = self.path.join("state.pending");
        let mut file = options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(&state)?;
        file.sync_all()?;
        fs::rename(path, self.path.join("producer.state"))?;
        self.sync_directory()
    }
}

fn read_state(path: &Path) -> io::Result<Option<([u8; 16], u64, bool)>> {
    let state_path = path.join("producer.state");
    let mut bytes = Vec::new();
    match options().read(true).open(&state_path) {
        Ok(file) => file.take(58).read_to_end(&mut bytes)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if bytes.len() != 57 {
        return Err(invalid("producer state integrity failure"));
    }
    let body = bytes
        .get(..25)
        .ok_or_else(|| invalid("producer state body"))?;
    let digest = bytes
        .get(25..)
        .ok_or_else(|| invalid("producer state digest"))?;
    let clean = *body.get(24).ok_or_else(|| invalid("producer clean flag"))?;
    if Sha256::digest(body).as_slice() != digest || clean > 1 {
        return Err(invalid("producer state integrity failure"));
    }
    let epoch = body
        .get(..16)
        .ok_or_else(|| invalid("producer epoch"))?
        .try_into()
        .map_err(|_| invalid("producer epoch"))?;
    let sequence = u64::from_be_bytes(
        body.get(16..24)
            .ok_or_else(|| invalid("producer sequence"))?
            .try_into()
            .map_err(|_| invalid("producer sequence"))?,
    );
    Ok(Some((epoch, sequence, clean == 1)))
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.mode(0o600).custom_flags(i32::from_ne_bytes(
        rustix::fs::OFlags::NOFOLLOW.bits().to_ne_bytes(),
    ));
    options
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut epoch = [0; 16];
            getrandom::fill(&mut epoch).expect("random path");
            Self(std::env::temp_dir().join(format!(
                "karst-usage-{}",
                BatchId { epoch, sequence: 0 }.name()
            )))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    const ID: BatchId = BatchId {
        epoch: [7; 16],
        sequence: 1,
    };

    #[test]
    fn restart_replays_exact_bytes_until_matching_acknowledgment() {
        let temp = Temp::new();
        let mut spool = Spool::open(&temp.0).expect("open");
        assert!(
            Spool::open(&temp.0).is_err(),
            "second writer must not acquire lock"
        );
        spool.put(ID, b"sealed batch").expect("persist");
        spool.put(ID, b"sealed batch").expect("idempotent retry");
        assert!(spool.put(ID, b"different content").is_err());
        drop(spool);
        let mut spool = Spool::open(&temp.0).expect("reopen");
        assert_eq!(spool.read(ID).expect("replay"), b"sealed batch");
        assert!(spool.acknowledge(ID, &[0; 32]).is_err());
        assert_eq!(
            spool.read(ID).expect("bad ack retains batch"),
            b"sealed batch"
        );
        let digest = Sha256::digest(b"sealed batch").into();
        spool.acknowledge(ID, &digest).expect("durable ack");
        spool.acknowledge(ID, &digest).expect("repeated ack");
        assert_eq!(
            spool.read(ID).expect_err("removed").kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn corrupted_or_partial_batches_are_not_replayed_as_usage() {
        let temp = Temp::new();
        let mut spool = Spool::open(&temp.0).expect("open");
        spool.put(ID, b"sealed batch").expect("persist");
        fs::write(temp.0.join(ID.name()), b"partial").expect("simulate damaged batch");
        assert!(spool.read(ID).is_err());
        assert!(
            spool.put(ID, b"sealed batch").is_err(),
            "never overwrite corrupted evidence"
        );
        assert!(spool
            .acknowledge(ID, &Sha256::digest(b"sealed batch").into())
            .is_err());
        fs::write(temp.0.join("pending"), b"unpublished").expect("simulate interrupted write");
        drop(spool);
        let spool = Spool::open(&temp.0).expect("reopen");
        assert!(!temp.0.join("pending").exists());
        assert!(
            spool.read(ID).is_err(),
            "published corruption remains visible"
        );
    }

    #[test]
    fn oversized_batches_are_rejected_before_disk_write() {
        let temp = Temp::new();
        let mut spool = Spool::open(&temp.0).expect("open");
        assert!(spool.put(ID, &[]).is_err());
        assert!(spool.put(ID, &vec![0; MAX_BATCH_BYTES + 1]).is_err());
        assert!(!temp.0.join(ID.name()).exists());
    }

    #[test]
    fn restart_discovers_all_epochs_and_rejects_damaged_names() {
        let temp = Temp::new();
        let mut spool = Spool::open(&temp.0).expect("open");
        let later = BatchId {
            epoch: [8; 16],
            sequence: 2,
        };
        spool.put(later, b"later epoch").expect("put");
        spool.put(ID, b"older backlog").expect("put");
        drop(spool);
        let spool = Spool::open(&temp.0).expect("restart");
        assert_eq!(spool.pending().expect("discover"), vec![ID, later]);
        fs::write(temp.0.join("broken.batch"), b"evidence").expect("damaged name");
        assert!(spool.pending().is_err(), "never hide unrecognized evidence");
    }

    #[test]
    fn batch_names_round_trip_without_path_or_case_aliases() {
        for id in [
            ID,
            BatchId {
                epoch: [255; 16],
                sequence: u64::MAX,
            },
        ] {
            assert_eq!(BatchId::parse(&id.name()).expect("round trip"), id);
        }
        assert!(BatchId::parse("../outside.batch").is_err());
        assert!(BatchId::parse(
            &BatchId {
                epoch: [255; 16],
                sequence: 1
            }
            .name()
            .to_uppercase()
        )
        .is_err());
    }

    #[test]
    fn full_spool_preserves_replay_and_identical_retry() {
        let temp = Temp::new();
        let mut spool = Spool::open(&temp.0).expect("open");
        spool.put(ID, b"retained").expect("persist");
        let other = BatchId {
            epoch: [9; 16],
            sequence: 1,
        };
        // Sparse allocation exercises the byte bound without filling the disk.
        File::create(temp.0.join(other.name()))
            .expect("sparse file")
            .set_len(MAX_SPOOL_BYTES)
            .expect("set size");
        assert!(spool.put(BatchId { sequence: 2, ..ID }, b"new").is_err());
        spool
            .put(ID, b"retained")
            .expect("retry remains valid at capacity");
        assert_eq!(spool.read(ID).expect("retained evidence"), b"retained");
    }

    #[test]
    fn write_failure_does_not_publish_or_damage_previous_batch() {
        let temp = Temp::new();
        let mut spool = Spool::open(&temp.0).expect("open");
        spool.put(ID, b"retained").expect("persist");
        fs::create_dir(temp.0.join("pending")).expect("inject write failure");
        let next = BatchId { sequence: 2, ..ID };
        assert!(spool.put(next, b"uncommitted").is_err());
        assert_eq!(
            spool.read(next).expect_err("not published").kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(spool.read(ID).expect("retained evidence"), b"retained");
        fs::remove_dir(temp.0.join("pending")).expect("repair storage");
        spool.put(next, b"uncommitted").expect("retry after repair");
        assert_eq!(spool.pending().expect("backlog"), vec![ID, next]);
    }

    #[test]
    fn batch_symlinks_are_not_followed() {
        use std::os::unix::fs::symlink;
        let temp = Temp::new();
        let spool = Spool::open(&temp.0).expect("open");
        symlink("spool.lock", temp.0.join(ID.name())).expect("symlink");
        assert!(spool.read(ID).is_err());
        assert!(spool.pending().is_err());
    }

    #[test]
    fn sequence_reservations_are_durable_and_unclean_restarts_are_reported() {
        let temp = Temp::new();
        let mut spool = Spool::open(&temp.0).expect("first start");
        assert!(!spool.recovered_unclean());
        let old_epoch = spool.epoch();
        let first = spool.reserve().expect("reserve");
        assert_eq!(first.epoch, old_epoch);
        assert_eq!(first.sequence, 0);
        // Drop without clean_shutdown to model a process crash.
        drop(spool);
        let mut recovered = Spool::open(&temp.0).expect("restart");
        assert!(recovered.recovered_unclean());
        assert_ne!(recovered.epoch(), old_epoch);
        let next = recovered.reserve().expect("new epoch");
        assert_eq!(next.sequence, 0);
        let current_epoch = recovered.epoch();
        recovered.clean_shutdown().expect("clean stop");
        drop(recovered);
        let clean = Spool::open(&temp.0).expect("clean restart");
        assert!(!clean.recovered_unclean());
        assert_ne!(clean.epoch(), current_epoch);
    }

    #[test]
    fn sequence_exhaustion_does_not_reuse_the_last_identity() {
        let temp = Temp::new();
        let mut spool = Spool::open(&temp.0).expect("open");
        spool.next_sequence = u64::MAX;
        assert!(spool.reserve().is_err());
    }
}
