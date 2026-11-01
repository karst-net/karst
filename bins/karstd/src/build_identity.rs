// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Identity of the executable actually running this agent, not its source
//! revision or a replacement executable installed at the same pathname.

use std::sync::{Once, OnceLock};

/// SHA-256 of the running process executable on Linux, cached once per process.
/// `/proc/self/exe` refers to the executing inode even after an upgrade renames
/// or unlinks it. Other platforms remain unknown until an equivalent running
/// image observation is available; `current_exe()` alone can name a replacement.
/// Hashing runs off the control/IPC thread. Until it completes (or on failure),
/// the identity is unknown; observation must never delay synchronization.
#[must_use]
pub fn artifact_id() -> Option<&'static str> {
    static IDENTITY: OnceLock<Option<String>> = OnceLock::new();
    static START: Once = Once::new();
    START.call_once(|| {
        // Thread creation failures also leave this advisory field unknown.
        let _ = std::thread::Builder::new()
            .name("artifact-identity".to_owned())
            .spawn(|| {
                let _ = IDENTITY.set(observe());
            });
    });
    IDENTITY.get().and_then(Option::as_deref)
}

#[cfg(target_os = "linux")]
fn observe() -> Option<String> {
    let file = std::fs::File::open("/proc/self/exe").ok()?;
    hash_executable(file).ok()
}

#[cfg(not(target_os = "linux"))]
fn observe() -> Option<String> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn hash_executable(mut reader: impl std::io::Read) -> std::io::Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = match reader.read(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        let chunk = buffer
            .get(..count)
            .ok_or_else(|| std::io::Error::other("invalid read length"))?;
        digest.update(chunk);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    #[test]
    fn hashes_artifact_bytes_and_refuses_partial_reads() {
        struct Unreadable;
        impl std::io::Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("unreadable executable"))
            }
        }
        let hash = super::hash_executable(&b"abc"[..]).expect("digest");
        assert_eq!(
            hash,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let failed = std::io::Read::chain(&b"partial"[..], Unreadable);
        assert!(super::hash_executable(failed).is_err());
    }
}
