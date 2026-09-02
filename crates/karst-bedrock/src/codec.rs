// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Length-prefixed field encoding — `spec/bedrock-v1.md` §3.2.
//!
//! `LP(x)` is a four-byte big-endian length followed by `x`, the same
//! construction as `karst-control-v1.md` §5.5 and the Go side's `writeLP`.
//!
//! Every read here is bounds-checked and returns `Option`/`Result` rather than
//! slicing. This parses attacker-supplied bytes on the node's fail-closed
//! verification path, and a panic there is a remote denial of service against
//! the daemon.

use crate::Error;

/// Appends `LP(field)`.
pub(crate) fn put_lp(dst: &mut Vec<u8>, field: &[u8]) {
    // A field longer than u32::MAX cannot be expressed; nothing Bedrock encodes
    // comes close, and saturating is the non-panicking way to say so.
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    dst.extend_from_slice(&len.to_be_bytes());
    dst.extend_from_slice(field);
}

pub(crate) fn put_u32(dst: &mut Vec<u8>, v: u32) {
    dst.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u64(dst: &mut Vec<u8>, v: u64) {
    dst.extend_from_slice(&v.to_be_bytes());
}

/// A bounds-checked reader over a length-prefixed field sequence.
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Malformed)?;
        let out = self.buf.get(self.pos..end).ok_or(Error::Malformed)?;
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::Malformed)?;
        Ok(u32::from_be_bytes(b))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| Error::Malformed)?;
        Ok(u64::from_be_bytes(b))
    }

    /// Reads one length-prefixed field.
    ///
    /// The length is attacker-controlled, so it is checked against what remains
    /// before anything is taken — never used to size an allocation first.
    pub(crate) fn lp(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// Reads a length-prefixed UTF-8 string.
    ///
    /// Invalid UTF-8 is a decode failure rather than a lossy conversion: a
    /// handle that two implementations render differently is a handle they
    /// could disagree about covering.
    pub(crate) fn lp_str(&mut self) -> Result<String, Error> {
        core::str::from_utf8(self.lp()?)
            .map(ToOwned::to_owned)
            .map_err(|_| Error::Malformed)
    }

    /// Reads `BE32(count)` then that many length-prefixed keys, each of which
    /// must be exactly `size` bytes.
    ///
    /// A wrong-sized key is a decode failure rather than a verification failure
    /// later: a key list whose entries are not keys has no interpretation worth
    /// carrying forward.
    pub(crate) fn keys(&mut self, size: usize, max: u32) -> Result<Vec<Vec<u8>>, Error> {
        let n = self.u32()?;
        if n > max {
            return Err(Error::Malformed);
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let k = self.lp()?;
            if k.len() != size {
                return Err(Error::Malformed);
            }
            out.push(k.to_vec());
        }
        Ok(out)
    }

    /// Succeeds only if the cursor consumed exactly the input.
    ///
    /// Trailing bytes are a decode failure: a body with slack in it is a body
    /// two implementations could read differently.
    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    /// A non-consuming peek: has this cursor read exactly the input so far?
    pub(crate) fn is_at_end(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Reads ADR-0016's optional trailing anchor-key block:
    /// `[ BE32(count) || count × LP(key) ]`.
    ///
    /// Absence — the cursor already at the end — means zero keys. A block
    /// that *is* present but whose count is zero is a decode failure: that is
    /// a second byte string for the meaning absence already carries, exactly
    /// the canonicalization hazard the codec elsewhere exists to remove — spec
    /// §3.4.
    pub(crate) fn optional_keys(&mut self, size: usize, max: u32) -> Result<Vec<Vec<u8>>, Error> {
        if self.is_at_end() {
            return Ok(Vec::new());
        }
        let n = self.u32()?;
        if n == 0 {
            return Err(Error::Malformed);
        }
        if n > max {
            return Err(Error::Malformed);
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let k = self.lp()?;
            if k.len() != size {
                return Err(Error::Malformed);
            }
            out.push(k.to_vec());
        }
        Ok(out)
    }
}
