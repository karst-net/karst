// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The file that crosses the air gap — `spec/bedrock-v1.md` §8 workflow.
//!
//! The console exports a **request** bundle; an admin carries it on removable
//! media to a machine with no network interface; `karst-bedrock sign` produces
//! a **response** bundle; the console imports it. File-based on purpose: no QR
//! codes, no Bluetooth, no clever transport that has to be audited too.
//!
//! # The signing input is recomputed, never trusted
//!
//! A request carries the log so far and the entries pending signature. It does
//! **not** get to assert what the signing input is — [`Request::verify`]
//! rebuilds it from the log and the pending bodies.
//!
//! That is the whole security of the offline path. A bundle arrives from a
//! machine the offline signer has no reason to trust (it came from the
//! coordination server, through whatever media was to hand), so a bundle that
//! could name its own signing input would let a compromised server obtain a
//! root signature over anything at all — including an authority list of keys it
//! controls, which is precisely the attack Bedrock exists to stop.
//!
//! JSON rather than the compact log encoding, because a human is meant to be
//! able to read one with `cat` when something has gone wrong at three in the
//! morning.

use crate::log::{decode_log, encode_log, Entry, Op, Signature};
use crate::verify::{verify_log, State};
use crate::Error;

/// The bundle format version, checked on load so a future format is refused
/// rather than half-understood.
pub const BUNDLE_VERSION: &str = "bedrock-bundle-v1";

/// One entry awaiting signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub seq: u64,
    pub time: i64,
    pub op: Op,
    pub body: Vec<u8>,
}

/// A signature produced offline, bound to the entry it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineSignature {
    pub seq: u64,
    pub signer_index: u32,
    pub sig: Vec<u8>,
}

/// What the console exports for an admin to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The verified log this request extends. Empty for a genesis request,
    /// which is the one case with no prior chain.
    pub log: Vec<Entry>,
    pub pending: Vec<Pending>,
}

/// What comes back from the offline machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub signatures: Vec<OfflineSignature>,
}

/// A request that has been checked, carrying the signing inputs the offline
/// signer must actually sign.
#[derive(Debug, Clone)]
pub struct VerifiedRequest {
    /// State established by the existing log, `None` for a genesis request.
    pub state: Option<State>,
    /// Each pending entry with the hash to sign, in order.
    pub to_sign: Vec<(Pending, Vec<u8>)>,
}

impl Request {
    /// Check a request and derive the signing inputs.
    ///
    /// Verifies the enclosed log in full, then rebuilds each pending entry's
    /// chain hash from that log rather than accepting any value the bundle
    /// supplied. See the module docs for why that distinction is the whole
    /// security of this path.
    ///
    /// # Errors
    ///
    /// [`Error::Broken`] if the enclosed log does not verify, if the pending
    /// entries do not follow it contiguously, or if a genesis request carries a
    /// prior log (or a non-genesis one does not).
    pub fn verify(&self) -> Result<VerifiedRequest, Error> {
        let (state, mut prev, mut next_seq) = if self.log.is_empty() {
            (None, Vec::new(), 1u64)
        } else {
            let st = verify_log(&self.log)?;
            let head = st.head.clone();
            let next = st.head_seq.saturating_add(1);
            (Some(st), head, next)
        };

        if self.pending.is_empty() {
            return Err(Error::Broken {
                seq: next_seq,
                why: "request has nothing to sign".into(),
            });
        }

        let mut to_sign = Vec::with_capacity(self.pending.len());
        for p in &self.pending {
            if p.seq != next_seq {
                return Err(Error::Broken {
                    seq: p.seq,
                    why: format!("pending entry does not follow the log; expected seq {next_seq}"),
                });
            }
            // A genesis may only appear at position 1, and position 1 must be a
            // genesis — the same rule the verifier applies, enforced here so an
            // admin is never asked to sign something that could not verify.
            if (p.seq == 1) != (p.op == Op::Genesis) {
                return Err(Error::Broken {
                    seq: p.seq,
                    why: "genesis must be the first entry and only the first".into(),
                });
            }

            let entry = Entry {
                seq: p.seq,
                time: p.time,
                op: p.op,
                body: p.body.clone(),
                sigs: Vec::new(),
            };
            let input = entry.signing_input(&prev);
            prev.clone_from(&input);
            next_seq = next_seq.saturating_add(1);
            to_sign.push((p.clone(), input));
        }

        Ok(VerifiedRequest { state, to_sign })
    }
}

impl VerifiedRequest {
    /// Fold a response's signatures back onto the request, producing the
    /// extended log.
    ///
    /// # Errors
    ///
    /// [`Error::Broken`] if a signature names an entry that is not pending, if
    /// any pending entry ends up with no signatures, or if the resulting log
    /// does not verify.
    pub fn apply(&self, log: &[Entry], response: &Response) -> Result<Vec<Entry>, Error> {
        let mut out = log.to_vec();

        for (pending, _) in &self.to_sign {
            let sigs: Vec<Signature> = response
                .signatures
                .iter()
                .filter(|s| s.seq == pending.seq)
                .map(|s| Signature {
                    signer_index: s.signer_index,
                    sig: s.sig.clone(),
                })
                .collect();
            if sigs.is_empty() {
                return Err(Error::Broken {
                    seq: pending.seq,
                    why: "response carries no signature for this entry".into(),
                });
            }
            out.push(Entry {
                seq: pending.seq,
                time: pending.time,
                op: pending.op,
                body: pending.body.clone(),
                sigs,
            });
        }

        // A signature naming an entry nobody asked about means the response and
        // the request disagree about what was signed.
        for s in &response.signatures {
            if !self.to_sign.iter().any(|(p, _)| p.seq == s.seq) {
                return Err(Error::Broken {
                    seq: s.seq,
                    why: "response signs an entry that was not requested".into(),
                });
            }
        }

        // The final word: the extended log must verify as a whole. Everything
        // above is a better error message for a failure this would catch anyway.
        verify_log(&out)?;
        Ok(out)
    }
}

// ── JSON serialisation ──────────────────────────────────────────────────────
//
// Hand-rolled rather than derived, so the crate does not take a serde
// dependency for a format only the offline tool reads. The shapes are small and
// the encoder is the only writer.

/// Render a request as JSON.
#[must_use]
pub fn request_to_json(req: &Request) -> String {
    let mut s = String::new();
    s.push_str("{\n  \"bundle\": \"");
    s.push_str(BUNDLE_VERSION);
    s.push_str("\",\n  \"kind\": \"request\",\n  \"log\": \"");
    s.push_str(&to_hex(&encode_log(&req.log)));
    s.push_str("\",\n  \"pending\": [\n");
    for (i, p) in req.pending.iter().enumerate() {
        s.push_str("    { \"seq\": ");
        s.push_str(&p.seq.to_string());
        s.push_str(", \"time\": ");
        s.push_str(&p.time.to_string());
        s.push_str(", \"op\": \"");
        s.push_str(p.op.as_str());
        s.push_str("\", \"body\": \"");
        s.push_str(&to_hex(&p.body));
        s.push_str("\" }");
        if i + 1 < req.pending.len() {
            s.push(',');
        }
        s.push('\n');
    }
    s.push_str("  ]\n}\n");
    s
}

/// Render a response as JSON.
#[must_use]
pub fn response_to_json(resp: &Response) -> String {
    let mut s = String::new();
    s.push_str("{\n  \"bundle\": \"");
    s.push_str(BUNDLE_VERSION);
    s.push_str("\",\n  \"kind\": \"response\",\n  \"signatures\": [\n");
    for (i, sig) in resp.signatures.iter().enumerate() {
        s.push_str("    { \"seq\": ");
        s.push_str(&sig.seq.to_string());
        s.push_str(", \"signer_index\": ");
        s.push_str(&sig.signer_index.to_string());
        s.push_str(", \"sig\": \"");
        s.push_str(&to_hex(&sig.sig));
        s.push_str("\" }");
        if i + 1 < resp.signatures.len() {
            s.push(',');
        }
        s.push('\n');
    }
    s.push_str("  ]\n}\n");
    s
}

/// Parse a request bundle.
///
/// # Errors
///
/// [`Error::Malformed`] on any structural problem, including a bundle version
/// this build does not know.
pub fn request_from_json(text: &str) -> Result<Request, Error> {
    check_bundle(text, "request")?;
    let log = decode_log(&from_hex(&field(text, "\"log\"").ok_or(Error::Malformed)?)?)?;

    let mut pending = Vec::new();
    for chunk in text.split("{ \"seq\":").skip(1) {
        let seq: u64 = chunk
            .split(',')
            .next()
            .ok_or(Error::Malformed)?
            .trim()
            .parse()
            .map_err(|_| Error::Malformed)?;
        let time: i64 = after(chunk, "\"time\":")
            .ok_or(Error::Malformed)?
            .split(',')
            .next()
            .ok_or(Error::Malformed)?
            .trim()
            .parse()
            .map_err(|_| Error::Malformed)?;
        let op_raw = quoted(chunk, "\"op\":").ok_or(Error::Malformed)?;
        let op = Op::parse(&op_raw).ok_or(Error::UnknownOp(op_raw))?;
        let body = from_hex(&quoted(chunk, "\"body\":").ok_or(Error::Malformed)?)?;
        pending.push(Pending {
            seq,
            time,
            op,
            body,
        });
    }
    Ok(Request { log, pending })
}

/// Parse a response bundle.
///
/// # Errors
///
/// [`Error::Malformed`] on any structural problem.
pub fn response_from_json(text: &str) -> Result<Response, Error> {
    check_bundle(text, "response")?;
    let mut signatures = Vec::new();
    for chunk in text.split("{ \"seq\":").skip(1) {
        let seq: u64 = chunk
            .split(',')
            .next()
            .ok_or(Error::Malformed)?
            .trim()
            .parse()
            .map_err(|_| Error::Malformed)?;
        let signer_index: u32 = after(chunk, "\"signer_index\":")
            .ok_or(Error::Malformed)?
            .split(',')
            .next()
            .ok_or(Error::Malformed)?
            .trim()
            .parse()
            .map_err(|_| Error::Malformed)?;
        let sig = from_hex(&quoted(chunk, "\"sig\":").ok_or(Error::Malformed)?)?;
        signatures.push(OfflineSignature {
            seq,
            signer_index,
            sig,
        });
    }
    Ok(Response { signatures })
}

fn check_bundle(text: &str, kind: &str) -> Result<(), Error> {
    if field(text, "\"bundle\"").as_deref() != Some(BUNDLE_VERSION) {
        return Err(Error::Malformed);
    }
    if field(text, "\"kind\"").as_deref() != Some(kind) {
        return Err(Error::Malformed);
    }
    Ok(())
}

fn after<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.split_once(key).map(|(_, rest)| rest)
}

fn field(text: &str, key: &str) -> Option<String> {
    quoted(text, &format!("{key}:"))
}

fn quoted(text: &str, key: &str) -> Option<String> {
    let rest = after(text, key)?;
    let start = rest.find('"')?.checked_add(1)?;
    let body = rest.get(start..)?;
    let end = body.find('"')?;
    body.get(..end).map(ToOwned::to_owned)
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for byte in b {
        s.push(nibble(byte >> 4));
        s.push(nibble(byte & 0x0f));
    }
    s
}

fn nibble(v: u8) -> char {
    match v {
        0..=9 => char::from(b'0'.saturating_add(v)),
        _ => char::from(b'a'.saturating_add(v.saturating_sub(10))),
    }
}

fn from_hex(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0 {
        return Err(Error::Malformed);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = unnibble(*pair.first().ok_or(Error::Malformed)?)?;
        let lo = unnibble(*pair.get(1).ok_or(Error::Malformed)?)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn unnibble(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(c.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Ok(c.saturating_sub(b'A').saturating_add(10)),
        _ => Err(Error::Malformed),
    }
}
