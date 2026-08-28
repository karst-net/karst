// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `karst-bedrock` — the offline signer. `spec/bedrock-v1.md` §8, plan item 10.9.
//!
//! ```text
//! karst-bedrock init root|authority FILE   generate a key, print the public key
//! karst-bedrock pubkey FILE                print a key's public key
//! karst-bedrock inspect FILE               decode and print a bundle or log
//! karst-bedrock sign REQUEST KEY OUT       verify, summarise, confirm, sign
//! karst-bedrock verify FILE                verify a chain offline
//! ```
//!
//! # Why this is a separate binary
//!
//! Authority keys must be usable from a machine that never touches the
//! coordination server, or the offline story is theatre. This tool has no
//! network dependency in its manifest — that is the claim, and the manifest is
//! where it is checked.
//!
//! # `sign` prints what it is about to sign, in words
//!
//! An admin who signs a bundle without reading it has reduced Bedrock to a
//! slower way of trusting the server. So `sign` renders each entry as a
//! sentence a human can check against what they *meant* to authorise, and
//! requires a typed confirmation — not a keypress, which is too easy to give
//! reflexively.
//!
//! The signing input is recomputed from the enclosed log rather than read from
//! the bundle (`bundle.rs` explains why at length): a bundle that could name
//! its own signing input would let a compromised server obtain a root signature
//! over anything at all.

use std::io::{Read as _, Write as _};
use std::process::ExitCode;

use karst_bedrock::bundle::{
    request_from_json, request_to_json, response_from_json, response_to_json, OfflineSignature,
    Pending, Request, Response,
};
use karst_bedrock::log::{Op, Tier};
use karst_bedrock::{
    decode_log, encode_log, genesis_body, parse_anchor, parse_authority_list, parse_disable,
    parse_genesis, parse_node_revoke, parse_node_sign, parse_quorum_change, verify_log,
};
use karst_crypto::sign::{AuthorityKey, RootKey};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let result = match refs.as_slice() {
        ["init", kind, path] => init(kind, path),
        ["pubkey", path] => pubkey(path, false),
        ["pubkey", "--full", path] | ["pubkey", path, "--full"] => pubkey(path, true),
        ["genesis-request", out, zone, k, groups @ ..] => genesis_request(out, zone, k, groups),
        ["inspect", path] => inspect(path),
        ["sign", request, key, out] => sign(request, key, out),
        ["combine", request, out, responses @ ..] => combine(request, out, responses),
        ["verify", path] => verify(path),
        _ => {
            usage();
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("karst-bedrock: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "karst-bedrock — offline Bedrock signer

  init root|authority FILE    generate a key; writes FILE and FILE.pub
  pubkey [--full] FILE        print a key's fingerprint, or the key itself
  genesis-request OUT ZONE K ROOT.pub... -- Q AUTHORITY.pub...
                              make a root-quorum genesis request

Both tiers are ML-DSA-87, so a key seed is 32 bytes either way and the tier is
decided by which list in the log contains the key, not by the file.
  inspect FILE                decode and print a bundle or an encoded log
  sign REQUEST KEY OUT        verify a request, summarise it, sign it
  combine REQUEST OUT RESPONSE...
                              combine verified signatures into a raw log
  verify FILE                 verify an encoded log offline

Keys are written with mode 0600. A key file is a 32-byte seed and is the whole
secret: back it up before you use it."
    );
}

// ── root quorum bootstrap ──────────────────────────────────────────────────

// Makes the one request whose previous log is empty. Private keys never enter
// this command: each root signs the same request separately and `combine`
// verifies their responses before emitting the log the server accepts.
fn genesis_request(out: &str, zone: &str, k: &str, groups: &[&str]) -> Result<(), String> {
    let separator = groups
        .iter()
        .position(|value| *value == "--")
        .ok_or("genesis-request needs ROOT.pub... -- Q AUTHORITY.pub...")?;
    // `position` guarantees `separator` is in bounds, so neither of these can
    // fail — but this crate signs the root of trust, and `indexing_slicing` is
    // denied here precisely so that an argument about why a panic cannot
    // happen never has to be trusted.
    let (root_paths, from_separator) = groups
        .split_at_checked(separator)
        .ok_or("genesis-request needs ROOT.pub... -- Q AUTHORITY.pub...")?;
    // Past the `--` itself. An empty remainder falls through to the
    // `split_first` below, which already has the right message for it.
    let authority_group = from_separator.get(1..).unwrap_or_default();
    let (q, authority_paths) = authority_group
        .split_first()
        .ok_or("genesis-request needs an authority quorum after --")?;
    if root_paths.is_empty() || authority_paths.is_empty() {
        return Err("genesis-request needs root and authority public keys".into());
    }
    let k = parse_quorum("root", k, root_paths.len())?;
    let q = parse_quorum("authority", q, authority_paths.len())?;
    // A one-root genesis would turn recovery into a one-device bypass.
    if root_paths.len() < 3 || k < 2 {
        return Err(
            "genesis-request requires at least three roots and a threshold of at least two".into(),
        );
    }
    let roots = read_public_keys(root_paths)?;
    let authorities = read_public_keys(authority_paths)?;
    reject_duplicates("root", &roots)?;
    reject_duplicates("authority", &authorities)?;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch")?
        .as_secs()
        .try_into()
        .map_err(|_| "system time does not fit Bedrock's timestamp")?;
    let request = Request {
        log: Vec::new(),
        pending: vec![Pending {
            seq: 1,
            time,
            op: Op::Genesis,
            body: genesis_body(zone, &roots, k, &authorities, q),
        }],
    };
    request
        .verify()
        .map_err(|e| format!("genesis request: {e}"))?;
    write_new(out, request_to_json(&request).as_bytes())?;
    println!("wrote root-quorum genesis request to {out}");
    Ok(())
}

// Verifies every submitted response against the request's root list and
// threshold before writing the compact binary log for /bedrock/bootstrap/import.
fn combine(request_path: &str, out: &str, responses: &[&str]) -> Result<(), String> {
    if responses.is_empty() {
        return Err("combine needs at least one signed response bundle".into());
    }
    let request = request_from_json(&read_text(request_path)?)
        .map_err(|e| format!("reading request: {e}"))?;
    let verified = request.verify().map_err(|e| format!("request: {e}"))?;
    let mut signatures = Vec::new();
    for path in responses {
        let response = response_from_json(&read_text(path)?)
            .map_err(|e| format!("reading response {path}: {e}"))?;
        signatures.extend(response.signatures);
    }
    let log = verified
        .apply(&request.log, &Response { signatures })
        .map_err(|e| format!("combining responses: {e}"))?;
    write_new(out, &encode_log(&log))?;
    println!("wrote verified {}-entry Bedrock log to {out}", log.len());
    Ok(())
}

fn parse_quorum(tier: &str, raw: &str, count: usize) -> Result<u32, String> {
    let value: u32 = raw
        .parse()
        .map_err(|_| format!("{tier} quorum {raw:?} is not a positive integer"))?;
    if value == 0 || usize::try_from(value).ok().is_none_or(|v| v > count) {
        return Err(format!(
            "{tier} quorum {value} is unreachable with {count} public keys"
        ));
    }
    Ok(value)
}

fn read_public_keys(paths: &[&str]) -> Result<Vec<Vec<u8>>, String> {
    paths
        .iter()
        .map(|path| {
            let bytes = unhex(read_text(path)?.trim())?;
            if bytes.len() != karst_crypto::sign::ROOT_PUBLIC_KEY {
                return Err(format!(
                    "{path} is {} bytes; a Bedrock public key is {}",
                    bytes.len(),
                    karst_crypto::sign::ROOT_PUBLIC_KEY
                ));
            }
            Ok(bytes)
        })
        .collect()
}

fn reject_duplicates(tier: &str, keys: &[Vec<u8>]) -> Result<(), String> {
    for (index, key) in keys.iter().enumerate() {
        // `take(index)`, not a `[..index]` slice or a `get(..index)` that
        // would need an `unwrap_or_default`. This check is what stops one
        // device being counted twice toward a quorum, so the fix for the
        // slicing lint must not introduce a path where the comparison is
        // silently skipped instead — `take` has no such path.
        if keys.iter().take(index).any(|other| other == key) {
            return Err(format!("{tier} public-key list contains a duplicate"));
        }
    }
    Ok(())
}

fn write_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("creating {path}: {e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("writing {path}: {e}"))
}

// ── commands ────────────────────────────────────────────────────────────────

fn init(kind: &str, path: &str) -> Result<(), String> {
    if std::fs::metadata(path).is_ok() {
        // Never silently overwrite a key file. Overwriting a root key that has
        // signed a genesis is unrecoverable — spec §7 — so the tool refuses
        // rather than asking, because a prompt here would eventually be
        // answered wrongly.
        return Err(format!(
            "{path} already exists; refusing to overwrite a key"
        ));
    }

    // The entropy source is visible right here, at the call site, rather than
    // hidden behind an RNG trait object — see `RootKey::from_seed`.
    let (bytes, public) = match kind {
        "root" => {
            let mut seed = [0u8; karst_crypto::sign::ROOT_SEED];
            getrandom::fill(&mut seed).map_err(|e| format!("no entropy: {e}"))?;
            let k = RootKey::from_seed(&seed).map_err(|e| e.to_string())?;
            // The seed is the whole secret; ML-DSA expands it deterministically,
            // so nothing longer needs to reach the media. Since ADR-0015 Option
            // A moved the root off SLH-DSA this is 32 bytes rather than 96 —
            // small enough to be a practical paper backup.
            (seed.to_vec(), k.public_key())
        }
        "authority" => {
            let mut seed = [0u8; karst_crypto::sign::AUTHORITY_SEED];
            getrandom::fill(&mut seed).map_err(|e| format!("no entropy: {e}"))?;
            let k = AuthorityKey::from_seed(&seed).map_err(|e| e.to_string())?;
            (seed.to_vec(), k.public_key())
        }
        other => {
            return Err(format!(
                "unknown key kind {other:?}; want root or authority"
            ))
        }
    };

    write_private(path, &bytes)?;
    let pub_path = format!("{path}.pub");
    std::fs::write(&pub_path, format!("{}\n", hex(&public)))
        .map_err(|e| format!("writing {pub_path}: {e}"))?;

    println!("wrote {kind} key to {path}");
    println!("wrote public key to {pub_path}");
    println!("fingerprint: {}", fingerprint(&public));
    if kind == "root" {
        println!(
            "\nThis is a root key. If k of n roots are lost the network lock can never\n\
             be disabled and no new node can ever be added — there is no recovery path,\n\
             by design. Back this up offline, on separate media, before using it."
        );
    }
    Ok(())
}

/// The public key a 32-byte seed expands to.
///
/// **Tier is not a property of the key.** Since ADR-0015 Option A both tiers are
/// ML-DSA-87, so one seed expands to one public key and whether it is a root or
/// an authority is decided entirely by which list in the log contains it. That
/// is a better answer than the file length this used to guess from, and it is
/// the log's answer rather than a convention.
fn public_of(seed: &[u8]) -> Result<Vec<u8>, String> {
    AuthorityKey::from_seed(seed)
        .map(|k| k.public_key())
        .map_err(|e| e.to_string())
}

fn pubkey(path: &str, full: bool) -> Result<(), String> {
    let raw = read_bytes(path)?;
    if raw.len() != karst_crypto::sign::ROOT_SEED {
        return Err(format!(
            "{path} is {} bytes; a Bedrock key seed is {}",
            raw.len(),
            karst_crypto::sign::ROOT_SEED
        ));
    }
    let public = public_of(&raw)?;

    // The fingerprint by default, the key only when asked. An ML-DSA-87 public
    // key is 5 184 hex characters; printing that to a terminal by default would
    // make the one output a human is meant to check the one they scroll past.
    if full {
        println!("{}", hex(&public));
    } else {
        println!("{}", fingerprint(&public));
    }
    Ok(())
}

fn inspect(path: &str) -> Result<(), String> {
    let text = read_text(path)?;
    if let Ok(req) = request_from_json(&text) {
        let verified = req.verify().map_err(|e| format!("request: {e}"))?;
        println!("bundle: signing request");
        if let Some(st) = &verified.state {
            println!(
                "existing log: {} entries, head {}",
                st.head_seq,
                short(&st.head)
            );
        } else {
            println!("existing log: none — this is a genesis request");
        }
        println!();
        for (p, input) in &verified.to_sign {
            println!("  {}", describe(p.seq, p.op, &p.body, p.time));
            println!("    signing input: {}", short(input));
        }
        return Ok(());
    }

    // Not a bundle — try a raw encoded log.
    let entries =
        decode_log(&unhex(text.trim())?).map_err(|e| format!("not a bundle or log: {e}"))?;
    print_log(&entries)
}

fn verify(path: &str) -> Result<(), String> {
    let text = read_text(path)?;
    let entries = decode_log(&unhex(text.trim())?).map_err(|e| e.to_string())?;
    print_log(&entries)
}

fn print_log(entries: &[karst_bedrock::Entry]) -> Result<(), String> {
    let st = verify_log(entries).map_err(|e| format!("chain does not verify: {e}"))?;
    println!("chain verifies: {} entries", entries.len());
    println!("zone:      {}", st.zone);
    println!("head:      {} at seq {}", short(&st.head), st.head_seq);
    println!("roots:     {} of {} required", st.k, st.roots.len());
    println!("authority: {} of {} required", st.q, st.authorities.len());
    if st.disabled {
        println!("ENFORCEMENT DISABLED: {}", st.disabled_reason);
    }
    println!("\ncovered nodes:");
    let mut handles: Vec<&String> = st.covered.keys().collect();
    handles.sort();
    for h in handles {
        if let Some(c) = st.covered.get(h) {
            let window = match (c.not_before, c.expiry) {
                (0, 0) => "always".to_owned(),
                (nb, 0) => format!("from {}", utc(nb)),
                (0, ex) => format!("until {}", utc(ex)),
                (nb, ex) => format!("{}..{}", utc(nb), utc(ex)),
            };
            let revoked = st
                .revoked
                .get(h)
                .map_or(String::new(), |e| format!("  REVOKED at {}", utc(*e)));
            println!(
                "  {h}  identity {}  {window}{revoked}",
                fingerprint(&c.identity_key)
            );
            println!(
                "        kem {}  dh {}",
                fingerprint(&c.kem_public_key),
                fingerprint(&c.dh_public_key)
            );
        }
    }
    Ok(())
}

fn sign(request_path: &str, key_path: &str, out_path: &str) -> Result<(), String> {
    let req: Request = request_from_json(&read_text(request_path)?)
        .map_err(|e| format!("reading request: {e}"))?;

    // Everything below acts on the *recomputed* signing inputs, never on
    // anything the bundle asserted.
    let verified = req.verify().map_err(|e| format!("request: {e}"))?;

    let raw = read_bytes(key_path)?;
    if raw.len() != karst_crypto::sign::ROOT_SEED {
        return Err(format!(
            "{key_path} is {} bytes; a Bedrock key seed is {}",
            raw.len(),
            karst_crypto::sign::ROOT_SEED
        ));
    }
    let public = public_of(&raw)?;

    // **The log says which tier this key is.** Both tiers are ML-DSA-87 since
    // ADR-0015 Option A, so the key material cannot distinguish them and the
    // only honest source is the list it appears in. Searching both also catches
    // a key that is in neither — which used to present as a confusing index
    // error and now says plainly that this key cannot sign here.
    let (tier, signer_index) = locate_tier(&verified, &public)?;
    let root = (tier == Tier::Root)
        .then(|| RootKey::from_seed(&raw).map_err(|e| e.to_string()))
        .transpose()?;
    let authority = (tier == Tier::Authority)
        .then(|| AuthorityKey::from_seed(&raw).map_err(|e| e.to_string()))
        .transpose()?;

    println!("About to sign as {} #{signer_index}", tier_name(tier));
    println!("key fingerprint: {}\n", fingerprint(&public));
    let mut signing = Vec::new();
    for (p, input) in &verified.to_sign {
        if p.op.tier() != tier {
            println!(
                "  (skipping seq {} — {} is signed by {}, not {})",
                p.seq,
                p.op.as_str(),
                tier_name(p.op.tier()),
                tier_name(tier)
            );
            continue;
        }
        println!("  {}", describe(p.seq, p.op, &p.body, p.time));
        signing.push((p.seq, input.clone()));
    }
    if signing.is_empty() {
        return Err(format!(
            "nothing in this request is signed by a {}",
            tier_name(tier)
        ));
    }

    // A typed confirmation, not a keypress. The point is to make reading the
    // summary the path of least resistance, and "y" is cheaper than reading.
    print!("\nType 'sign' to confirm: ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    if answer.trim() != "sign" {
        return Err("not confirmed; nothing was signed".into());
    }

    let mut signatures = Vec::with_capacity(signing.len());
    for (seq, input) in signing {
        let sig = match (&root, &authority) {
            (Some(k), _) => k.sign(&input),
            (_, Some(k)) => k.sign(&input),
            _ => return Err("no key loaded".into()),
        }
        .map_err(|e| e.to_string())?;
        signatures.push(OfflineSignature {
            seq,
            signer_index,
            sig,
        });
    }

    let n = signatures.len();
    std::fs::write(out_path, response_to_json(&Response { signatures }))
        .map_err(|e| format!("writing {out_path}: {e}"))?;
    println!(
        "signed {n} entr{} into {out_path}",
        if n == 1 { "y" } else { "ies" }
    );
    Ok(())
}

/// Find which tier this key belongs to, and its index in that tier's list.
///
/// A key in **both** lists is refused rather than resolved. It would mean an
/// operator had installed one key as a root and an authority, which collapses
/// the separation ADR-0014's two tiers exist to provide — and guessing which
/// they meant would be the wrong response to finding it.
fn locate_tier(
    verified: &karst_bedrock::VerifiedRequest,
    public: &[u8],
) -> Result<(Tier, u32), String> {
    let root = locate(verified, Tier::Root, public).ok();
    let authority = locate(verified, Tier::Authority, public).ok();
    match (root, authority) {
        (Some(_), Some(_)) => Err("this key is in both the root and the authority list; \
             refusing to guess which tier it is meant to sign as"
            .to_owned()),
        (Some(i), None) => Ok((Tier::Root, i)),
        (None, Some(i)) => Ok((Tier::Authority, i)),
        (None, None) => Err(
            "this key is in neither the root nor the authority list for this log; \
                 it cannot sign here"
                .to_owned(),
        ),
    }
}

/// Find this key's index in one tier's list.
fn locate(
    verified: &karst_bedrock::VerifiedRequest,
    tier: Tier,
    public: &[u8],
) -> Result<u32, String> {
    // For a genesis request there is no prior state, so the key list is the one
    // inside the genesis body being signed.
    let list: Vec<Vec<u8>> = match (&verified.state, tier) {
        (Some(st), Tier::Root) => st.roots.clone(),
        (Some(st), Tier::Authority) => st.authorities.clone(),
        (None, _) => {
            let (p, _) = verified.to_sign.first().ok_or("empty request".to_owned())?;
            let g = parse_genesis(&p.body).map_err(|e| e.to_string())?;
            match tier {
                Tier::Root => g.roots,
                Tier::Authority => g.authorities,
            }
        }
    };

    list.iter()
        .position(|k| k == public)
        .and_then(|i| u32::try_from(i).ok())
        .ok_or_else(|| {
            format!(
                "this key is not in the {} list for this log; it cannot sign here",
                tier_name(tier)
            )
        })
}

const fn tier_name(t: Tier) -> &'static str {
    match t {
        Tier::Root => "root",
        Tier::Authority => "authority",
    }
}

/// Render an entry as a sentence an admin can check against their intent.
///
/// This is the security-relevant part of the tool. Everything it prints comes
/// from parsing the body that will actually be hashed — never from a label the
/// bundle supplied alongside it.
fn describe(seq: u64, op: Op, body: &[u8], time: i64) -> String {
    let detail = match op {
        Op::Genesis => parse_genesis(body).map_or_else(
            |e| format!("UNPARSEABLE genesis ({e})"),
            |g| {
                format!(
                    "create zone {:?} with {} roots (k={}) and {} authorities (q={})",
                    g.zone,
                    g.roots.len(),
                    g.k,
                    g.authorities.len(),
                    g.q
                )
            },
        ),
        Op::AuthorityList => parse_authority_list(body).map_or_else(
            |e| format!("UNPARSEABLE authority-list ({e})"),
            |a| {
                format!(
                    "REPLACE the authority list with {} keys, q={}",
                    a.authorities.len(),
                    a.q
                )
            },
        ),
        Op::NodeSign => parse_node_sign(body).map_or_else(
            |e| format!("UNPARSEABLE node-sign ({e})"),
            |n| {
                let window = match (n.not_before, n.expiry) {
                    (0, 0) => "no expiry".to_owned(),
                    (0, ex) => format!("expires {}", utc(ex)),
                    (nb, 0) => format!("from {}, no expiry", utc(nb)),
                    (nb, ex) => format!("from {}, expires {}", utc(nb), utc(ex)),
                };
                // All three fingerprints, because all three are what the
                // countersignature authorises (spec §6.1) and an admin who
                // checked only the identity key would be approving datapath
                // keys they never saw.
                format!(
                    "countersign node {:?}, {window}\n      identity {}\n      kem      {}\n      dh       {}",
                    n.handle,
                    fingerprint(&n.identity_key),
                    fingerprint(&n.kem_public_key),
                    fingerprint(&n.dh_public_key)
                )
            },
        ),
        Op::NodeRevoke => parse_node_revoke(body).map_or_else(
            |e| format!("UNPARSEABLE node-revoke ({e})"),
            |r| {
                format!(
                    "REVOKE node {:?} effective {} ({:?})",
                    r.handle,
                    utc(r.effective),
                    r.reason
                )
            },
        ),
        Op::QuorumChange => parse_quorum_change(body).map_or_else(
            |e| format!("UNPARSEABLE quorum-change ({e})"),
            |q| format!("change the authority quorum to {q}"),
        ),
        Op::Anchor => parse_anchor(body).map_or_else(
            |e| format!("UNPARSEABLE anchor ({e})"),
            |a| {
                format!(
                    "anchor the audit log at seq {} ({})",
                    a.audit_seq,
                    short(&a.audit_head)
                )
            },
        ),
        Op::Disable => parse_disable(body).map_or_else(
            |e| format!("UNPARSEABLE disable ({e})"),
            |r| format!("DISABLE ENFORCEMENT NETWORK-WIDE ({r:?})"),
        ),
    };
    format!("seq {seq} at {}: {detail}", utc(time))
}

// ── small helpers ───────────────────────────────────────────────────────────

fn read_text(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))
}

fn read_bytes(path: &str) -> Result<Vec<u8>, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("opening {path}: {e}"))?;
    let mut out = Vec::new();
    f.read_to_end(&mut out)
        .map_err(|e| format!("reading {path}: {e}"))?;
    Ok(out)
}

/// Write private key material with an owner-only mode.
///
/// The mode is set at creation rather than afterwards: a chmod after the fact
/// leaves a window in which the key is world-readable, which on a shared
/// machine is the whole exposure.
fn write_private(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("creating {path}: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("writing {path}: {e}"))
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for byte in b {
        // Infallible: writing to a String cannot fail, and swallowing the
        // Result here is what keeps this helper from returning one.
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Render a Unix timestamp as a UTC date an admin can check against intent.
///
/// "expires 1774915200" is not a thing anyone verifies; "expires
/// 2026-03-31T00:00:00Z" is. This is the one output the whole confirmation step
/// exists for, so it is worth twenty lines of calendar arithmetic rather than a
/// date-formatting dependency in a binary whose short dependency list is part
/// of its offline claim.
///
/// Civil-from-days after Howard Hinnant's `chrono`-compatible algorithm, which
/// is exact for the proleptic Gregorian calendar.
#[allow(clippy::many_single_char_names)] // the algorithm's own variable names
fn utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// A key's SHA-256 fingerprint, in the shape §8 of the spec asks for.
///
/// This is the representation a human is meant to compare. The keys themselves
/// are 48 bytes (root) and 1 952 bytes (authority, node); the latter renders as
/// 3 904 hex characters, which is not something anyone checks by eye.
fn fingerprint(public: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(public);
    format!("SHA-256:{}", hex(&h.finalize()))
}

/// A short, human-comparable rendering of a hash or key.
///
/// Both ends, not just the head: an attacker who can grind a prefix cannot as
/// easily grind both, and an admin comparing two values by eye reads the ends.
fn short(b: &[u8]) -> String {
    let h = hex(b);
    if h.len() <= 24 {
        return h;
    }
    let head = h.get(..12).unwrap_or_default();
    let tail = h.get(h.len().saturating_sub(12)..).unwrap_or_default();
    format!("{head}…{tail}")
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex input has an odd length".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).map_err(|_| "non-hex input".to_owned())?;
            u8::from_str_radix(text, 16).map_err(|_| "non-hex input".to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::utc;

    /// Calendar arithmetic written by hand deserves to be checked against known
    /// values, including the cases that catch an off-by-one in leap handling.
    #[test]
    fn utc_matches_known_timestamps() {
        for (secs, want) in [
            (0_i64, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (86_399, "1970-01-01T23:59:59Z"),
            (86_400, "1970-01-02T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"), // leap day in a leap century
            (1_709_164_800, "2024-02-29T00:00:00Z"), // ordinary leap year
            (1_772_323_200, "2026-03-01T00:00:00Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"), // 2100 is not a leap year
            (-86_400, "1969-12-31T00:00:00Z"),       // before the epoch
        ] {
            assert_eq!(utc(secs), want, "for {secs}");
        }
    }
}
