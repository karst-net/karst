// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// No crate-level `#![deny(unsafe_code)]` here, unlike `crates/karst-tun`/
// `crates/karst-ffi`/`bins/karstd`: that pattern (deny by default, allow and
// justify each site) is for isolating a handful of unsafe spots in an
// otherwise-safe crate (ADR-0003). Here, `#[no_mangle] extern "C" fn` itself
// trips rustc's `unsafe_code` lint on *every* exported function, including
// ones with no unsafe operation in their own body (`karst_embed_last_error`)
// — crossing a C ABI is this crate's entire purpose, not an exception to an
// otherwise-safe one, so a per-function `#[allow(unsafe_code)]` on every
// single item would be boilerplate rather than a meaningful flag. Every
// function that touches a raw pointer still carries its own `# Safety`
// doc comment stating the contract, which is the part ADR-0003 actually
// cares about preserving.
//! A hand-rolled C ABI over [`karst_embed`], for cgo and any other non-Rust
//! embedder — GitHub issue #214, `docs/adr/0044-embedded-library-mode.md`.
//!
//! **Why hand-rolled, not generated.** `crates/karst-ffi` (ADR-0029) uses
//! `UniFFI`, which targets Swift and Kotlin — Go is not one of its supported
//! languages, and the third-party (non-Mozilla) `uniffi-bindgen-go`
//! generator would be a new, less mature tool dependency for one consumer.
//! A plain `extern "C"` boundary is what cgo already expects natively, with
//! no generator in the loop. The header (`include/karst_embed_capi.h`) is
//! likewise hand-written rather than `cbindgen`-generated: `cbindgen` is
//! MPL-2.0, and ADR-0029's existing MPL allowance is scoped explicitly to
//! `UniFFI`'s own dependency tree, not a general license for this workspace.
//! A hand-written header is a real, named cost — it can drift from these
//! signatures — accepted here as the ADR records.
//!
//! **The opaque-handle pattern.** Every `karst_embed_*_t` the header
//! declares is, on this side, a boxed [`karst_embed`] type behind a raw
//! pointer (`Box::into_raw`/`Box::from_raw`). C never looks inside one; it
//! only ever holds the pointer and passes it back.
//!
//! **Free-ordering safety contract, stated once here rather than repeated
//! on every function:** a [`karst_embed::MeshTcpStream`],
//! [`karst_embed::MeshTcpListener`], or [`karst_embed::MeshUdpSocket`]
//! handle borrows the [`karst_embed::MeshNode`] it came from. The caller
//! must free every stream, listener, and UDP socket derived from a node
//! *before* calling [`karst_embed_free`] on that node — this crate leaks
//! the node (`Box::leak`-equivalent, via `Box::into_raw` with no matching
//! `Box::from_raw` until the caller explicitly frees it) specifically so
//! those borrows remain valid for as long as the node is alive, but nothing
//! stops a caller from freeing the node first and then dereferencing a
//! stale stream handle. A future version could close this with `Arc`-based
//! reference counting instead of a bare borrow; this pass states the
//! contract rather than building that, matching this project's "minimal
//! viable, named follow-up" convention elsewhere (see the ADR).
//!
//! **Error reporting.** Fallible functions return a sentinel (null, or a
//! negative integer) and leave the message in a thread-local, retrieved with
//! [`karst_embed_last_error`] — the same `errno`/`strerror` shape cgo
//! callers already expect, chosen over threading an output parameter through
//! every function.

use std::ffi::{c_char, CStr, CString};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::ptr;

use karst_embed::{MeshNode, MeshTcpListener, MeshTcpStream, MeshUdpSocket};

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn set_last_error(message: &str) {
    // A NUL embedded in a Rust `String` can only come from this crate's own
    // error text, never from attacker-controlled bytes reaching a C string
    // boundary unparsed — truncating at it, via `CString::new`'s own
    // fallback here, is strictly safer than panicking on a message whose
    // only job is to be read by a human.
    let text = CString::new(message).unwrap_or_else(|error| {
        let valid_len = error.nul_position();
        let truncated = error
            .into_vec()
            .get(..valid_len)
            .unwrap_or_default()
            .to_vec();
        CString::new(truncated).unwrap_or_default()
    });
    LAST_ERROR.with(|cell| *cell.borrow_mut() = Some(text));
}

/// The most recent error on this thread, or null if the last call did not
/// fail. Valid only until the next `karst_embed_*` call on this thread, and
/// must not be freed by the caller — read it (e.g. `strdup` it in C, or copy
/// it in Go) before making another call.
#[no_mangle]
pub extern "C" fn karst_embed_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        cell.borrow()
            .as_ref()
            .map_or(ptr::null(), |text| text.as_ptr())
    })
}

/// # Safety
/// `ptr` must be a valid, NUL-terminated C string, or null.
unsafe fn cstr_arg<'a>(ptr: *const c_char) -> Result<&'a str, &'static str> {
    if ptr.is_null() {
        return Err("unexpected null string argument");
    }
    // SAFETY: forwarded from this function's own contract above.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| "argument is not valid UTF-8")
}

fn alloc_cstring(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

/// Free a string this crate returned (`karst_embed_status_json`, or an
/// out-parameter such as `karst_embed_tcp_accept`'s peer address). A no-op
/// on null.
///
/// # Safety
/// `s` must be exactly a pointer this crate returned via `CString::into_raw`
/// and not already freed.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: forwarded from this function's own contract above.
    drop(unsafe { CString::from_raw(s) });
}

fn vec_into_raw_bytes(mut v: Vec<u8>) -> (*mut u8, usize) {
    v.shrink_to_fit();
    let len = v.len();
    let ptr = if len == 0 {
        std::ptr::NonNull::dangling().as_ptr()
    } else {
        v.as_mut_ptr()
    };
    std::mem::forget(v);
    (ptr, len)
}

/// Free a byte buffer `karst_embed_udp_recv_from` returned. A no-op on null.
///
/// # Safety
/// `(buf, len)` must be exactly the pair a single `karst_embed_*` call
/// returned, not already freed.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_free_bytes(buf: *mut u8, len: usize) {
    if buf.is_null() {
        return;
    }
    // SAFETY: forwarded from this function's own contract above — `len` is
    // both the length and the capacity, matching `vec_into_raw_bytes`'s own
    // `shrink_to_fit` before handing the pointer out.
    drop(unsafe { Vec::from_raw_parts(buf, len, len) });
}

/// Provision this node from a pasted administrator invitation. Returns `0`
/// on success, `-1` on error (see [`karst_embed_last_error`]).
///
/// # Safety
/// Every `*const c_char` argument must be a valid, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_enroll(
    invitation: *const c_char,
    config_path: *const c_char,
    state_dir: *const c_char,
) -> i32 {
    // SAFETY: forwarded from this function's own contract above.
    let result = unsafe {
        cstr_arg(invitation).and_then(|invitation| {
            cstr_arg(config_path).and_then(|config_path| {
                cstr_arg(state_dir).map(|state_dir| (invitation, config_path, state_dir))
            })
        })
    };
    let (invitation, config_path, state_dir) = match result {
        Ok(args) => args,
        Err(message) => {
            set_last_error(message);
            return -1;
        }
    };
    match karst_embed::enroll(invitation, Path::new(config_path), Path::new(state_dir)) {
        Ok(()) => 0,
        Err(error) => {
            set_last_error(&error.to_string());
            -1
        }
    }
}

/// As [`karst_embed_enroll`], but explicitly replaces an existing
/// configuration instead of refusing.
///
/// # Safety
/// As [`karst_embed_enroll`].
#[no_mangle]
pub unsafe extern "C" fn karst_embed_re_enroll(
    invitation: *const c_char,
    config_path: *const c_char,
    state_dir: *const c_char,
) -> i32 {
    // SAFETY: forwarded from this function's own contract above.
    let result = unsafe {
        cstr_arg(invitation).and_then(|invitation| {
            cstr_arg(config_path).and_then(|config_path| {
                cstr_arg(state_dir).map(|state_dir| (invitation, config_path, state_dir))
            })
        })
    };
    let (invitation, config_path, state_dir) = match result {
        Ok(args) => args,
        Err(message) => {
            set_last_error(message);
            return -1;
        }
    };
    match karst_embed::re_enroll(invitation, Path::new(config_path), Path::new(state_dir)) {
        Ok(()) => 0,
        Err(error) => {
            set_last_error(&error.to_string());
            -1
        }
    }
}

/// Load `config_path` and start the embedded engine. Returns null on error
/// (see [`karst_embed_last_error`]).
///
/// # Safety
/// `config_path`/`socket_path` must be valid, NUL-terminated C strings. The
/// returned pointer must eventually reach [`karst_embed_free`], after every
/// stream, listener, and UDP socket derived from it has already been freed
/// — see this crate's module-level safety note.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_start(
    config_path: *const c_char,
    socket_path: *const c_char,
) -> *mut MeshNode {
    // SAFETY: forwarded from this function's own contract above.
    let result =
        unsafe { cstr_arg(config_path).and_then(|c| cstr_arg(socket_path).map(|s| (c, s))) };
    let (config_path, socket_path) = match result {
        Ok(args) => args,
        Err(message) => {
            set_last_error(message);
            return ptr::null_mut();
        }
    };
    match MeshNode::start(Path::new(config_path), Path::new(socket_path)) {
        Ok(node) => Box::into_raw(Box::new(node)),
        Err(error) => {
            set_last_error(&error.to_string());
            ptr::null_mut()
        }
    }
}

/// Ask the node to stop, and wait for it to actually do so. Does not free
/// `node` — call [`karst_embed_free`] afterward (or let it call this itself).
///
/// # Safety
/// `node` must be a live pointer from [`karst_embed_start`], or null (a
/// no-op).
#[no_mangle]
pub unsafe extern "C" fn karst_embed_stop(node: *mut MeshNode) {
    if node.is_null() {
        return;
    }
    // SAFETY: forwarded from this function's own contract above.
    unsafe { &*node }.stop();
}

/// Stop and free a node. See this crate's module-level safety note: every
/// stream, listener, and UDP socket derived from `node` must already be
/// freed. A no-op on null.
///
/// # Safety
/// `node` must be a live pointer from [`karst_embed_start`], not already
/// freed, or null. `node` must not be used again after this call.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_free(node: *mut MeshNode) {
    if node.is_null() {
        return;
    }
    // SAFETY: forwarded from this function's own contract above.
    let node = unsafe { Box::from_raw(node) };
    node.stop();
    drop(node);
}

/// This node's own status, as JSON — the same body `karst status --json`
/// reads from a `LaunchDaemon`-packaged `karstd`. Returns null on error.
///
/// # Safety
/// `node` must be a live pointer from [`karst_embed_start`].
#[no_mangle]
pub unsafe extern "C" fn karst_embed_status_json(node: *mut MeshNode) -> *mut c_char {
    if node.is_null() {
        set_last_error("null node");
        return ptr::null_mut();
    }
    // SAFETY: forwarded from this function's own contract above.
    match unsafe { &*node }.status_json() {
        Ok(json) => alloc_cstring(&json),
        Err(error) => {
            set_last_error(&error.to_string());
            ptr::null_mut()
        }
    }
}

/// Open a TCP connection to another mesh peer's overlay address. Returns
/// null on error.
///
/// # Safety
/// `node` must be a live pointer from [`karst_embed_start`]; `address` must
/// be a valid, NUL-terminated C string. The returned stream borrows `node`
/// — see this crate's module-level safety note on free ordering.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_tcp_connect(
    node: *mut MeshNode,
    address: *const c_char,
    port: u16,
) -> *mut MeshTcpStream<'static> {
    if node.is_null() {
        set_last_error("null node");
        return ptr::null_mut();
    }
    // SAFETY: forwarded from this function's own contract above.
    let address: Result<IpAddr, &'static str> =
        unsafe { cstr_arg(address) }.and_then(|s| s.parse().map_err(|_| "invalid overlay address"));
    let address = match address {
        Ok(address) => address,
        Err(message) => {
            set_last_error(message);
            return ptr::null_mut();
        }
    };
    // SAFETY: `node` is live per this function's own contract; the returned
    // stream's borrow is asserted `'static` here, which is exactly the
    // module-level free-ordering contract the caller must uphold.
    let node: &'static MeshNode = unsafe { &*node };
    match node.connect_tcp(address, port) {
        Ok(stream) => Box::into_raw(Box::new(stream)),
        Err(error) => {
            set_last_error(&error.to_string());
            ptr::null_mut()
        }
    }
}

/// Listen for inbound TCP connections on an overlay port. Returns null on
/// error.
///
/// # Safety
/// `node` must be a live pointer from [`karst_embed_start`]. The returned
/// listener borrows `node` — see this crate's module-level safety note.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_tcp_listen(
    node: *mut MeshNode,
    port: u16,
) -> *mut MeshTcpListener<'static> {
    if node.is_null() {
        set_last_error("null node");
        return ptr::null_mut();
    }
    // SAFETY: as `karst_embed_tcp_connect`'s identical cast.
    let node: &'static MeshNode = unsafe { &*node };
    match node.listen_tcp(port) {
        Ok(listener) => Box::into_raw(Box::new(listener)),
        Err(error) => {
            set_last_error(&error.to_string());
            ptr::null_mut()
        }
    }
}

/// Block until a peer connects. `out_peer_address`/`out_peer_port`, if
/// non-null, receive the peer's overlay address — `*out_peer_address` is a
/// newly allocated string the caller must free with
/// [`karst_embed_free_string`]. Returns null on error.
///
/// # Safety
/// `listener` must be a live pointer from [`karst_embed_tcp_listen`].
/// `out_peer_address`/`out_peer_port` must each be a valid pointer or null.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_tcp_accept(
    listener: *mut MeshTcpListener<'static>,
    out_peer_address: *mut *mut c_char,
    out_peer_port: *mut u16,
) -> *mut MeshTcpStream<'static> {
    if listener.is_null() {
        set_last_error("null listener");
        return ptr::null_mut();
    }
    // SAFETY: forwarded from this function's own contract above.
    let listener = unsafe { &mut *listener };
    match listener.accept() {
        Ok((stream, peer)) => {
            // SAFETY: forwarded from this function's own contract above.
            unsafe {
                if !out_peer_address.is_null() {
                    *out_peer_address = alloc_cstring(&peer.ip().to_string());
                }
                if !out_peer_port.is_null() {
                    *out_peer_port = peer.port();
                }
            }
            Box::into_raw(Box::new(stream))
        }
        Err(error) => {
            set_last_error(&error.to_string());
            ptr::null_mut()
        }
    }
}

/// Read up to `len` bytes into `buf`. Returns the number of bytes read
/// (`0` means the peer closed its sending half), or `-1` on error.
///
/// # Safety
/// `stream` must be live. `buf` must point to at least `len` writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_tcp_read(
    stream: *mut MeshTcpStream<'static>,
    buf: *mut u8,
    len: usize,
) -> i64 {
    if stream.is_null() || (buf.is_null() && len > 0) {
        set_last_error("null argument");
        return -1;
    }
    // SAFETY: forwarded from this function's own contract above.
    let stream = unsafe { &mut *stream };
    // SAFETY: forwarded from this function's own contract above.
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match std::io::Read::read(stream, slice) {
        Ok(n) => i64::try_from(n).unwrap_or(i64::MAX),
        Err(error) => {
            set_last_error(&error.to_string());
            -1
        }
    }
}

/// Write up to `len` bytes from `buf`. Returns the number of bytes written,
/// or `-1` on error (including the connection no longer being active).
///
/// # Safety
/// `stream` must be live. `buf` must point to at least `len` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_tcp_write(
    stream: *mut MeshTcpStream<'static>,
    buf: *const u8,
    len: usize,
) -> i64 {
    if stream.is_null() || (buf.is_null() && len > 0) {
        set_last_error("null argument");
        return -1;
    }
    // SAFETY: forwarded from this function's own contract above.
    let stream = unsafe { &mut *stream };
    // SAFETY: forwarded from this function's own contract above.
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
    match std::io::Write::write(stream, slice) {
        Ok(n) => i64::try_from(n).unwrap_or(i64::MAX),
        Err(error) => {
            set_last_error(&error.to_string());
            -1
        }
    }
}

/// Free a TCP stream, releasing its underlying overlay socket. A no-op on
/// null.
///
/// # Safety
/// `stream` must be a live pointer from [`karst_embed_tcp_connect`] or
/// [`karst_embed_tcp_accept`], not already freed, or null.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_tcp_stream_free(stream: *mut MeshTcpStream<'static>) {
    if stream.is_null() {
        return;
    }
    // SAFETY: forwarded from this function's own contract above.
    drop(unsafe { Box::from_raw(stream) });
}

/// Free a TCP listener, releasing its underlying overlay socket. A no-op on
/// null.
///
/// # Safety
/// `listener` must be a live pointer from [`karst_embed_tcp_listen`], not
/// already freed, or null.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_tcp_listener_free(listener: *mut MeshTcpListener<'static>) {
    if listener.is_null() {
        return;
    }
    // SAFETY: forwarded from this function's own contract above.
    drop(unsafe { Box::from_raw(listener) });
}

/// Bind a UDP socket on an overlay port. Returns null on error.
///
/// # Safety
/// `node` must be a live pointer from [`karst_embed_start`]. The returned
/// socket borrows `node` — see this crate's module-level safety note.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_udp_bind(
    node: *mut MeshNode,
    port: u16,
) -> *mut MeshUdpSocket<'static> {
    if node.is_null() {
        set_last_error("null node");
        return ptr::null_mut();
    }
    // SAFETY: as `karst_embed_tcp_connect`'s identical cast.
    let node: &'static MeshNode = unsafe { &*node };
    match node.bind_udp(port) {
        Ok(socket) => Box::into_raw(Box::new(socket)),
        Err(error) => {
            set_last_error(&error.to_string());
            ptr::null_mut()
        }
    }
}

/// Send one datagram to a peer's overlay address. Returns `0` on success,
/// `-1` on error.
///
/// # Safety
/// `sock` must be live. `buf` must point to at least `len` readable bytes.
/// `to_address` must be a valid, NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_udp_send_to(
    sock: *mut MeshUdpSocket<'static>,
    buf: *const u8,
    len: usize,
    to_address: *const c_char,
    to_port: u16,
) -> i32 {
    if sock.is_null() || (buf.is_null() && len > 0) {
        set_last_error("null argument");
        return -1;
    }
    // SAFETY: forwarded from this function's own contract above.
    let address: Result<IpAddr, &'static str> = unsafe { cstr_arg(to_address) }
        .and_then(|s| s.parse().map_err(|_| "invalid overlay address"));
    let address = match address {
        Ok(address) => address,
        Err(message) => {
            set_last_error(message);
            return -1;
        }
    };
    // SAFETY: forwarded from this function's own contract above.
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
    // SAFETY: forwarded from this function's own contract above.
    match unsafe { &*sock }.send_to(slice, SocketAddr::new(address, to_port)) {
        Ok(()) => 0,
        Err(error) => {
            set_last_error(&error.to_string());
            -1
        }
    }
}

/// Block until a datagram arrives. `*out_buf`/`*out_len` receive a newly
/// allocated byte buffer the caller must free with
/// [`karst_embed_free_bytes`]; `out_from_address`/`out_from_port`, if
/// non-null, receive the sender's overlay address — `*out_from_address` is a
/// newly allocated string the caller must free with
/// [`karst_embed_free_string`]. Returns `0` on success, `-1` on error.
///
/// # Safety
/// `sock` must be live. `out_buf`/`out_len` must each be a valid pointer.
/// `out_from_address`/`out_from_port` must each be a valid pointer or null.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_udp_recv_from(
    sock: *mut MeshUdpSocket<'static>,
    out_buf: *mut *mut u8,
    out_len: *mut usize,
    out_from_address: *mut *mut c_char,
    out_from_port: *mut u16,
) -> i32 {
    if sock.is_null() || out_buf.is_null() || out_len.is_null() {
        set_last_error("null argument");
        return -1;
    }
    // SAFETY: forwarded from this function's own contract above.
    let (bytes, from) = unsafe { &*sock }.recv_from();
    let (ptr, len) = vec_into_raw_bytes(bytes);
    // SAFETY: forwarded from this function's own contract above.
    unsafe {
        *out_buf = ptr;
        *out_len = len;
        if !out_from_address.is_null() {
            *out_from_address = alloc_cstring(&from.ip().to_string());
        }
        if !out_from_port.is_null() {
            *out_from_port = from.port();
        }
    }
    0
}

/// Free a UDP socket, releasing its underlying overlay socket. A no-op on
/// null.
///
/// # Safety
/// `sock` must be a live pointer from [`karst_embed_udp_bind`], not already
/// freed, or null.
#[no_mangle]
pub unsafe extern "C" fn karst_embed_udp_socket_free(sock: *mut MeshUdpSocket<'static>) {
    if sock.is_null() {
        return;
    }
    // SAFETY: forwarded from this function's own contract above.
    drop(unsafe { Box::from_raw(sock) });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// A malformed invitation must report an error through
    /// `karst_embed_last_error`, not panic across the FFI boundary — a panic
    /// unwinding into C is undefined behavior, which is exactly what makes
    /// this boundary's own discipline (every entry point catches its own
    /// `Result`, none of them propagate a panic) worth a test.
    #[test]
    fn enroll_reports_a_malformed_invitation_through_last_error() {
        let invitation = CString::new("not-a-real-invitation").unwrap();
        let config_path = CString::new("/nonexistent/config.toml").unwrap();
        let state_dir = CString::new("/nonexistent/state").unwrap();
        let result = unsafe {
            karst_embed_enroll(
                invitation.as_ptr(),
                config_path.as_ptr(),
                state_dir.as_ptr(),
            )
        };
        assert_eq!(result, -1);
        let error = karst_embed_last_error();
        assert!(!error.is_null());
        let message = unsafe { CStr::from_ptr(error) }.to_str().unwrap();
        assert!(!message.is_empty());
    }

    #[test]
    fn start_returns_null_and_sets_last_error_for_a_missing_config() {
        let config_path = CString::new("/nonexistent/karst-embed-capi-config.toml").unwrap();
        let socket_path = CString::new("/nonexistent/karst-embed-capi.sock").unwrap();
        let node = unsafe { karst_embed_start(config_path.as_ptr(), socket_path.as_ptr()) };
        assert!(node.is_null());
        let error = karst_embed_last_error();
        assert!(!error.is_null());
    }

    #[test]
    fn free_functions_are_a_no_op_on_null() {
        unsafe {
            karst_embed_free_string(ptr::null_mut());
            karst_embed_free_bytes(ptr::null_mut(), 0);
            karst_embed_free(ptr::null_mut());
            karst_embed_stop(ptr::null_mut());
            karst_embed_tcp_stream_free(ptr::null_mut());
            karst_embed_tcp_listener_free(ptr::null_mut());
            karst_embed_udp_socket_free(ptr::null_mut());
        }
    }
}
