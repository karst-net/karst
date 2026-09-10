// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Win32 and Wintun FFI — the Windows counterpart to [`crate::sys_macos`], and
//! subject to the same discipline (ADR-0003): this module carries the crate's
//! `allow(unsafe_code)`, and every block states its safety argument.
//!
//! # Two kinds of API here
//!
//! IP Helper (`CreateUnicastIpAddressEntry`, `CreateIpForwardEntry2`, ...) is
//! an ordinary import: `windows-sys` declares it and the linker resolves it
//! against `iphlpapi.dll`, the same as any other Win32 call.
//!
//! Wintun is not. It ships as a DLL next to `karstd.exe`, not a Cargo
//! dependency — ADR-0017 is explicit that no Wintun wrapper crate is added,
//! so the Rust tree stays MIT/Apache with nothing GPL-adjacent linked into it.
//! [`Wintun::load`] therefore resolves every entry point at runtime with
//! `LoadLibraryExW` and `GetProcAddress`, against the exact signatures in
//! `wintun/include/wintun.h` from the archive ADR-0017 hashed. The function
//! pointer types below are transcribed from that header, not guessed.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    CloseHandle, FreeLibrary, ERROR_NO_MORE_ITEMS, FALSE, HANDLE, HMODULE, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, InitializeIpForwardEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_INET,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
};

/// A network adapter's LUID, as `WintunGetAdapterLUID` fills it in.
pub(crate) type Luid = NET_LUID_LH;

/// `luid` as its 64-bit form, for logging and `Debug` — `NET_LUID_LH` is a
/// Win32 union with no `Debug` impl of its own.
///
/// Not partial: `Value` is valid for any bit pattern the union can hold, so
/// reading it back out is well-defined regardless of which arm was last
/// written.
#[must_use]
pub(crate) fn luid_value(luid: Luid) -> u64 {
    // SAFETY: as the doc comment — `Value` is `NET_LUID_LH`'s plain `u64`
    // arm, valid for any bits the union holds.
    unsafe { luid.Value }
}

// ── Loading `wintun.dll` ────────────────────────────────────────────────────

type CreateAdapterFn = unsafe extern "system" fn(
    *const u16,
    *const u16,
    *const windows_sys::core::GUID,
) -> *mut c_void;
type CloseAdapterFn = unsafe extern "system" fn(*mut c_void);
type GetAdapterLuidFn = unsafe extern "system" fn(*mut c_void, *mut Luid);
type StartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSessionFn = unsafe extern "system" fn(*mut c_void);
type GetReadWaitEventFn = unsafe extern "system" fn(*mut c_void) -> HANDLE;
type ReceivePacketFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleaseReceivePacketFn = unsafe extern "system" fn(*mut c_void, *const u8);
type AllocateSendPacketFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendPacketFn = unsafe extern "system" fn(*mut c_void, *const u8);

/// The subset of `wintun.dll`'s exports Karst calls, resolved once at
/// startup and kept for the life of the adapter.
///
/// Every field is a function pointer or an opaque module handle — no raw
/// pointer into Wintun's own state — so sharing this across the daemon's
/// threads is exactly as safe as sharing any other `fn`. Wintun's session
/// functions are independently documented thread-safe (`wintun.h`:
/// `WintunReceivePacket`, `WintunReleaseReceivePacket`,
/// `WintunAllocateSendPacket` and `WintunSendPacket` are each "thread-safe");
/// the adapter/session lifecycle functions are not meant to race their own
/// teardown, which Rust's ordinary ownership rules already enforce because
/// [`Adapter`] and [`Session`] each require `&mut self` or consume `self` to
/// close.
#[derive(Debug)]
pub(crate) struct Wintun {
    module: HMODULE,
    create_adapter: CreateAdapterFn,
    close_adapter: CloseAdapterFn,
    get_adapter_luid: GetAdapterLuidFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    get_read_wait_event: GetReadWaitEventFn,
    receive_packet: ReceivePacketFn,
    release_receive_packet: ReleaseReceivePacketFn,
    allocate_send_packet: AllocateSendPacketFn,
    send_packet: SendPacketFn,
}

// SAFETY: every field is `Copy` (a raw function pointer or module handle);
// none of them alias mutable state that two threads could race, per the type
// doc comment above.
unsafe impl Send for Wintun {}
// SAFETY: as above — sharing `&Wintun` across threads only ever calls Wintun
// entry points documented thread-safe, or `WintunCreateAdapter`/
// `WintunStartSession` guarded by this process's own single-daemon lifecycle.
unsafe impl Sync for Wintun {}

impl Drop for Wintun {
    fn drop(&mut self) {
        // SAFETY: `self.module` was returned by a successful `LoadLibraryExW`
        // in `load` and is not used again after this call — `Wintun` is being
        // dropped, and every handle derived from it (`Adapter`, `Session`)
        // borrows `&Wintun` and so cannot outlive it either.
        unsafe {
            let _ = FreeLibrary(self.module);
        }
    }
}

impl Wintun {
    /// Load `wintun.dll` from an absolute path and resolve its API.
    ///
    /// **Never a bare name.** `path` must already be an absolute path into
    /// the protected install directory — ADR-0017: "Do not search the
    /// working directory or PATH for the DLL." `LOAD_LIBRARY_SEARCH_*`
    /// additionally confines the search for *`wintun.dll`'s own* dependency
    /// imports to System32 and its own directory, so nothing on this
    /// process's `PATH` or CWD can be substituted for one of them either.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error if the library or any of
    /// the required entry points cannot be resolved.
    pub(crate) fn load(path: &Path) -> io::Result<Arc<Self>> {
        let wide = wide_z(path.as_os_str());
        // SAFETY: `wide` is a live, NUL-terminated UTF-16 buffer for the
        // duration of the call, which is `LoadLibraryExW`'s only requirement
        // for its first argument; the reserved parameter is null and the
        // flags are a documented combination.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
            )
        };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `module` was just returned by a successful `LoadLibraryExW`
        // above. `proc` transmutes the resolved address to the function
        // pointer type transcribed from `wintun.h` for that exact export
        // name; a mismatch between the two is a programmer error in this
        // file, not something the loaded DLL can trigger.
        unsafe {
            Ok(Arc::new(Self {
                module,
                create_adapter: proc(module, "WintunCreateAdapter\0")?,
                close_adapter: proc(module, "WintunCloseAdapter\0")?,
                get_adapter_luid: proc(module, "WintunGetAdapterLUID\0")?,
                start_session: proc(module, "WintunStartSession\0")?,
                end_session: proc(module, "WintunEndSession\0")?,
                get_read_wait_event: proc(module, "WintunGetReadWaitEvent\0")?,
                receive_packet: proc(module, "WintunReceivePacket\0")?,
                release_receive_packet: proc(module, "WintunReleaseReceivePacket\0")?,
                allocate_send_packet: proc(module, "WintunAllocateSendPacket\0")?,
                send_packet: proc(module, "WintunSendPacket\0")?,
            }))
        }
    }

    /// Create a new adapter with the given name and tunnel type.
    ///
    /// Takes `self` as `&Arc<Self>` so the returned [`Adapter`] can hold its
    /// own clone and outlive any particular borrow of `Wintun` — it must,
    /// since it is closed from its own `Drop`, not by an explicit call the
    /// borrow checker could otherwise order for us.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error if Wintun refuses —
    /// without Administrator, `ERROR_ACCESS_DENIED`.
    pub(crate) fn create_adapter(
        self: &Arc<Self>,
        name: &str,
        tunnel_type: &str,
    ) -> io::Result<Adapter> {
        let name = wide_z_str(name);
        let tunnel_type = wide_z_str(tunnel_type);
        // SAFETY: `self.create_adapter` was resolved against
        // `WINTUN_CREATE_ADAPTER_FUNC`'s exact signature. Both string
        // arguments are live, NUL-terminated UTF-16 buffers for the duration
        // of the call; the GUID pointer is null, which the header documents
        // as "chosen by the system at random".
        let handle =
            unsafe { (self.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Adapter {
            wintun: Arc::clone(self),
            handle,
        })
    }

    /// Close an adapter this instance created. Called from [`Adapter::drop`]
    /// only — not exposed directly, so a handle cannot be closed twice.
    fn close_adapter_raw(&self, handle: *mut c_void) {
        // SAFETY: `handle` is non-null (the only way to construct an
        // `Adapter`) and was obtained from this same `Wintun` instance's
        // `WintunCreateAdapter`. `Adapter::drop` runs at most once per value.
        unsafe { (self.close_adapter)(handle) }
    }

    /// The adapter's LUID, for IP Helper addressing and routing calls.
    pub(crate) fn adapter_luid(&self, adapter: &Adapter) -> Luid {
        // SAFETY: `adapter.handle` is a live handle from this `Wintun`
        // instance. `luid` is a live, uniquely borrowed `Luid` the callee
        // fills in completely — `WintunGetAdapterLUID` has no partial-write
        // failure mode per the header (`VOID`, no error path).
        let mut luid: Luid = unsafe { mem::zeroed() };
        unsafe { (self.get_adapter_luid)(adapter.handle, &raw mut luid) };
        luid
    }

    /// Start a session with the given ring capacity (bytes, power of two,
    /// `WINTUN_MIN_RING_CAPACITY..=WINTUN_MAX_RING_CAPACITY`).
    ///
    /// As [`Wintun::create_adapter`], takes `&Arc<Self>` so the returned
    /// [`Session`] can outlive any particular borrow and close itself from
    /// `Drop`.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error if Wintun refuses, e.g. a
    /// capacity outside those bounds or one already outside a power of two.
    pub(crate) fn start_session(
        self: &Arc<Self>,
        adapter: &Adapter,
        capacity: u32,
    ) -> io::Result<Session> {
        // SAFETY: `adapter.handle` is live for the duration of the call,
        // which is all `WintunStartSession` requires of it.
        let handle = unsafe { (self.start_session)(adapter.handle, capacity) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is the session just started; `WintunGetReadWaitEvent`
        // has no failure mode per the header and the event it returns is
        // owned by the session, not by this call — see `Session::drop`,
        // which never closes it.
        let read_event = unsafe { (self.get_read_wait_event)(handle) };
        Ok(Session {
            wintun: Arc::clone(self),
            handle,
            read_event,
        })
    }

    /// End a session this instance started. Called from [`Session::drop`]
    /// only — not exposed directly, so a handle cannot be closed twice.
    fn end_session_raw(&self, handle: *mut c_void) {
        // SAFETY: `handle` is non-null and was obtained from this same
        // `Wintun` instance's `WintunStartSession`; `Session::drop` runs at
        // most once per value.
        unsafe { (self.end_session)(handle) }
    }

    /// Retrieve one packet from `session`, or `Ok(None)` if the ring is empty
    /// right now. Called from [`Session::receive`] — see it for the public
    /// surface.
    ///
    /// # Errors
    /// An [`io::Error`] for any failure other than an empty ring, including
    /// `ERROR_HANDLE_EOF` when the adapter is terminating.
    fn receive_packet<'s>(&self, session: &'s Session) -> io::Result<Option<Packet<'s>>> {
        let mut len: u32 = 0;
        // SAFETY: `session.handle` is live. `len` is a live, uniquely
        // borrowed `u32` `WintunReceivePacket` writes through on success and
        // may leave unwritten on failure — read only when `ptr` is non-null.
        let ptr = unsafe { (self.receive_packet)(session.handle, &raw mut len) };
        if ptr.is_null() {
            let err = io::Error::last_os_error();
            return if err.raw_os_error() == i32::try_from(ERROR_NO_MORE_ITEMS).ok() {
                Ok(None)
            } else {
                Err(err)
            };
        }
        Ok(Some(Packet { session, ptr, len }))
    }

    /// Release a packet returned by [`Wintun::receive_packet`]. Called from
    /// [`Packet::drop`] only, so a packet cannot be released twice.
    fn release_receive_packet_raw(&self, session_handle: *mut c_void, ptr: *const u8) {
        // SAFETY: `session_handle` is live; `ptr` was returned by this same
        // session's `WintunReceivePacket` and has not been released yet —
        // `Packet` has no `Copy`/`Clone` and this is its only `Drop`.
        unsafe { (self.release_receive_packet)(session_handle, ptr) }
    }

    /// Allocate space in `session`'s send ring for a packet of exactly
    /// `packet.len()` bytes, copy it in, and hand it to Wintun. Called from
    /// [`Session::send`] — see it for the public surface.
    ///
    /// One call rather than allocate-then-send-as-two-steps, because the
    /// buffer `WintunAllocateSendPacket` returns is valid only until the
    /// matching `WintunSendPacket` — there is no safe way to hand the caller
    /// a longer-lived reference to it.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error if the ring is full
    /// (`ERROR_BUFFER_OVERFLOW`) or the adapter is terminating.
    fn send_packet(&self, session: &Session, packet: &[u8]) -> io::Result<()> {
        #[allow(clippy::cast_possible_truncation)]
        let len = packet.len() as u32;
        // SAFETY: `session.handle` is live and `len` matches `packet.len()`
        // exactly (checked by the caller against `WINTUN_MAX_IP_PACKET_SIZE`
        // before this is reached — see `crate::windows::Tun::send`).
        let ptr = unsafe { (self.allocate_send_packet)(session.handle, len) };
        if ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `ptr` is non-null and, per the header, writable for exactly
        // `len` bytes — the size just requested and returned successfully.
        // `packet` is a live, immutably borrowed slice of that same length,
        // and the two allocations cannot overlap since one was just handed
        // back by the DLL.
        unsafe { std::ptr::copy_nonoverlapping(packet.as_ptr(), ptr, packet.len()) };
        // SAFETY: `session.handle` is live and `ptr` is the buffer just
        // filled, not yet sent — `WintunSendPacket` both sends and releases
        // it, so it is used exactly once.
        unsafe { (self.send_packet)(session.handle, ptr) };
        Ok(())
    }
}

/// Resolve one export by name and reinterpret it as `F`.
///
/// # Safety
/// `module` must be a handle from a successful `LoadLibraryExW` that has not
/// yet been freed, and `F` must be exactly the function pointer type the
/// named export implements — there is no way for `GetProcAddress` to check
/// that, which is why every call site above cites the header entry it
/// transcribes.
unsafe fn proc<F: Copy>(module: HMODULE, name_z: &str) -> io::Result<F> {
    debug_assert_eq!(mem::size_of::<F>(), mem::size_of::<usize>());
    // SAFETY: `module` is live per the caller's contract. `name_z` is a
    // `'static` byte string the caller wrote with a trailing NUL, satisfying
    // `GetProcAddress`'s requirement for `lpprocname`.
    let addr = unsafe { GetProcAddress(module, name_z.as_ptr()) };
    match addr {
        Some(f) => {
            // SAFETY: sizes match (asserted above); the caller's contract
            // supplies the rest — that `F` is the correct signature for this
            // export.
            Ok(unsafe { mem::transmute_copy::<_, F>(&f) })
        }
        None => Err(io::Error::last_os_error()),
    }
}

/// Encode a path as a NUL-terminated UTF-16 buffer for a `*const u16` Win32
/// argument.
fn wide_z(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// As [`wide_z`], for a `&str` rather than a path.
fn wide_z_str(s: &str) -> Vec<u16> {
    wide_z(std::ffi::OsStr::new(s))
}

/// An open Wintun adapter, and the loaded library it was created from.
///
/// Owns a clone of the `Arc<Wintun>` it was created with rather than
/// borrowing one, so it can close itself in `Drop` regardless of how long the
/// caller keeps it — see [`Wintun::create_adapter`].
#[derive(Debug)]
pub(crate) struct Adapter {
    wintun: Arc<Wintun>,
    handle: *mut c_void,
}

impl Drop for Adapter {
    fn drop(&mut self) {
        self.wintun.close_adapter_raw(self.handle);
    }
}

/// A running Wintun session: the ring buffers `karst-tun` reads and writes.
#[derive(Debug)]
pub(crate) struct Session {
    wintun: Arc<Wintun>,
    handle: *mut c_void,
    read_event: HANDLE,
}

impl Session {
    /// The event Wintun signals when a packet becomes available. **Not
    /// owned** — the header is explicit that `WintunEndSession` closes it and
    /// a caller must not.
    pub(crate) fn read_event(&self) -> HANDLE {
        self.read_event
    }

    /// Retrieve one packet, or `Ok(None)` if the ring is empty right now.
    ///
    /// Callers that get `None` should wait on [`Session::read_event`] and a
    /// [`ShutdownEvent`] together — see [`wait_for_data_or_shutdown`] — before
    /// calling again, per the header: spinning on this immediately is what
    /// "after spinning on it for a while under heavy load" describes as the
    /// alternative.
    ///
    /// # Errors
    /// An [`io::Error`] for any failure other than an empty ring, including
    /// `ERROR_HANDLE_EOF` when the adapter is terminating.
    pub(crate) fn receive(&self) -> io::Result<Option<Packet<'_>>> {
        self.wintun.receive_packet(self)
    }

    /// Send one packet, blocking only long enough to copy it into the ring.
    ///
    /// # Errors
    /// An [`io::Error`] from the last Win32 error if the ring is full
    /// (`ERROR_BUFFER_OVERFLOW`) or the adapter is terminating.
    pub(crate) fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.wintun.send_packet(self, packet)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.wintun.end_session_raw(self.handle);
    }
}

/// One packet borrowed from the receive ring.
///
/// Dropping this calls `WintunReleaseReceivePacket`, so the ring slot is
/// reclaimed exactly once, at the end of the borrow that reads it — there is
/// no way to hold `Packet` past the `recv` call that produced it, because its
/// lifetime is tied to `&Session`.
pub(crate) struct Packet<'s> {
    session: &'s Session,
    ptr: *mut u8,
    len: u32,
}

impl Packet<'_> {
    /// The packet bytes: a bare layer-3 IPv4 or IPv6 datagram, exactly as the
    /// other platforms hand back.
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: `ptr` is non-null and was returned by `WintunReceivePacket`
        // with `len` as its documented `_Post_writable_byte_size_`, and
        // remains valid until `WintunReleaseReceivePacket` — which is exactly
        // `Drop`, run after every read of this slice ends because it borrows
        // `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len as usize) }
    }
}

impl Drop for Packet<'_> {
    fn drop(&mut self) {
        self.session
            .wintun
            .release_receive_packet_raw(self.session.handle, self.ptr);
    }
}

// ── The shutdown event ──────────────────────────────────────────────────────
//
// Wintun's read-wait event alone leaves no way to wake the blocking read
// thread when `karstd` wants to stop it — plan §3's "the shutdown path does
// not [map cleanly]". A second, manual-reset event turns "stop" into a first
// class wake reason alongside "data is ready": `Tun::recv` waits on both with
// `WaitForMultipleObjects`.

/// A manual-reset event this process creates and owns, for waking a blocked
/// [`wait_for_data_or_shutdown`] call.
#[derive(Debug)]
pub(crate) struct ShutdownEvent {
    handle: HANDLE,
}

// SAFETY: a Win32 event `HANDLE` has no thread affinity; `SetEvent` and
// `WaitForMultipleObjects` are documented safe to call from any thread that
// holds a copy of the value.
unsafe impl Send for ShutdownEvent {}
// SAFETY: as above.
unsafe impl Sync for ShutdownEvent {}

impl ShutdownEvent {
    /// Create an unsignaled, manual-reset event with no name — this process
    /// is the only holder, so nothing else needs to find it by name.
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: every argument is either null or a plain `BOOL`/`FALSE`
        // constant; `CreateEventW` has no other precondition.
        let handle = unsafe {
            CreateEventW(
                std::ptr::null(),
                /* bManualReset */ 1,
                /* bInitialState */ 0,
                std::ptr::null(),
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    /// Signal the event, waking every thread blocked in
    /// [`wait_for_data_or_shutdown`] on it.
    ///
    /// Manual-reset, so this is idempotent: a second shutdown request from a
    /// second signal (`SERVICE_CONTROL_STOP` racing a power event, say) finds
    /// the event already set rather than needing to be coalesced by hand.
    pub(crate) fn signal(&self) {
        // SAFETY: `self.handle` is live for the life of `self`, which is
        // `SetEvent`'s only requirement.
        unsafe {
            let _ = SetEvent(self.handle);
        }
    }
}

impl Drop for ShutdownEvent {
    fn drop(&mut self) {
        // SAFETY: `self.handle` was created by `CreateEventW` in `new` and is
        // not used again after this call.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Whether a wait on `(read_event, shutdown_event)` woke because data is
/// ready or because shutdown was signaled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wake {
    /// The read-wait event fired — retry `WintunReceivePacket`.
    DataReady,
    /// The shutdown event fired — stop reading.
    Shutdown,
}

/// Block until Wintun has data, or shutdown is requested, whichever is
/// first.
///
/// # Errors
/// An [`io::Error`] if the wait itself fails — not for a timeout, since this
/// waits forever by design (`INFINITE`): the two events between them cover
/// every reason to stop waiting.
pub(crate) fn wait_for_data_or_shutdown(
    read_event: HANDLE,
    shutdown: &ShutdownEvent,
) -> io::Result<Wake> {
    let handles = [read_event, shutdown.handle];
    // SAFETY: `handles` is a live array of exactly two valid, open event
    // handles for the duration of the call — `read_event` outlives the
    // session that owns it (checked by `Tun::recv`'s borrow of `Session`),
    // and `shutdown.handle` outlives `self` by construction.
    let count = u32::try_from(handles.len()).unwrap_or(0);
    let result = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), FALSE, INFINITE) };
    if result == WAIT_OBJECT_0 {
        Ok(Wake::DataReady)
    } else if result == WAIT_OBJECT_0 + 1 {
        Ok(Wake::Shutdown)
    } else {
        Err(io::Error::last_os_error())
    }
}

// ── IP Helper: addressing and routing ───────────────────────────────────────
//
// Plan §4: the IP Helper API directly, not `netsh` — its output is
// locale-dependent text, and IP Helper is "well-documented, stable, and
// directly callable". These are ordinary linked imports (`windows-sys`
// declares `iphlpapi.dll`'s exports), unlike Wintun above.

/// Build a `SOCKADDR_INET` for `addr`. Its `si_family` selects which union
/// arm every consumer of the value must read.
fn sockaddr_inet(addr: IpAddr) -> SOCKADDR_INET {
    match addr {
        IpAddr::V4(v4) => {
            let mut sin: SOCKADDR_IN = unsafe { mem::zeroed() };
            sin.sin_family = AF_INET;
            sin.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_be_bytes(v4.octets()),
                },
            };
            SOCKADDR_INET { Ipv4: sin }
        }
        IpAddr::V6(v6) => {
            let mut sin6: SOCKADDR_IN6 = unsafe { mem::zeroed() };
            sin6.sin6_family = AF_INET6;
            sin6.sin6_addr = IN6_ADDR {
                u: IN6_ADDR_0 { Byte: v6.octets() },
            };
            SOCKADDR_INET { Ipv6: sin6 }
        }
    }
}

/// Read the address family `sockaddr_inet` was built for back out.
fn family_of(addr: &SOCKADDR_INET) -> u16 {
    // SAFETY: `si_family` occupies the same leading bytes in every arm of
    // this union (`ADDRESS_FAMILY` is a `u16` and both `sockaddr_in` and
    // `sockaddr_in6` put it first, matching the real `sockaddr` layout every
    // arm has to agree with), so reading it through any arm is well-defined
    // regardless of which one was last written.
    unsafe { addr.si_family }
}

/// Assign `addr/prefix_len` to the interface named by `luid`.
///
/// Additive: Windows does not replace an interface's existing address the
/// way `SIOCSIFADDR`/`ifconfig` do, so this is also what
/// [`crate::windows::Tun::add_secondary_address`] calls — there is no
/// separate "alias" mode to ask for here.
///
/// `SkipAsSource` is set so the tunnel address is never chosen as the source
/// for off-mesh traffic — plan §4.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error, unless it is
/// `ERROR_OBJECT_ALREADY_EXISTS`, which is not an error: see
/// [`crate::windows::Tun::add_route`] for why the same idempotence matters
/// for routes, and it applies here for the same reason.
pub(crate) fn create_unicast_address(luid: Luid, addr: IpAddr, prefix_len: u8) -> io::Result<()> {
    // SAFETY: `row` is a live, uniquely borrowed `MIB_UNICASTIPADDRESS_ROW`;
    // `InitializeUnicastIpAddressEntry` writes every field to its documented
    // default before this function overrides the three that matter.
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };
    row.InterfaceLuid = luid;
    row.Address = sockaddr_inet(addr);
    row.OnLinkPrefixLength = prefix_len;
    row.SkipAsSource = true;

    // SAFETY: `row` is fully initialized above — every field either came
    // from `InitializeUnicastIpAddressEntry`'s documented defaults or was
    // just set — and lives for the duration of this call, which is
    // `CreateUnicastIpAddressEntry`'s only requirement.
    let status = unsafe { CreateUnicastIpAddressEntry(&raw const row) };
    ok_or_last_error(status)
}

/// Add an on-link route to `dst/prefix_len` over the interface named by
/// `luid`, with no gateway — plan §4: a tunnel peer is the far end of the
/// interface, not behind a next hop.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error, except
/// `ERROR_OBJECT_ALREADY_EXISTS`, which [`crate::windows::Tun::add_route`]
/// treats as success for the reason given there.
pub(crate) fn create_forward_route(luid: Luid, dst: IpAddr, prefix_len: u8) -> io::Result<()> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    // SAFETY: `row` is a live, uniquely borrowed `MIB_IPFORWARD_ROW2`;
    // `InitializeIpForwardEntry` writes every field to its documented
    // default before the fields below override what matters.
    unsafe { InitializeIpForwardEntry(&raw mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = sockaddr_inet(dst);
    row.DestinationPrefix.PrefixLength = prefix_len;
    // An unspecified `NextHop` of the destination's own family, matching
    // "on-link, no gateway". `family_of` mirrors `DestinationPrefix`'s family
    // into the otherwise-zeroed `NextHop`, since IP Helper validates the two
    // agree.
    row.NextHop = sockaddr_inet(match dst {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });
    debug_assert_eq!(
        family_of(&row.NextHop),
        family_of(&row.DestinationPrefix.Prefix)
    );
    // Low enough that mesh routes win over the interface metric alone — plan
    // §4 — without pinning an exact value that would fight whatever
    // `InitializeIpForwardEntry` already defaulted for automatic metric.
    row.Metric = 0;

    // SAFETY: `row` is fully initialized above and lives for the duration of
    // this call, which is `CreateIpForwardEntry2`'s only requirement.
    let status = unsafe { CreateIpForwardEntry2(&raw const row) };
    match ok_or_last_error(status) {
        Err(e) if e.raw_os_error() == Some(ERROR_OBJECT_ALREADY_EXISTS) => Ok(()),
        other => other,
    }
}

/// Remove the on-link route to `dst/prefix_len` over the interface named by
/// `luid`.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error. A route that is already
/// absent is **not** an error: desired state, not a specific prior state, is
/// what matters — the same rule [`crate::windows::Tun::remove_route`] states
/// for the reason it applies at the `Tun` level.
pub(crate) fn delete_forward_route(luid: Luid, dst: IpAddr, prefix_len: u8) -> io::Result<()> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&raw mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = sockaddr_inet(dst);
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.NextHop = sockaddr_inet(match dst {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });

    // SAFETY: as `create_forward_route`.
    let status = unsafe { DeleteIpForwardEntry2(&raw const row) };
    match ok_or_last_error(status) {
        Err(e) if e.raw_os_error() == Some(ERROR_NOT_FOUND) => Ok(()),
        other => other,
    }
}

/// The kernel interface index for `luid`, for callers that need the older
/// index-based identity rather than the LUID.
///
/// # Errors
/// An [`io::Error`] from the last Win32 error if the LUID does not name a
/// current interface.
pub(crate) fn luid_to_index(luid: Luid) -> io::Result<u32> {
    let mut index: u32 = 0;
    // SAFETY: `luid` is a live value for the duration of the call and
    // `index` is a live, uniquely borrowed `u32` the callee writes through on
    // success.
    let status = unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut index) };
    ok_or_last_error(status)?;
    Ok(index)
}

/// `ERROR_NOT_FOUND`, from `winerror.h`. Not part of the `Win32_Foundation`
/// feature's curated re-exports at this crate's `windows-sys` version, so
/// named here rather than pulling in the much larger raw error-code module
/// for one constant.
const ERROR_NOT_FOUND: i32 = 1168;

/// `ERROR_OBJECT_ALREADY_EXISTS`, from `winerror.h`. As [`ERROR_NOT_FOUND`]:
/// named locally rather than importing the raw constants module for one
/// value.
const ERROR_OBJECT_ALREADY_EXISTS: i32 = 5010;

/// Map an IP Helper `NETIO_STATUS`/`ERROR_SUCCESS`-shaped return to a
/// `Result`, the same convention every other Win32 status code in this module
/// uses.
fn ok_or_last_error(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ))
    }
}
