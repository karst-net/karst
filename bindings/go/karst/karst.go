// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// Package karst embeds a Karst mesh node directly into a Go application,
// with no karstd sidecar process alongside it — GitHub issue #214,
// docs/adr/0044-embedded-library-mode.md.
//
// This package cgo-links against crates/karst-embed-capi's hand-rolled C
// ABI. The header (its checked-in, fixed repo-relative path) is found
// automatically via cgo's ${SRCDIR}; the compiled library is not, since its
// location depends on the build profile. Build crates/karst-embed-capi
// first (cargo build -p karst-embed-capi --release), then:
//
//	export CGO_LDFLAGS="-L$(repo_root)/target/release"
//	export LD_LIBRARY_PATH="$(repo_root)/target/release:$LD_LIBRARY_PATH"
//	go build ./...
//
// See .github/workflows/go-embed-build.yml for the exact order CI uses.
//
// MeshNode wraps crates/karst-embed's engine-lifecycle shape one layer
// further out: enroll, start on a background thread, and drive
// karst_tun::Userspace's TCP/UDP socket API — already built for "containers
// that cannot create a TUN device" — rather than a kernel device this
// process has no privilege to create.
package karst

/*
#cgo CFLAGS: -I${SRCDIR}/../../../crates/karst-embed-capi/include
#cgo LDFLAGS: -lkarst_embed_capi
#include <stdlib.h>
#include "karst_embed_capi.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"time"
	"unsafe"
)

// ErrNotSupported is returned by the deadline methods on [TCPStream] and
// [UDPSocket] — the underlying poll-and-sleep bridge (crates/karst-embed's
// own doc comment explains why it exists) has no deadline concept yet. A
// named, stated gap rather than a silent no-op.
var ErrNotSupported = errors.New("karst: not supported by the embedded transport")

// lastError reads crates/karst-embed-capi's thread-local last-error string.
// Must be called on the same OS thread as the failing call — see
// [lockOSThreadForFFI].
func lastError() error {
	msg := C.karst_embed_last_error()
	if msg == nil {
		return errors.New("karst: unknown error")
	}
	return errors.New("karst: " + C.GoString(msg))
}

// Every exported function here that can fail locks its goroutine to its OS
// thread for the duration of the cgo call: crates/karst-embed-capi's
// last-error string is thread-local, and Go's scheduler is free to move a
// goroutine to a different OS thread between two cgo calls, which would read
// another call's error or none at all.
func lockOSThreadForFFI() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

// MeshAddr is a mesh overlay address — the address family this package's
// connections and sockets use instead of a host IP, since there is no host
// network interface underneath them.
type MeshAddr struct {
	IPAddr string
	Port   uint16
}

// Network implements [net.Addr].
func (a *MeshAddr) Network() string { return "karst" }

// String implements [net.Addr].
func (a *MeshAddr) String() string { return fmt.Sprintf("%s:%d", a.IPAddr, a.Port) }

// Enroll provisions this node from a pasted administrator invitation.
func Enroll(invitation, configPath, stateDir string) error {
	defer lockOSThreadForFFI()()
	cInvitation := C.CString(invitation)
	defer C.free(unsafe.Pointer(cInvitation))
	cConfigPath := C.CString(configPath)
	defer C.free(unsafe.Pointer(cConfigPath))
	cStateDir := C.CString(stateDir)
	defer C.free(unsafe.Pointer(cStateDir))

	if C.karst_embed_enroll(cInvitation, cConfigPath, cStateDir) != 0 {
		return lastError()
	}
	return nil
}

// ReEnroll is as [Enroll], but explicitly replaces an existing configuration
// instead of refusing.
func ReEnroll(invitation, configPath, stateDir string) error {
	defer lockOSThreadForFFI()()
	cInvitation := C.CString(invitation)
	defer C.free(unsafe.Pointer(cInvitation))
	cConfigPath := C.CString(configPath)
	defer C.free(unsafe.Pointer(cConfigPath))
	cStateDir := C.CString(stateDir)
	defer C.free(unsafe.Pointer(cStateDir))

	if C.karst_embed_re_enroll(cInvitation, cConfigPath, cStateDir) != 0 {
		return lastError()
	}
	return nil
}

// MeshNode is a running, embedded mesh node.
//
// [Enroll] or [ReEnroll] must already have written configPath before
// [Start]. Call [MeshNode.Close] when done; a finalizer calls it too, as a
// defensive fallback, not the intended path — the same posture
// crates/karst-embed's own Rust Drop impl documents.
type MeshNode struct {
	ptr *C.karst_embed_node_t
}

// Start loads the config [Enroll] already wrote to configPath, then starts
// the engine on a background thread. configPath's network_mode must already
// be "userspace". socketPath is this process's own private control socket.
func Start(configPath, socketPath string) (*MeshNode, error) {
	defer lockOSThreadForFFI()()
	cConfigPath := C.CString(configPath)
	defer C.free(unsafe.Pointer(cConfigPath))
	cSocketPath := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cSocketPath))

	ptr := C.karst_embed_start(cConfigPath, cSocketPath)
	if ptr == nil {
		return nil, lastError()
	}
	node := &MeshNode{ptr: ptr}
	runtime.SetFinalizer(node, (*MeshNode).Close)
	return node, nil
}

// StatusJSON is this node's own status, as JSON — the same body
// `karst status --json` reads from a LaunchDaemon-packaged karstd.
func (n *MeshNode) StatusJSON() (string, error) {
	defer lockOSThreadForFFI()()
	s := C.karst_embed_status_json(n.ptr)
	if s == nil {
		return "", lastError()
	}
	defer C.karst_embed_free_string(s)
	return C.GoString(s), nil
}

// DialTCP opens a TCP connection to another mesh peer's overlay address.
func (n *MeshNode) DialTCP(address string, port uint16) (*TCPStream, error) {
	defer lockOSThreadForFFI()()
	cAddress := C.CString(address)
	defer C.free(unsafe.Pointer(cAddress))

	ptr := C.karst_embed_tcp_connect(n.ptr, cAddress, C.uint16_t(port))
	if ptr == nil {
		return nil, lastError()
	}
	stream := &TCPStream{ptr: ptr, remote: &MeshAddr{IPAddr: address, Port: port}}
	runtime.SetFinalizer(stream, (*TCPStream).Close)
	return stream, nil
}

// ListenTCP listens for inbound TCP connections on an overlay port.
func (n *MeshNode) ListenTCP(port uint16) (*TCPListener, error) {
	defer lockOSThreadForFFI()()
	ptr := C.karst_embed_tcp_listen(n.ptr, C.uint16_t(port))
	if ptr == nil {
		return nil, lastError()
	}
	listener := &TCPListener{ptr: ptr, port: port}
	runtime.SetFinalizer(listener, (*TCPListener).Close)
	return listener, nil
}

// BindUDP binds a UDP socket on an overlay port.
func (n *MeshNode) BindUDP(port uint16) (*UDPSocket, error) {
	defer lockOSThreadForFFI()()
	ptr := C.karst_embed_udp_bind(n.ptr, C.uint16_t(port))
	if ptr == nil {
		return nil, lastError()
	}
	sock := &UDPSocket{ptr: ptr, local: &MeshAddr{Port: port}}
	runtime.SetFinalizer(sock, (*UDPSocket).Close)
	return sock, nil
}

// Close asks the engine to stop, waits for it to do so, and frees the node.
// Every [TCPStream], [TCPListener], and [UDPSocket] derived from this node
// must already be closed — see crates/karst-embed-capi's own free-ordering
// safety note, which this package does not (yet) enforce at the Go level.
func (n *MeshNode) Close() error {
	if n.ptr == nil {
		return nil
	}
	C.karst_embed_free(n.ptr)
	n.ptr = nil
	runtime.SetFinalizer(n, nil)
	return nil
}

// TCPStream is a TCP connection over the mesh, from [MeshNode.DialTCP] or
// [TCPListener.Accept]. It implements [net.Conn]; SetDeadline and its
// siblings return [ErrNotSupported].
type TCPStream struct {
	ptr    *C.karst_embed_tcp_stream_t
	remote *MeshAddr
}

// Read implements [net.Conn].
func (s *TCPStream) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	defer lockOSThreadForFFI()()
	n := C.karst_embed_tcp_read(s.ptr, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	switch {
	case n < 0:
		return 0, lastError()
	case n == 0:
		return 0, io.EOF
	default:
		return int(n), nil
	}
}

// Write implements [net.Conn].
func (s *TCPStream) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	defer lockOSThreadForFFI()()
	n := C.karst_embed_tcp_write(s.ptr, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n < 0 {
		return 0, lastError()
	}
	return int(n), nil
}

// Close implements [net.Conn].
func (s *TCPStream) Close() error {
	if s.ptr == nil {
		return nil
	}
	C.karst_embed_tcp_stream_free(s.ptr)
	s.ptr = nil
	runtime.SetFinalizer(s, nil)
	return nil
}

// LocalAddr implements [net.Conn]. The embedded transport does not track a
// distinct local overlay address per stream, so this returns an empty
// [MeshAddr] rather than nil — never a meaningful value to dial back to.
func (s *TCPStream) LocalAddr() net.Addr { return &MeshAddr{} }

// RemoteAddr implements [net.Conn].
func (s *TCPStream) RemoteAddr() net.Addr { return s.remote }

// SetDeadline implements [net.Conn]. Always returns [ErrNotSupported].
func (s *TCPStream) SetDeadline(time.Time) error { return ErrNotSupported }

// SetReadDeadline implements [net.Conn]. Always returns [ErrNotSupported].
func (s *TCPStream) SetReadDeadline(time.Time) error { return ErrNotSupported }

// SetWriteDeadline implements [net.Conn]. Always returns [ErrNotSupported].
func (s *TCPStream) SetWriteDeadline(time.Time) error { return ErrNotSupported }

var _ net.Conn = (*TCPStream)(nil)

// TCPListener is a TCP listener over the mesh, from [MeshNode.ListenTCP]. It
// implements [net.Listener].
type TCPListener struct {
	ptr  *C.karst_embed_tcp_listener_t
	port uint16
}

// Accept implements [net.Listener], blocking until a peer connects.
func (l *TCPListener) Accept() (net.Conn, error) {
	defer lockOSThreadForFFI()()
	var peerAddrC *C.char
	var peerPort C.uint16_t
	ptr := C.karst_embed_tcp_accept(l.ptr, &peerAddrC, &peerPort)
	if ptr == nil {
		return nil, lastError()
	}
	remote := &MeshAddr{Port: l.port}
	if peerAddrC != nil {
		remote = &MeshAddr{IPAddr: C.GoString(peerAddrC), Port: uint16(peerPort)}
		C.karst_embed_free_string(peerAddrC)
	}
	stream := &TCPStream{ptr: ptr, remote: remote}
	runtime.SetFinalizer(stream, (*TCPStream).Close)
	return stream, nil
}

// Close implements [net.Listener].
func (l *TCPListener) Close() error {
	if l.ptr == nil {
		return nil
	}
	C.karst_embed_tcp_listener_free(l.ptr)
	l.ptr = nil
	runtime.SetFinalizer(l, nil)
	return nil
}

// Addr implements [net.Listener].
func (l *TCPListener) Addr() net.Addr { return &MeshAddr{Port: l.port} }

var _ net.Listener = (*TCPListener)(nil)

// UDPSocket is a UDP socket over the mesh, from [MeshNode.BindUDP]. It
// implements [net.PacketConn]; SetDeadline and its siblings return
// [ErrNotSupported].
type UDPSocket struct {
	ptr   *C.karst_embed_udp_socket_t
	local *MeshAddr
}

// ReadFrom implements [net.PacketConn]. As with a real UDP socket, a
// datagram larger than len(p) is truncated to fit — the excess bytes are
// discarded, not an error.
func (s *UDPSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	defer lockOSThreadForFFI()()
	var outBuf *C.uint8_t
	var outLen C.size_t
	var outAddrC *C.char
	var outPort C.uint16_t
	if C.karst_embed_udp_recv_from(s.ptr, &outBuf, &outLen, &outAddrC, &outPort) != 0 {
		return 0, nil, lastError()
	}
	defer C.karst_embed_free_bytes(outBuf, outLen)
	n := copy(p, C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen)))
	addr := &MeshAddr{Port: uint16(outPort)}
	if outAddrC != nil {
		addr.IPAddr = C.GoString(outAddrC)
		C.karst_embed_free_string(outAddrC)
	}
	return n, addr, nil
}

// WriteTo implements [net.PacketConn]. addr must be a [*MeshAddr].
func (s *UDPSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	meshAddr, ok := addr.(*MeshAddr)
	if !ok {
		return 0, fmt.Errorf("karst: WriteTo needs a *MeshAddr, got %T", addr)
	}
	defer lockOSThreadForFFI()()
	cAddress := C.CString(meshAddr.IPAddr)
	defer C.free(unsafe.Pointer(cAddress))
	var dataPtr *C.uint8_t
	if len(p) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&p[0]))
	}
	if C.karst_embed_udp_send_to(s.ptr, dataPtr, C.size_t(len(p)), cAddress, C.uint16_t(meshAddr.Port)) != 0 {
		return 0, lastError()
	}
	return len(p), nil
}

// Close implements [net.PacketConn].
func (s *UDPSocket) Close() error {
	if s.ptr == nil {
		return nil
	}
	C.karst_embed_udp_socket_free(s.ptr)
	s.ptr = nil
	runtime.SetFinalizer(s, nil)
	return nil
}

// LocalAddr implements [net.PacketConn].
func (s *UDPSocket) LocalAddr() net.Addr { return s.local }

// SetDeadline implements [net.PacketConn]. Always returns [ErrNotSupported].
func (s *UDPSocket) SetDeadline(time.Time) error { return ErrNotSupported }

// SetReadDeadline implements [net.PacketConn]. Always returns [ErrNotSupported].
func (s *UDPSocket) SetReadDeadline(time.Time) error { return ErrNotSupported }

// SetWriteDeadline implements [net.PacketConn]. Always returns [ErrNotSupported].
func (s *UDPSocket) SetWriteDeadline(time.Time) error { return ErrNotSupported }

var _ net.PacketConn = (*UDPSocket)(nil)
