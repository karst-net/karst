// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Command karst-testserver runs KarstControlService on a real socket for
// cross-implementation testing.
//
// The vectors in spec/vectors/ prove the Go and Rust implementations agree on
// every derivation and framing function. They cannot prove the two ends
// actually talk: that needs sockets, HTTP/2, protobuf on the wire, and a real
// ML-KEM handshake between two processes in two languages.
//
// This binary is what `crates/karst-control-client/tests/interop.rs` spawns.
// It prints its listen address and the pins a node needs, as JSON on stdout,
// then serves until killed.
//
// It is a test fixture and says so: the account manager is a stub, because
// what is under test is the channel and the wire format, not the business
// layer that already has its own tests.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/management/internals/karst/channel"
	"github.com/netbirdio/netbird/management/internals/karst/control"
	"github.com/netbirdio/netbird/management/internals/karst/identity"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type pins struct {
	Address   string `json:"address"`
	StaticKEM string `json:"static_kem"`
	VerifyKey string `json:"verify_key"`
}

func main() {
	log.SetLevel(log.ErrorLevel)

	static, err := channel.GenerateStatic()
	if err != nil {
		fail("static key: %v", err)
	}
	srvKey, err := identity.Generate()
	if err != nil {
		fail("server identity: %v", err)
	}

	// Two modes. The default is an echo handler, which is what the channel
	// tests need: it proves a payload survived the record layer in both
	// directions without a business layer in the way.
	//
	// `--netmap N` runs the *real* login and netmap handlers over an in-memory
	// account, preloaded with N peers. That is what the node-side test drives,
	// and it exercises production code all the way down — the node store, the
	// PSK deriver, the ACL compiler, the netmap assembly and the version hash.
	var handler control.Handler
	lookup := func([]byte) []byte { return nil }

	var netmapRouter *router
	if n, ok := netmapMode(); ok {
		r, err := buildNetmapServer(n, dnsZone())
		if err != nil {
			fail("netmap fixture: %v", err)
		}
		handler = r
		netmapRouter = r
		// Real identity lookup, so a returning node is recognized by its handle
		// rather than having to present its key again.
		lookup = r.nodes.LookupFunc()
	} else {
		handler = control.HandlerFunc(func(_ context.Context, _, id, payload []byte) ([]byte, error) {
			// Include the authenticated identity so the test can check the
			// server really authenticated the node rather than echoing blindly.
			out := append([]byte("echo:"), payload...)
			out = append(out, byte(len(id)))
			return out, nil
		})
	}

	svc := control.New(static, identity.ControlSigner{Key: srvKey},
		lookup, identity.ControlVerifier{}, handler)

	lis, err := net.Listen("tcp", listenAddr())
	if err != nil {
		fail("listen: %v", err)
	}

	out, err := json.Marshal(pins{
		Address:   lis.Addr().String(),
		StaticKEM: hex.EncodeToString(svc.Pins().StaticKEM),
		VerifyKey: hex.EncodeToString(svc.Pins().VerifyKey),
	})
	if err != nil {
		fail("marshal pins: %v", err)
	}
	fmt.Println(string(out))
	// The Rust side blocks on this line, so it must not sit in a buffer.
	_ = os.Stdout.Sync()

	// An out-of-band way to change the account while nodes are connected.
	//
	// The end-to-end deprovisioning check needs to revoke a device *during* a
	// live session and time how long the other node keeps talking to it. There
	// is no other way in: the control channel only carries node-initiated
	// requests, and this fixture stands in for the account manager a console
	// would otherwise drive.
	if addr := controlAddr(); addr != "" && netmapRouter != nil {
		go serveControl(addr, netmapRouter)
	}

	srv := grpc.NewServer()
	proto.RegisterKarstControlServiceServer(srv, svc)
	if err := srv.Serve(lis); err != nil {
		fail("serve: %v", err)
	}
}

// controlAddr reads `--control ADDR`. Empty means no control surface, which is
// what every test but the deprovisioning one wants.
func controlAddr() string {
	args := os.Args[1:]
	for i, a := range args {
		if a == "--control" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// serveControl exposes the one operation the fixture needs driven from
// outside: remove a peer from the account.
//
//	GET  /peers                    -> [{handle, label, ip}, ...]
//	POST /remove?handle=<handle>   -> 200 removed / 404 no such peer
func serveControl(addr string, r *router) {
	mux := http.NewServeMux()
	mux.HandleFunc("/peers", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(r.account.list())
	})
	mux.HandleFunc("/remove", func(w http.ResponseWriter, req *http.Request) {
		handle := req.URL.Query().Get("handle")
		if handle == "" {
			http.Error(w, "handle is required", http.StatusBadRequest)
			return
		}
		if !r.account.remove(handle) {
			http.Error(w, "no such peer", http.StatusNotFound)
			return
		}
		fmt.Fprintln(w, "removed")
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		fail("control surface: %v", err)
	}
}

// netmapMode reads `--netmap N` from the command line.
// listenAddr is where the fixture serves.
//
// Loopback by default, because the interop tests run it in the same namespace
// they connect from and a fixture that listened on every interface by default
// would be a surprise on a developer's machine. `--listen` widens it for the
// end-to-end test, whose nodes live in a different network namespace and
// cannot reach 127.0.0.1 here.
func listenAddr() string {
	args := os.Args[1:]
	for i, a := range args {
		if a == "--listen" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return "127.0.0.1:0"
}

// bedrockMode reads `--bedrock N[:mode][:self]`: seed a chain, countersign the
// first N preloaded peers, advertise `mode` (off, advisory, or enforcing), and
// countersign the enrolling node unless `self` is given as `nocover`.
//
// Absent means no Bedrock log at all, which is the common production state and
// the one every pre-existing test expects.
func bedrockMode() (int, proto.KarstBedrockMode, bool, bool) {
	args := os.Args[1:]
	for i, a := range args {
		if a != "--bedrock" || i+1 >= len(args) {
			continue
		}
		spec := args[i+1]
		mode := proto.KarstBedrockMode_KARST_BEDROCK_MODE_OFF
		coverEnrolling := true
		if name, rest, found := strings.Cut(spec, ":"); found {
			spec = name
			if m, tail, more := strings.Cut(rest, ":"); more {
				rest = m
				if tail == "nocover" {
					coverEnrolling = false
				}
			}
			switch rest {
			case "advisory":
				mode = proto.KarstBedrockMode_KARST_BEDROCK_MODE_ADVISORY
			case "enforcing":
				mode = proto.KarstBedrockMode_KARST_BEDROCK_MODE_ENFORCING
			case "off":
			default:
				fail("--bedrock mode must be off, advisory or enforcing")
			}
		}
		n, err := strconv.Atoi(spec)
		if err != nil {
			fail("--bedrock needs a covered-peer count: %v", err)
		}
		return n, mode, coverEnrolling, true
	}
	return 0, proto.KarstBedrockMode_KARST_BEDROCK_MODE_OFF, true, false
}

// dnsZone reads `--dns-zone ZONE` from the command line. Empty (the default)
// keeps MagicDNS off, which every fixture except the KarstDNS end-to-end row
// depends on: a non-empty zone turns on the node's `host_integration = "auto"`
// default, and `resolvconf` mode edits `/etc/resolv.conf` directly, with no
// regard for network namespaces. Turning that on for every row would risk the
// runner's own resolver, not just the fixture's.
func dnsZone() string {
	args := os.Args[1:]
	for i, a := range args {
		if a == "--dns-zone" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func netmapMode() (int, bool) {
	args := os.Args[1:]
	for i, a := range args {
		if a != "--netmap" {
			continue
		}
		if i+1 >= len(args) {
			return 0, true
		}
		n, err := strconv.Atoi(args[i+1])
		if err != nil {
			fail("--netmap needs a peer count: %v", err)
		}
		return n, true
	}
	return 0, false
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
