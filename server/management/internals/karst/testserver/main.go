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
	"os"
	"strconv"

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

	if n, ok := netmapMode(); ok {
		r, err := buildNetmapServer(n)
		if err != nil {
			fail("netmap fixture: %v", err)
		}
		handler = r
		// Real identity lookup, so a returning node is recognised by its handle
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

	lis, err := net.Listen("tcp", "127.0.0.1:0")
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

	srv := grpc.NewServer()
	proto.RegisterKarstControlServiceServer(srv, svc)
	if err := srv.Serve(lis); err != nil {
		fail("serve: %v", err)
	}
}

// netmapMode reads `--netmap N` from the command line.
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
