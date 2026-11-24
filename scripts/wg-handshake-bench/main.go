// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.
//
// WireGuard handshake CPU cost, measured the same way
// bins/karstd/tests/handshake_rate_bench.rs measures PHREATIC's: one
// responder with N pre-registered peer identities (a closed roster), N
// distinct initiator identities, timing only the responder-side
// handshake-message processing — not setup, not the initiator's own cost
// (that runs on a different machine's core in any real deployment).
//
// Uses golang.zx2c4.com/wireguard's real production device package —
// the same CreateMessageInitiation/ConsumeMessageInitiation/
// CreateMessageResponse/ConsumeMessageResponse/BeginSymmetricSession
// calls a real wireguard-go (and so Tailscale) handshake runs, per that
// module's own device/noise_test.go and device/receive.go.
//
// See ../../docs/measurements/handshake-cpu-2026-11-24.md for the
// numbers this produced and how they compare to PHREATIC's.
//
// Run:
//
//	cd scripts/wg-handshake-bench && go run .
package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

const nClients = 2000

func genKeypair() (device.NoisePrivateKey, device.NoisePublicKey) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	var sk device.NoisePrivateKey
	// FromHex both loads and clamps, exactly like the library's own
	// newPrivateKey() (unexported, so we go through the hex path instead).
	if err := sk.FromHex(fmt.Sprintf("%x", raw)); err != nil {
		panic(err)
	}
	pubRaw, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	var pk device.NoisePublicKey
	copy(pk[:], pubRaw)
	return sk, pk
}

func newDev(sk device.NoisePrivateKey) *device.Device {
	tun := tuntest.NewChannelTUN()
	logger := device.NewLogger(device.LogLevelError, "")
	d := device.NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	if err := d.SetPrivateKey(sk); err != nil {
		panic(err)
	}
	return d
}

func main() {
	fmt.Printf("Generating %d client identities...\n", nClients)
	setupStart := time.Now()

	serverSK, serverPK := genKeypair()
	server := newDev(serverSK)

	type client struct {
		dev        *device.Device
		peerServer *device.Peer // the server, as seen from the client
	}
	clients := make([]client, nClients)

	for i := 0; i < nClients; i++ {
		clientSK, clientPK := genKeypair()

		// server-side roster entry
		sp, err := server.NewPeer(clientPK)
		if err != nil {
			panic(err)
		}
		sp.Start()

		// client device + its one peer (the server)
		cdev := newDev(clientSK)
		cp, err := cdev.NewPeer(serverPK)
		if err != nil {
			panic(err)
		}
		cp.Start()

		clients[i] = client{dev: cdev, peerServer: cp}
	}
	fmt.Printf("Setup done in %.1fs (%d identities + rosters)\n", time.Since(setupStart).Seconds(), nClients)

	succeeded := 0
	var serverTime time.Duration

	for i := 0; i < nClients; i++ {
		c := clients[i]

		// client creates the initiation — not timed, runs on the client's
		// own core in any real deployment.
		msg1, err := c.dev.CreateMessageInitiation(c.peerServer)
		if err != nil {
			panic(err)
		}

		t0 := time.Now()
		serverPeer := server.ConsumeMessageInitiation(msg1)
		if serverPeer == nil {
			continue
		}
		msg2, err := server.CreateMessageResponse(serverPeer)
		if err != nil {
			continue
		}
		if err := serverPeer.BeginSymmetricSession(); err != nil {
			continue
		}
		serverTime += time.Since(t0)

		// client consumes the response — not timed, just to confirm the
		// handshake actually completed end to end.
		clientPeer := c.dev.ConsumeMessageResponse(msg2)
		if clientPeer == nil {
			continue
		}
		if err := clientPeer.BeginSymmetricSession(); err != nil {
			continue
		}
		succeeded++
	}

	rate := float64(succeeded) / serverTime.Seconds()
	fmt.Printf("\n%d/%d handshakes completed\n", succeeded, nClients)
	fmt.Printf("server-side time: %.3fs (client-side and setup excluded)\n", serverTime.Seconds())
	fmt.Printf("rate: %.0f handshakes/sec/core\n", rate)
	fmt.Printf("per-handshake server CPU: %.1f us\n", serverTime.Seconds()*1e6/float64(succeeded))
}
