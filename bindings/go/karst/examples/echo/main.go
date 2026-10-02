// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// Command echo is a minimal, runnable demonstration of embedding a mesh
// node from Go — GitHub issue #214's own acceptance criterion: "a minimal
// Go example doing the same" as crates/karst-embed/examples/mesh_echo.rs.
//
// Meant to be run by hand against a real deployed karst-control, from an
// administrator-issued invitation — see crates/karst-embed/README.md for
// the full walkthrough this mirrors, and this package's own doc comment
// (../../karst.go) for how to build and link it.
//
//	# One-time, per device:
//	go run . enroll <invitation> <config.toml> <state-dir>
//
//	# Then, on one host:
//	go run . listen <config.toml> <control.sock> <port>
//
//	# And on another (or another port on the same host):
//	go run . connect <config.toml> <control.sock> <overlay-address> <port> <message>
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/karst-net/karst/bindings/go/karst"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = enroll(os.Args[2:])
	case "listen":
		err = listenCmd(os.Args[2:])
	case "connect":
		err = connectCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "echo: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: echo enroll <invitation> <config> <state-dir>")
	fmt.Fprintln(os.Stderr, "   or: echo listen <config> <socket> <port>")
	fmt.Fprintln(os.Stderr, "   or: echo connect <config> <socket> <address> <port> <message>")
	os.Exit(2)
}

func enroll(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("enroll needs <invitation> <config> <state-dir>")
	}
	invitation, configPath, stateDir := args[0], args[1], args[2]
	if err := karst.Enroll(invitation, configPath, stateDir); err != nil {
		return err
	}

	// See crates/karst-embed/README.md step 3: karst_embed::enroll writes a
	// Tun-mode config with no attachment and the system-wide exit-route
	// path, neither of which an embedding caller wants. MeshNode.Start (via
	// karst_embed::MeshNode::start) refuses anything but
	// network_mode = "userspace", and validate_userspace/the exit-route
	// default would otherwise fail startup, exactly as the README explains.
	text, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	patched := strings.Replace(string(text), "[node]\n", "[node]\nnetwork_mode = \"userspace\"\n", 1)
	patched += fmt.Sprintf("exit_node_state_file = \"%s/exit-route\"\n", stateDir)
	patched += "\n[[node.userspace_publish]]\nport = 65535\nto = \"127.0.0.1:1\"\n"
	if err := os.WriteFile(configPath, []byte(patched), 0o600); err != nil {
		return err
	}

	fmt.Printf("enrolled; config written to %s\n", configPath)
	return nil
}

func start(configPath, socketPath string) (*karst.MeshNode, error) {
	node, err := karst.Start(configPath, socketPath)
	if err != nil {
		return nil, err
	}
	status, err := node.StatusJSON()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "echo: started; status: %s\n", status)
	return node, nil
}

func listenCmd(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("listen needs <config> <socket> <port>")
	}
	node, err := start(args[0], args[1])
	if err != nil {
		return err
	}
	defer node.Close()

	port, err := strconv.ParseUint(args[2], 10, 16)
	if err != nil {
		return err
	}
	listener, err := node.ListenTCP(uint16(port))
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("listening on overlay port %d; waiting for a peer...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		fmt.Printf("accepted a connection from %s\n", conn.RemoteAddr())
		echoLoop(conn)
	}
}

func echoLoop(conn io.ReadWriteCloser) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			fmt.Print(string(buf[:n]))
			if _, werr := conn.Write(buf[:n]); werr != nil {
				fmt.Fprintf(os.Stderr, "echo: write: %v\n", werr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "echo: read: %v\n", err)
			}
			return
		}
	}
}

func connectCmd(args []string) error {
	if len(args) != 5 {
		return fmt.Errorf("connect needs <config> <socket> <address> <port> <message>")
	}
	node, err := start(args[0], args[1])
	if err != nil {
		return err
	}
	defer node.Close()

	port, err := strconv.ParseUint(args[3], 10, 16)
	if err != nil {
		return err
	}
	stream, err := node.DialTCP(args[2], uint16(port))
	if err != nil {
		return err
	}
	defer stream.Close()

	message := args[4]
	if _, err := stream.Write([]byte(message)); err != nil {
		return err
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(bufio.NewReader(stream), reply); err != nil {
		return err
	}
	fmt.Printf("echoed back: %s\n", reply)
	return nil
}
