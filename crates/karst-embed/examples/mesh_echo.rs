// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! A minimal, runnable demonstration of embedding a mesh node — GitHub
//! issue #214's own acceptance criterion: "a minimal Rust example binary
//! that links the library and becomes a reachable mesh peer with no
//! `karstd` process running alongside it."
//!
//! Meant to be run by hand against a real deployed `karst-control`, from an
//! administrator-issued invitation — see `crates/karst-embed/README.md` for
//! the full walkthrough this mirrors. Not wired into CI: the automated,
//! no-real-infrastructure-needed proof is `tests/two_nodes.rs`, which runs a
//! real (test) control server itself; this example is for a human holding a
//! real invitation against a real deployment.
//!
//! ```text
//! # One-time, per device:
//! cargo run --example mesh_echo -- enroll <invitation> <config.toml> <state-dir>
//!
//! # Then, on one host:
//! cargo run --example mesh_echo -- listen <config.toml> <control.sock> <port>
//!
//! # And on another (or another port on the same host):
//! cargo run --example mesh_echo -- connect <config.toml> <control.sock> <overlay-address> <port> <message>
//!
//! # Either way, at any time:
//! cargo run --example mesh_echo -- status <config.toml> <control.sock>
//! ```

use std::io::{Read as _, Write as _};
use std::net::IpAddr;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: mesh_echo enroll <invitation> <config> <state-dir>\n   or: mesh_echo listen <config> <socket> <port>\n   or: mesh_echo connect <config> <socket> <address> <port> <message>\n   or: mesh_echo status <config> <socket>";
    let Some(command) = args.get(1) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };

    let rest = args.get(2..).unwrap_or_default();
    let result = match command.as_str() {
        "enroll" => enroll(rest),
        "listen" => listen(rest),
        "connect" => connect(rest),
        "status" => status(rest),
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };

    if let Err(error) = result {
        eprintln!("mesh_echo: {error}");
        std::process::exit(1);
    }
}

fn enroll(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::fmt::Write as _;
    let [invitation, config, state] = args else {
        return Err("enroll needs <invitation> <config> <state-dir>".into());
    };
    let config_path = Path::new(config);
    let state_dir = Path::new(state);
    karst_embed::enroll(invitation, config_path, state_dir)?;

    // See crates/karst-embed/README.md step 3: `enroll_invitation` writes a
    // Tun-mode config with no attachment and the system-wide exit-route
    // path, none of which an embedding caller wants. This rewrite is not
    // optional ceremony — `MeshNode::start` refuses anything but
    // `network_mode = "userspace"`, and `validate_userspace`/the exit-route
    // default would otherwise fail startup, exactly as the README explains.
    let mut text = std::fs::read_to_string(config_path)?;
    text = text.replacen("[node]\n", "[node]\nnetwork_mode = \"userspace\"\n", 1);
    let _ = writeln!(
        text,
        "exit_node_state_file = \"{}\"",
        state_dir.join("exit-route").display()
    );
    text.push_str("\n[[node.userspace_publish]]\nport = 65535\nto = \"127.0.0.1:1\"\n");
    std::fs::write(config_path, text)?;

    println!("enrolled; config written to {}", config_path.display());
    Ok(())
}

fn start(config: &str, socket: &str) -> Result<karst_embed::MeshNode, Box<dyn std::error::Error>> {
    let node = karst_embed::MeshNode::start(Path::new(config), Path::new(socket))?;
    eprintln!("mesh_echo: started; status: {}", node.status_json()?);
    Ok(node)
}

fn listen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [config, socket, port] = args else {
        return Err("listen needs <config> <socket> <port>".into());
    };
    let node = start(config, socket)?;
    let port: u16 = port.parse()?;
    let mut listener = node.listen_tcp(port)?;
    println!("listening on overlay port {port}; waiting for a peer...");
    loop {
        let (mut stream, peer) = listener.accept()?;
        println!("accepted a connection from {peer}");
        let mut buf = [0_u8; 4096];
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                println!("{peer} closed the connection");
                break;
            }
            let Some(received) = buf.get(..n) else {
                break;
            };
            print!("{}", String::from_utf8_lossy(received));
            stream.write_all(received)?; // echo it back
        }
    }
}

fn connect(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [config, socket, address, port, message] = args else {
        return Err("connect needs <config> <socket> <address> <port> <message>".into());
    };
    let node = start(config, socket)?;
    let address: IpAddr = address.parse()?;
    let port: u16 = port.parse()?;
    let mut stream = node.connect_tcp(address, port)?;
    stream.write_all(message.as_bytes())?;
    let mut reply = vec![0_u8; message.len()];
    stream.read_exact(&mut reply)?;
    println!("echoed back: {}", String::from_utf8_lossy(&reply));
    Ok(())
}

fn status(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [config, socket] = args else {
        return Err("status needs <config> <socket>".into());
    };
    let node = start(config, socket)?;
    println!("{}", node.status_json()?);
    Ok(())
}
