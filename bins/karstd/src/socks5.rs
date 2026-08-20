// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The deliberately small sidecar attachment for userspace mode.
//!
//! SOCKS5 is bound only where the operator configured it. It accepts literal
//! overlay IP addresses; accepting DNS names would silently make resolution a
//! host-network operation outside the Karst policy boundary.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use karst_tun::Userspace;

use crate::run::Shutdown;

pub(crate) fn serve(stack: &Userspace, listen: SocketAddr, shutdown: &Shutdown) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    std::thread::scope(|connections| {
        while !shutdown.requested() {
            match listener.accept() {
                Ok((stream, _)) => {
                    let stack = stack.clone();
                    connections.spawn(move || {
                        let _ = proxy(stream, &stack, shutdown);
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    Ok(())
}

fn proxy(mut client: TcpStream, stack: &Userspace, shutdown: &Shutdown) -> io::Result<()> {
    let destination = negotiate(&mut client)?;
    let tunnel = stack
        .connect_tcp(destination.ip(), destination.port())
        .map_err(|e| io::Error::other(e.to_string()))?;
    while !stack.tcp_can_send(tunnel) {
        if shutdown.requested() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    client.set_nonblocking(true)?;

    let mut from_client = Vec::new();
    let mut buf = [0u8; 4096];
    while !shutdown.requested() {
        if stack.tcp_can_recv(tunnel) {
            let mut received = Vec::new();
            stack
                .tcp_recv(tunnel, &mut received)
                .map_err(|e| io::Error::other(e.to_string()))?;
            if !received.is_empty() {
                client.write_all(&received)?;
            }
        }
        match client.read(&mut buf) {
            Ok(0) => {
                stack.tcp_close(tunnel);
                return Ok(());
            }
            Ok(n) => from_client.extend_from_slice(buf.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        if !from_client.is_empty() && stack.tcp_can_send(tunnel) {
            let sent = stack
                .tcp_send(tunnel, &from_client)
                .map_err(|e| io::Error::other(e.to_string()))?;
            from_client.drain(..sent);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    stack.tcp_close(tunnel);
    Ok(())
}

fn negotiate(client: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut hello = [0u8; 2];
    client.read_exact(&mut hello)?;
    if hello[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let mut methods = vec![0; usize::from(hello[1])];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff])?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS auth required",
        ));
    }
    client.write_all(&[5, 0])?;

    let mut request = [0u8; 4];
    client.read_exact(&mut request)?;
    if request[..3] != [5, 1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only SOCKS CONNECT is supported",
        ));
    }
    let ip = match request[3] {
        1 => {
            let mut raw = [0u8; 4];
            client.read_exact(&mut raw)?;
            IpAddr::V4(Ipv4Addr::from(raw))
        }
        4 => {
            let mut raw = [0u8; 16];
            client.read_exact(&mut raw)?;
            IpAddr::V6(Ipv6Addr::from(raw))
        }
        3 => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length)?;
            let mut ignored = vec![0; usize::from(length[0])];
            client.read_exact(&mut ignored)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS domains are not supported",
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown SOCKS address type",
            ))
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}
