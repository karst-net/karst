# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# The two fixtures the macOS NE harness probes: a 64 KiB HTTP body and a UDP
# echo. They listen on every address; peer-entrypoint.sh's firewall is what
# makes them reachable only through the overlay.
import http.server
import os
import socket
import socketserver
import threading

BODY = os.urandom(64 * 1024)
HTTP_PORT = 8080
UDP_PORT = 7777


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def udp_echo():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", UDP_PORT))
    while True:
        data, addr = sock.recvfrom(65535)
        sock.sendto(data, addr)


threading.Thread(target=udp_echo, daemon=True).start()
Server(("0.0.0.0", HTTP_PORT), Handler).serve_forever()
