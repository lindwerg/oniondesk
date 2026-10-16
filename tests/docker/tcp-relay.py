"""Ephemeral container-local port-80 relay for browser-origin fidelity."""
import select
import socket
import socketserver


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.create_connection(('127.0.0.1', 18080), timeout=10) as upstream:
            peers = [self.request, upstream]
            while True:
                ready, _, _ = select.select(peers, [], [], 30)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.request else self.request).sendall(data)


with socketserver.ThreadingTCPServer(('127.0.0.1', 80), Relay) as server:
    server.daemon_threads = True
    server.serve_forever()
