"""CI-only WebSocket handshake fixture for the nginx transport boundary."""

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "BTJ2.abc." + "A" * 43


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        valid = (
            self.path in ("/ws/battles/pep/1/battle-1", "/ws/battles/pep/1/battle-1?lastSeenEventSeq=19")
            and self.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in self.headers.get("Connection", "").lower()
            and self.headers.get("Origin") == "https://game.example"
            and self.headers.get("Sec-WebSocket-Protocol") == f"battle.v1, {TOKEN}"
            and self.headers.get("Authorization") is None
            and self.headers.get("Proxy-Authorization") is None
            and self.headers.get("Cookie") is None
        )
        if not valid:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.send_header("Sec-WebSocket-Protocol", "battle.v1")
        self.end_headers()
        self.close_connection = True


ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
