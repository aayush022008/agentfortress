"""
Decoy endpoints — fake API endpoints that log when agents call them.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer


@dataclass
class DecoyHit:
    """A recorded hit on a decoy endpoint."""

    hit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    endpoint: str = ""
    method: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    source_ip: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hit_id": self.hit_id,
            "endpoint": self.endpoint,
            "method": self.method,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
        }


class DecoyEndpointServer:
    """
    Runs a lightweight HTTP server on localhost with fake API endpoints.
    Any request to the server is logged as a DecoyHit and triggers callbacks.

    Usage::

        server = DecoyEndpointServer(port=18080)
        server.on_hit(lambda hit: alert(f"Agent called decoy: {hit.endpoint}"))
        server.start()

        # Inject URL into agent context
        print(server.decoy_url("/v1/internal/user-data"))

        # Later
        server.stop()
        hits = server.hits
    """

    def __init__(self, port: int = 18080, host: str = "127.0.0.1") -> None:
        self.port = port
        self.host = host
        self.hits: List[DecoyHit] = []
        self._callbacks: List[Callable[[DecoyHit], None]] = []
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[Thread] = None

    def on_hit(self, callback: Callable[[DecoyHit], None]) -> None:
        """Register callback invoked when any request hits the decoy server."""
        self._callbacks.append(callback)

    def decoy_url(self, path: str = "/api/v1/secrets") -> str:
        """Return the full URL for a decoy endpoint path."""
        return f"http://{self.host}:{self.port}{path}"

    def start(self) -> None:
        """Start the decoy server in a background thread."""
        server_instance = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._handle()

            def do_POST(self) -> None:
                self._handle()

            def do_PUT(self) -> None:
                self._handle()

            def do_DELETE(self) -> None:
                self._handle()

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode(errors="replace") if length else ""
                hit = DecoyHit(
                    endpoint=self.path,
                    method=self.command,
                    headers=dict(self.headers),
                    body=body,
                    source_ip=self.client_address[0],
                )
                server_instance.hits.append(hit)
                for cb in server_instance._callbacks:
                    try:
                        cb(hit)
                    except Exception:
                        pass

                # Return a realistic-looking response
                response = json.dumps({"error": "Unauthorized", "code": 401}).encode()
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Silence access log

        self._server = HTTPServer((self.host, self.port), Handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Shutdown the decoy server."""
        if self._server:
            self._server.shutdown()
            self._server = None

    def get_hit_count(self) -> int:
        return len(self.hits)

    def get_recent_hits(self, n: int = 10) -> List[DecoyHit]:
        return self.hits[-n:]
