"""Ground truth for the loopback cases: does a real client reach a real server?

Two clients are used because they read URLs differently: Python's urllib hands
the host to the OS resolver, and curl parses legacy IPv4 spellings itself.
"""

from __future__ import annotations

import http.client
import http.server
import shutil
import subprocess
import threading
import urllib.request

MARKER = b"fetch-url-gate-live"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(MARKER)))
        self.end_headers()
        self.wfile.write(MARKER)

    def log_message(self, *args):
        pass


class LocalServer:
    """An HTTP server bound to 127.0.0.1 on a free port."""

    def __enter__(self):
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()


def reaches_urllib(url: str, timeout: float = 2.0) -> bool:
    """True if urllib, with proxies off, gets the server's marker from this URL."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as response:
            return response.read(len(MARKER)) == MARKER
    except (OSError, ValueError, http.client.HTTPException):
        return False


def reaches_curl(url: str, timeout: float = 2.0) -> bool:
    """True if curl, with proxies off and globbing off, gets the server's marker."""
    command = ["curl", "--silent", "--noproxy", "*", "--globoff", "--max-time", str(int(timeout)), url]
    try:
        done = subprocess.run(command, capture_output=True, timeout=timeout + 3, check=False)
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return done.returncode == 0 and done.stdout == MARKER


def clients() -> dict:
    found = {"urllib": reaches_urllib}
    if shutil.which("curl"):
        found["curl"] = reaches_curl
    return found
