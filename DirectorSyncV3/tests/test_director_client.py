import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from directorsync_v3.core.director_client import DirectorClient, HttpError


class _Handler(BaseHTTPRequestHandler):
    # class-level counters so tests can assert retries/calls
    calls = {
        "ok": 0,
        "echo": 0,
        "flaky": 0,
        "bad": 0,
        "slow": 0,
        "put": 0,
    }

    protocol_version = "HTTP/1.1"

    def _auth_ok(self) -> bool:
        auth = self.headers.get("Authorization", "")
        return auth.strip() == "Bearer TEST"

    def _send_json(self, status: int, obj) -> None:
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if not self._auth_ok():
            self._send_json(401, {"error": "unauthorized"})
            return

        if path == "/ok":
            _Handler.calls["ok"] += 1
            self._send_json(200, {"ok": True})
        elif path == "/flaky":
            _Handler.calls["flaky"] += 1
            # first 2 attempts 500, then 200
            if _Handler.calls["flaky"] < 3:
                self._send_json(500, {"error": "transient"})
            else:
                self._send_json(200, {"ok": "finally"})
        elif path == "/bad":
            _Handler.calls["bad"] += 1
            self._send_json(400, {"error": "bad request"})
        elif path == "/slow":
            _Handler.calls["slow"] += 1
            time.sleep(0.2)  # longer than client timeout in test
            self._send_json(200, {"ok": True})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        if not self._auth_ok():
            self._send_json(401, {"error": "unauthorized"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            data = {"_raw": body.decode("utf-8")}

        if path == "/echo":
            _Handler.calls["echo"] += 1
            data["method"] = "POST"
            self._send_json(200, data)
        else:
            self._send_json(404, {"error": "not found"})

    def do_PUT(self):  # noqa: N802
        path = urlparse(self.path).path
        if not self._auth_ok():
            self._send_json(401, {"error": "unauthorized"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length) if length else b"{}"

        if path == "/put":
            _Handler.calls["put"] += 1
            self._send_json(200, {"updated": True})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):  # silence server logs during tests
        return


@pytest.fixture()
def http_server(tmp_path):
    # Bind to an ephemeral port
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://{host}:{port}"
    yield base_url
    server.shutdown()
    thread.join(timeout=1.0)


def test_get_ok(http_server):
    client = DirectorClient(http_server, token="TEST", timeout_sec=2, retries=1)
    data = client.get_json("/ok")
    assert data["ok"] is True
    assert _Handler.calls["ok"] >= 1


def test_post_and_put(http_server):
    client = DirectorClient(http_server, token="TEST", timeout_sec=2, retries=1)
    out = client.post_json("/echo", {"a": 1})
    assert out["method"] == "POST" and out["a"] == 1

    out2 = client.put_json("/put", {"x": 2})
    assert out2["updated"] is True
    assert _Handler.calls["put"] >= 1


def test_retry_on_5xx_then_success(http_server):
    # First 2 calls -> 500, third -> 200
    client = DirectorClient(http_server, token="TEST", timeout_sec=2, retries=3, backoff_base_sec=0.01)
    data = client.get_json("/flaky")
    assert data["ok"] == "finally"
    assert _Handler.calls["flaky"] == 3  # 2 failures + 1 success


def test_no_retry_on_4xx(http_server):
    client = DirectorClient(http_server, token="TEST", timeout_sec=2, retries=3, backoff_base_sec=0.01)
    with pytest.raises(HttpError) as ei:
        client.get_json("/bad")
    err = ei.value
    assert err.status == 400
    # should be exactly one call
    assert _Handler.calls["bad"] == 1


def test_timeout_and_retries(http_server):
    client = DirectorClient(http_server, token="TEST", timeout_sec=0.05, retries=2, backoff_base_sec=0.01)
    with pytest.raises(HttpError) as ei:
        client.get_json("/slow")
    err = ei.value
    # status 0 for network/timeout (URLError)
    assert err.status == 0
    # 1 + 2 retries = 3 total
    assert _Handler.calls["slow"] >= 3
