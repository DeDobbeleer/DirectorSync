import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from directorsync_v3.core.director_client import DirectorClient
from directorsync_v3.core.inventories import HttpInventories, InventoryError  # to be implemented


class _InvHandler(BaseHTTPRequestHandler):
    calls = {"nodes": 0, "policies": 0}
    mode = {
        # for error test: nodes -> first 500 then 200
        "nodes_fail_then_ok": False,
    }

    protocol_version = "HTTP/1.1"

    def _send_json(self, status, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/nodes":
            _InvHandler.calls["nodes"] += 1
            if _InvHandler.mode["nodes_fail_then_ok"] and _InvHandler.calls["nodes"] == 1:
                self._send_json(500, {"error": "boom"})
                return
            self._send_json(
                200,
                {
                    "items": [
                        {"id": "N1", "name": "ALPHA"},
                        {"id": "N2", "name": "BETA"},
                    ]
                },
            )
        elif path == "/policies":
            _InvHandler.calls["policies"] += 1
            # default OK
            self._send_json(
                200,
                {
                    "items": [
                        {"id": "P1", "name": "a"},
                        {"id": "P2", "name": "b"},
                        {"id": "P3", "name": "c"},
                    ]
                },
            )
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        return


@pytest.fixture()
def inv_server():
    _InvHandler.calls = {"nodes": 0, "policies": 0}
    _InvHandler.mode["nodes_fail_then_ok"] = False
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _InvHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base_url = f"http://{srv.server_address[0]}:{srv.server_address[1]}"
    try:
        yield srv, base_url
    finally:
        srv.shutdown()
        t.join(timeout=1.0)


def test_http_inventories_fetch_once_and_cache(inv_server):
    srv, base_url = inv_server
    client = DirectorClient(base_url, token="TEST", retries=1, timeout_sec=2)
    inventories = HttpInventories(client=client)

    # First fetch populates cache
    nodes_1 = inventories("nodes")
    pols_1 = inventories("policies")

    # Second fetch should hit cache (no extra HTTP call)
    nodes_2 = inventories("nodes")
    pols_2 = inventories("policies")

    assert _InvHandler.calls["nodes"] == 1
    assert _InvHandler.calls["policies"] == 1

    # Content identical
    assert nodes_1 == nodes_2 == [{"id": "N1", "name": "ALPHA"}, {"id": "N2", "name": "BETA"}]
    assert pols_1 == pols_2 and len(pols_1) == 3


def test_http_inventories_error_propagates(inv_server, caplog):
    srv, base_url = inv_server
    _InvHandler.mode["nodes_fail_then_ok"] = True

    client = DirectorClient(base_url, token="TEST", retries=1, timeout_sec=2)
    inventories = HttpInventories(client=client)

    # nodes: 500 then 200 (DirectorClient retries once) -> OK
    nodes = inventories("nodes")
    assert _InvHandler.calls["nodes"] == 2
    assert nodes and nodes[0]["id"] == "N1"

    # policies: force 404 (simulate by pointing to unknown path via override)
    inventories.endpoints["policies"] = "/no_such_inventory"

    with pytest.raises(InventoryError):
        inventories("policies")

    # We expect at least one WARNING in logs mentioning inventory name
    assert any("policies" in r.message for r in caplog.records if r.levelname in ("WARNING", "ERROR"))
