import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from directorsync_v3.core.applier import CrudApplier
from directorsync_v3.core.director_client import DirectorClient
from directorsync_v3.core.profiles import ProfileLoader


class _CrudHandler(BaseHTTPRequestHandler):
    calls = {"list": 0, "create": 0, "update": 0}
    last_payloads = {"create": None, "update": None}

    # Simulated remote state (id, name, items, node_id)
    state = [
        {"id": 2, "name": "BETA",  "items": ["a", "c"], "node_id": "N2"},  # differs -> UPDATED
        {"id": 3, "name": "GAMMA", "items": ["c", "d"], "node_id": "N2"},  # same    -> UNCHANGED
    ]    

    protocol_version = "HTTP/1.1"

    def _send_json(self, status: int, obj) -> None:
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/list":
            _CrudHandler.calls["list"] += 1
            self._send_json(200, {"items": _CrudHandler.state})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        if path.startswith("/create"):
            _CrudHandler.calls["create"] += 1
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b"{}"
            _CrudHandler.last_payloads["create"] = json.loads(body.decode("utf-8"))
            # Append to state as simulation
            new_id = 10 + _CrudHandler.calls["create"]
            _CrudHandler.state.append({"id": new_id, **_CrudHandler.last_payloads["create"]})
            self._send_json(200, {"id": new_id})
        else:
            self._send_json(404, {"error": "not found"})

    def do_PUT(self):  # noqa: N802
        path = urlparse(self.path).path
        if path.startswith("/update/"):
            _CrudHandler.calls["update"] += 1
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b"{}"
            _CrudHandler.last_payloads["update"] = json.loads(body.decode("utf-8"))
            self._send_json(200, {"updated": True})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):  # silence test server logs
        return


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CrudHandler)
    return server, f"http://{server.server_address[0]}:{server.server_address[1]}"


def test_crud_applier_end_to_end(tmp_path, monkeypatch):
    # Spin up server
    server, base_url = _server()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    # Profile with endpoints & diff rules
    base = tmp_path / "resources" / "profiles"
    base.mkdir(parents=True)
    (base / "_defaults.yml").write_text(
        """
version: 1
diff:
  list_as_sets: ["items"]
  ignore_fields: ["id"]
""",
        encoding="utf-8",
    )
    (base / "repos.yml").write_text(
        """
version: 1
extends: "_defaults"
resource: "repositories"
endpoint:
  list: "/list"
  create: "/create/{node_id}"
  update: "/update/{id}"
identity:
  id_field: "id"
  name_field: "name"
  natural_key: ["name"]
xlsx:
  mapping:
    name:
      col: "Name"
      transform: ["norm_str"]
    items:
      expr: "${A};${B}"
      transform:
        - fn: "split"
          sep: ";"
        - "uniq"
    node_id:
      col: "NodeId"
prechecks:
  - { type: "non_empty", field: "name" }
hooks:
    preprocess_row: "make_upper"
payload:
  name: "${name}"
  items: "${items}"
  node_id: "${node_id}"
""",
        encoding="utf-8",
    )

    pl = ProfileLoader(search_paths=[str(base)])
    prof = pl.load("repos")

    client = DirectorClient(base_url, token="TEST", timeout_sec=2, retries=1)

    def make_upper(mapped):
        mapped = dict(mapped)
        if "name" in mapped and isinstance(mapped["name"], str):
            mapped["name"] = mapped["name"].upper()
        return mapped

    applier = CrudApplier(
        prof,
        client,
        context={"tenant": "T1", "pool_uuid": "POOL"},  # available for URL formatting if needed
        hooks={"make_upper": make_upper},
    )

    # Input rows:
    rows = [
        {"Name": "Alpha", "A": "x;y", "B": "y", "NodeId": "N1"},     # CREATED -> POST /create/N1
        {"Name": "Beta",  "A": "b;a", "B": "",  "NodeId": "N2"},     # UPDATED -> PUT /update/2
        {"Name": "Gamma", "A": "c;d", "B": "d", "NodeId": "N2"},     # UNCHANGED -> no call
        {"Name": "   ",   "A": "",    "B": "",  "NodeId": "N3"},     # SKIP -> no call
    ]

    results, counts = applier.apply(rows)

    # Summary
    assert counts["CREATED"] == 1
    assert counts["UPDATED"] == 1
    assert counts["UNCHANGED"] == 1
    assert counts["SKIP"] == 1

    # URL formatting checks
    # POST used node_id from mapped values
    assert _CrudHandler.calls["create"] == 1
    assert _CrudHandler.last_payloads["create"]["name"].upper() == "ALPHA"

    # PUT used id=2 for 'Beta'
    assert _CrudHandler.calls["update"] == 1
    # payload normalization: items derive from mapping/uniq
    assert set(_CrudHandler.last_payloads["update"]["items"]) == {"a", "b"}

    server.shutdown()
    t.join(timeout=1.0)
