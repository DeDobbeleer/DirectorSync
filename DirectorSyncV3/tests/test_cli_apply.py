import csv
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from directorsync_v3.cli import main
from directorsync_v3.core.profiles import ProfileLoader


class _Srv(BaseHTTPRequestHandler):
    calls = {"list": 0, "create": 0, "update": 0}
    state = [
        {"id": 2, "name": "Beta", "items": ["a", "c"], "node_id": "N2"},   # -> UPDATED
        {"id": 3, "name": "Gamma", "items": ["c", "d"], "node_id": "N2"},  # -> UNCHANGED
    ]

    protocol_version = "HTTP/1.1"

    def _send_json(self, status, obj):
        raw = (str(obj) if isinstance(obj, str) else __import__("json").dumps(obj)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/list":
            _Srv.calls["list"] += 1
            self._send_json(200, {"items": _Srv.state})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        if path.startswith("/create/"):
            _Srv.calls["create"] += 1
            self._send_json(200, {"id": 99})
        else:
            self._send_json(404, {"error": "not found"})

    def do_PUT(self):  # noqa: N802
        path = urlparse(self.path).path
        if path.startswith("/update/"):
            _Srv.calls["update"] += 1
            self._send_json(200, {"updated": True})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        return


def _server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Srv)
    return srv, f"http://{srv.server_address[0]}:{srv.server_address[1]}"


def _write_profile(tmp_path):
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
payload:
  name: "${name}"
  items: "${items}"
  node_id: "${node_id}"
""",
        encoding="utf-8",
    )
    return base


def _write_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Name", "A", "B", "NodeId"])
        w.writeheader()
        w.writerows(rows)


def test_cli_dry_run(tmp_path, capsys, monkeypatch):
    base = _write_profile(tmp_path)
    data = tmp_path / "rows.csv"
    _write_csv(
        data,
        [
            {"Name": "Alpha", "A": "x;y", "B": "y", "NodeId": "N1"},  # CREATED
            {"Name": "   ", "A": "", "B": "", "NodeId": "N9"},       # SKIP
        ],
    )

    code = main(
        [
            "apply",
            "--profile",
            "repos",
            "--rows",
            str(data),
            "--search-path",
            str(base),
            "--dry-run",
        ]
    )
    out = capsys.readouterr().out.strip()
    assert code == 0
    # CREATED=1, UPDATED=0, UNCHANGED=0, SKIP=1
    assert "CREATED=1" in out and "SKIP=1" in out


def test_cli_apply_with_http(tmp_path, capsys):
    # Server
    srv, base_url = _server()
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()

    try:
        base = _write_profile(tmp_path)
        data = tmp_path / "rows.csv"
        _write_csv(
            data,
            [
                {"Name": "Alpha", "A": "x;y", "B": "y", "NodeId": "N1"},  # CREATED -> POST /create/N1
                {"Name": "Beta", "A": "b;a", "B": "", "NodeId": "N2"},    # UPDATED -> PUT /update/2
                {"Name": "Gamma", "A": "c;d", "B": "d", "NodeId": "N2"},  # UNCHANGED
            ],
        )

        code = main(
            [
                "apply",
                "--profile",
                "repos",
                "--rows",
                str(data),
                "--search-path",
                str(base),
                "--base-url",
                base_url,
                "--token",
                "TEST",
            ]
        )
        out = capsys.readouterr().out.strip()
        assert code == 0
        # Exactly 1 created, 1 updated, 1 unchanged
        assert "CREATED=1" in out and "UPDATED=1" in out and "UNCHANGED=1" in out
        # Server calls prove we hit the right endpoints
        assert _Srv.calls["list"] == 1
        assert _Srv.calls["create"] == 1
        assert _Srv.calls["update"] == 1
    finally:
        srv.shutdown()
        th.join(timeout=1.0)
