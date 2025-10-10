import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from directorsync_v3.core.director_client import DirectorClient
from directorsync_v3.core.job_monitor import JobMonitor, MonitorConfig, MonitorError, MonitorTimeout


class _JobH(BaseHTTPRequestHandler):
    calls = {"job": 0}
    states = ["running", "running", "done"]  # success sequence
    fail_states = ["running", "error"]       # failure sequence
    mode = "success"  # or "fail"

    def _send_json(self, status: int, obj) -> None:
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path.startswith("/jobs/"):
            _JobH.calls["job"] += 1
            i = _JobH.calls["job"] - 1
            if _JobH.mode == "success":
                state = _JobH.states[min(i, len(_JobH.states) - 1)]
            else:
                state = _JobH.fail_states[min(i, len(_JobH.fail_states) - 1)]
            self._send_json(200, {"state": state})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        return


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JobH)
    return server, f"http://{server.server_address[0]}:{server.server_address[1]}"


def test_job_monitor_success():
    server, base = _server()
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    try:
        client = DirectorClient(base, token="TEST", timeout_sec=1, retries=1, backoff_base_sec=0.01)
        mon = JobMonitor(client, MonitorConfig(
            path="/jobs/{job_id}",
            status_field="state",
            ok_states=["done"],
            fail_states=["error"],
            interval_sec=0.01,
            timeout_sec=1.0,
        ))
        _JobH.mode = "success"
        _JobH.calls["job"] = 0
        res = mon.wait(context={"job_id": "J1"})
        assert res["state"] == "done"
        assert _JobH.calls["job"] >= 3
    finally:
        server.shutdown()
        th.join(timeout=1.0)


def test_job_monitor_fail_and_timeout():
    server, base = _server()
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    try:
        client = DirectorClient(base, token="TEST", timeout_sec=1, retries=0)
        mon = JobMonitor(client, MonitorConfig(
            path="/jobs/{job_id}",
            status_field="state",
            ok_states=["done"],
            fail_states=["error"],
            interval_sec=0.01,
            timeout_sec=0.5,
        ))
        # Failure path
        _JobH.mode = "fail"
        _JobH.calls["job"] = 0
        try:
            mon.wait(context={"job_id": "J2"})
        except MonitorError as e:
            assert "job state='error'" in str(e)

        # Timeout path
        _JobH.mode = "success"
        _JobH.calls["job"] = 0
        # Short timeout with all "running"
        _JobH.states = ["running"] * 100
        try:
            mon.wait(context={"job_id": "J3"})
        except MonitorTimeout as e:
            assert "timeout" in str(e)
    finally:
        server.shutdown()
        th.join(timeout=1.0)
