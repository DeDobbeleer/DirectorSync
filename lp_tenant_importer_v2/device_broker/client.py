"""Director API client using only Python standard library (urllib)."""

import json
import ssl
import time
import urllib.error
import urllib.request


class APIError(Exception):
    """Raised when the Director API returns an error or a network failure occurs."""


class DirectorAPIClient:
    """Low-level HTTP client for the Guardsix Fleet Config API."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_url(self, path: str) -> str:
        """Return a full URL, handling absolute monitor URLs gracefully."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        path = path.lstrip("/")
        return f"{self.base_url}/{path}"

    def _request(
        self,
        method: str,
        path: str,
        data: dict | None = None,
        retries: int = 3,
    ) -> dict | None:
        """Execute an HTTP request with retries and raise APIError on failure."""
        url = self._build_url(path)
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(
            url, data=body, headers=headers, method=method
        )

        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                with urllib.request.urlopen(
                    req, timeout=self.timeout, context=ctx
                ) as resp:
                    if resp.status == 204:
                        return {}
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                body_text = ""
                if exc.fp is not None:
                    try:
                        body_text = exc.read().decode("utf-8")[:500]
                    except Exception:
                        pass
                last_exc = APIError(
                    f"HTTP {exc.code} on {method} {url}: {body_text}"
                )
                if 400 <= exc.code < 500 and exc.code not in (408, 429):
                    raise last_exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_exc = APIError(f"Network error on {method} {url}: {exc}")
                time.sleep(attempt * 2)

        raise last_exc

    @staticmethod
    def _extract_job_id(response: dict | None) -> str | None:
        """Extract a job identifier from an async API response."""
        if not isinstance(response, dict):
            return None
        return (
            response.get("job_id")
            or response.get("jobId")
            or response.get("id")
        )

    @staticmethod
    def _extract_monitor_path(response: dict | None) -> str | None:
        """Extract a monitor URL/path from an async API response."""
        if not isinstance(response, dict):
            return None
        return (
            response.get("monitor")
            or response.get("monitor_url")
            or response.get("monitorPath")
        )

    # ------------------------------------------------------------------
    # Public HTTP methods
    # ------------------------------------------------------------------

    def get_json(self, path: str) -> dict | list | None:
        """Execute a GET request and return the parsed JSON body."""
        return self._request("GET", path)

    def delete_json(self, path: str) -> dict | None:
        """Execute a DELETE request and return the parsed JSON body."""
        return self._request("DELETE", path)

    def put_json(self, path: str, payload: dict) -> dict | None:
        """Execute a PUT request with a JSON body."""
        return self._request("PUT", path, payload)

    # ------------------------------------------------------------------
    # Async monitoring
    # ------------------------------------------------------------------

    def monitor_job(
        self,
        pool_uuid: str,
        node_id: str,
        job_id: str,
        *,
        timeout_sec: int = 120,
        poll_interval: int = 2,
    ) -> tuple[bool, dict, str | None]:
        """Poll the Director monitor API until a job completes or times out.

        Returns a tuple of (success, raw_response, reason_or_none).
        """
        path = f"monitorapi/{pool_uuid}/{node_id}/orders/{job_id}"
        deadline = time.time() + timeout_sec

        while time.time() < deadline:
            data = self.get_json(path) or {}
            resp = data.get("response") if isinstance(data, dict) else None
            if isinstance(resp, dict):
                success = resp.get("success")
                errors = resp.get("errors", [])
                if success is True:
                    return True, data, None
                if success is False or errors:
                    reason = "; ".join(str(e) for e in errors) if errors else "job failed"
                    return False, data, reason

            status = str(data.get("status", "")).lower()
            if status in {"completed", "success", "ok"}:
                return True, data, None
            if status in {"failed", "error"}:
                return False, data, f"status={status}"

            time.sleep(poll_interval)

        return False, {}, "monitoring timeout"

    def monitor_job_url(
        self,
        monitor_path: str,
        *,
        timeout_sec: int = 120,
        poll_interval: int = 2,
    ) -> tuple[bool, dict, str | None]:
        """Poll an absolute or relative monitor URL until completion.

        Returns a tuple of (success, raw_response, reason_or_none).
        """
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            data = self.get_json(monitor_path) or {}
            resp = data.get("response") if isinstance(data, dict) else None
            if isinstance(resp, dict):
                success = resp.get("success")
                errors = resp.get("errors", [])
                if success is True:
                    return True, data, None
                if success is False or errors:
                    reason = "; ".join(str(e) for e in errors) if errors else "job failed"
                    return False, data, reason

            status = str(data.get("status", "")).lower()
            if status in {"completed", "success", "ok"}:
                return True, data, None
            if status in {"failed", "error"}:
                return False, data, f"status={status}"

            time.sleep(poll_interval)

        return False, {}, "monitoring timeout"
