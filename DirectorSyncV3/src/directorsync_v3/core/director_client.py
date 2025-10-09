"""
Director HTTP client (Step 7).

- No external deps (urllib).
- Methods: get_json, post_json, put_json.
- Retries with exponential backoff on network errors and 5xx.
- No retry on 4xx.
- TLS verification toggle (verify_tls=True by default).
- JSON only (application/json).
- Errors as HttpError with status, url, and body.

Usage:
    client = DirectorClient(base_url, token, verify_tls=True, timeout_sec=10, retries=3)
    data = client.get_json("/api/...")
"""

from __future__ import annotations

import json
import logging
import ssl
import time
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class HttpError(Exception):
    """HTTP/transport error with context."""
    status: int
    url: str
    body: str = ""
    message: str = ""

    def __str__(self) -> str:  # pragma: no cover (simple formatting)
        base = f"HttpError(status={self.status}, url={self.url})"
        if self.message:
            base += f": {self.message}"
        if self.body:
            base += f" body={self.body[:200]}"
        return base


class DirectorClient:
    """Minimal JSON HTTP client with retries and timeouts."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        verify_tls: bool = True,
        timeout_sec: int = 30,
        retries: int = 3,
        backoff_base_sec: float = 0.05,
        logger: Optional[logging.LoggerAdapter] = None,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls
        self.timeout = float(timeout_sec)
        self.retries = max(0, int(retries))
        self.backoff = float(backoff_base_sec)
        self.log = logger or logging.getLogger("ds.http")

        # SSL context
        if self.base_url.lower().startswith("https"):
            if verify_tls:
                self._ssl_context = ssl.create_default_context()
            else:
                self._ssl_context = ssl._create_unverified_context()  # nosec - intentional opt-out
        else:
            self._ssl_context = None

    # ------------- Public API -------------

    def get_json(self, path: str) -> Dict[str, Any]:
        return self._request_json("GET", path)

    def post_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request_json("POST", path, payload)

    def put_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request_json("PUT", path, payload)

    # ------------- Internal -------------

    def _full_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request_json(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = self._full_url(path)
        data: Optional[bytes] = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "DirectorSync-v3/HTTPClient",
        }

        last_err: Optional[HttpError] = None
        attempts = self.retries + 1
        for attempt in range(attempts):
            start = time.time()
            req = urllib.request.Request(url=url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                    status = getattr(resp, "status", 200)
                    raw = resp.read() or b""
                    elapsed = (time.time() - start) * 1000
                    self._log_ok(method, path, status, elapsed)
                    if status == 204 or not raw:
                        return {}
                    try:
                        return json.loads(raw.decode("utf-8"))
                    except json.JSONDecodeError as e:  # pragma: no cover (rare)
                        raise HttpError(status=status, url=url, body=raw.decode("utf-8"), message=str(e))
            except urllib.error.HTTPError as e:
                body = (e.read() or b"").decode("utf-8", errors="replace")
                status = int(e.code)
                err = HttpError(status=status, url=url, body=body, message=str(e))
                self._log_err(method, path, status, err)
                # Retry only on 5xx
                if 500 <= status < 600 and attempt < attempts - 1:
                    self._sleep_backoff(attempt)
                    last_err = err
                    continue
                raise err
            except urllib.error.URLError as e:
                # Network/timeout. Treat as retryable if attempts remain.
                err = HttpError(status=0, url=url, message=str(e))
                self._log_err(method, path, 0, err)
                if attempt < attempts - 1:
                    self._sleep_backoff(attempt)
                    last_err = err
                    continue
                raise err
            except socket.timeout as e:
                # Read/connect timeout not wrapped by urllib on some platforms
                err = HttpError(status=0, url=url, message="timed out")
                self._log_err(method, path, 0, err)
                if attempt < attempts - 1:
                    self._sleep_backoff(attempt)
                    last_err = err
                    continue
                raise err            
            except Exception as e:  # pragma: no cover (unexpected)
                err = HttpError(status=0, url=url, message=str(e))
                self._log_err(method, path, 0, err)
                raise err
        # Should not reach here
        assert last_err is not None
        raise last_err

    def _sleep_backoff(self, attempt: int) -> None:
        delay = self.backoff * (2 ** attempt)
        time.sleep(delay)

    def _log_ok(self, method: str, path: str, status: int, elapsed_ms: float) -> None:
        try:
            self.log.debug("%s %s -> %s in %.1fms", method, path, status, elapsed_ms)
        except Exception:
            pass

    def _log_err(self, method: str, path: str, status: int, err: HttpError) -> None:
        try:
            self.log.warning("%s %s failed (status=%s): %s", method, path, status, err)
        except Exception:
            pass
