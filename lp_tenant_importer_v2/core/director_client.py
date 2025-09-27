"""
DirectorClient — JSON-first HTTP client for Logpoint Director API (v2 baseline).

This module provides a single, reusable HTTP client with:
  * Consistent JSON helpers (`get_json`, `post_json`, `put_json`, `delete_json`)
  * Path builders for the Director **config** and **monitor** APIs
  * Built-in **job monitoring** for asynchronous operations
  * **Generic resource helpers** so importers do not duplicate HTTP plumbing

Design goals:
  * Hide HTTP details from importers
  * Provide robust, explicit error reporting
  * Centralize monitoring and token handling

Example:
    client = DirectorClient(base_url, token)
    res = client.create_resource(pool_uuid, node_id, "Repos", {"name": "core", ...})
    # returns {"status": "Success"|"Failed", "result": {...}}
"""
from __future__ import annotations

import time
import os
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
from typing import Any, Dict, List, Union

import warnings
import urllib3
import requests

from .logging_utils import get_logger

log = get_logger(__name__)

JSON = Union[Dict[str, Any], List[Any]]

me = os.getenv("LP_SUPPRESS_TLS_WARNINGS")

@dataclass
class ClientOptions:
    """Runtime options for :class:`DirectorClient`.

    Attributes:
        verify: If False, SSL certificate verification is disabled.
        timeout_sec: Per-request timeout (seconds).
        monitor_timeout_sec: Global timeout when polling monitor API (seconds).
        monitor_poll_interval_sec: Interval between monitor polls (seconds).
    """
    verify: bool = True
    timeout_sec: int = 60
    monitor_timeout_sec: int = 180
    monitor_poll_interval_sec: float = 1.0
    monitor_stagnant_max: int = 120  # new: max same-status polls
    monitor_enabled: bool = True     # new: allow disabling monitoring

class DirectorClient:
    """High-level HTTP client for Logpoint Director API.

    The client exposes JSON-first helpers and **generic** resource CRUD methods,
    keeping importers free from HTTP boilerplate and monitoring code.

    Args:
        base_url: Base URL of the Director service (e.g., ``https://director.local``).
        api_token: API token to pass as ``Authorization: Bearer`` header.
        options: Optional :class:`ClientOptions` to fine-tune behavior.
        verify: Optional SSL verification override (if provided, overrides ``options.verify``).
    """
    def __init__(self, base_url: str, api_token: str, *, options: Optional[ClientOptions] = None, verify: bool | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        })
        self.options = options or ClientOptions()
        if verify is not None:
            self.options.verify = bool(verify)
        
        self.options.monitor_timeout_sec = int(os.getenv("LP_MONITOR_TIMEOUT_SEC", self.options.monitor_timeout_sec))
        self.options.monitor_poll_interval_sec = float(os.getenv("LP_MONITOR_POLL_SEC", self.options.monitor_poll_interval_sec))
        self.options.monitor_stagnant_max = int(os.getenv("LP_MONITOR_STAGNANT_MAX", self.options.monitor_stagnant_max))
        
        me = os.getenv("LP_MONITOR_ENABLED")
        if me is not None:
            self.options.monitor_enabled = me.strip().lower() not in {"0", "false", "no"}
        
        me = os.getenv("LP_SUPPRESS_TLS_WARNINGS")
        if me is not None:
            self.options.suppress_insecure_warning = me.strip().lower() not in {"0", "false", "no"}
        
        if not self.options.verify and self.options.suppress_insecure_warning:
            warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        

    # ---------------- low-level ----------------
    def _url(self, path: str) -> str:
        """Resolve an absolute URL from a relative *path*."""
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _req(self, method: str, path: str, *, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform an HTTP request and return the JSON response (or empty dict).

        Raises:
            requests.RequestException: On connection-level errors.
            requests.HTTPError: On non-2xx responses.
        """
        url = self._url(path)
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                json=json_body,
                timeout=self.options.timeout_sec,
                verify=self.options.verify,
            )
        except requests.RequestException as exc:
            log.error("HTTP %s %s failed: %s", method, url, exc)
            raise

        if resp.status_code >= 400:
            snippet = resp.text[:200]
            log.error("HTTP %s %s -> %s: %s", method, url, resp.status_code, snippet)
            raise requests.HTTPError(f"{resp.status_code}: {snippet}")

        try:
            return resp.json() if resp.text else {}
        except Exception:
            log.warning("Non-JSON response from %s %s, returning empty dict", method, url)
            return {}

    def get_json(self, path: str) -> JSON[str, Any]:
        """GET a JSON resource and return it as a dict (empty dict on no-content)."""
        return self._req("GET", path)

    def post_json(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """POST a JSON payload and return the parsed JSON response."""
        return self._req("POST", path, json_body=data)

    def put_json(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """PUT a JSON payload and return the parsed JSON response."""
        return self._req("PUT", path, json_body=data)

    def delete_json(self, path: str) -> Dict[str, Any]:
        """DELETE a JSON resource and return the parsed JSON response (if any)."""
        return self._req("DELETE", path)

    # ---------------- path builders ----------------
    @staticmethod
    def configapi(pool_uuid: str, node_id: str, resource: str) -> str:
        """Build the *configapi* path for a given resource under a pool/node."""
        return f"configapi/{pool_uuid}/{node_id}/{resource.strip('/')}"

    @staticmethod
    def monitorapi(pool_uuid: str, node_id: str, job_id: str) -> str:
        """Build the *monitorapi* path for a job id under a pool/node."""
        return f"monitorapi/{pool_uuid}/{node_id}/orders/{job_id}"

    def _extract_job_id(self, response: Dict[str, Any]) -> Optional[str]:
        """Extract a job id from a response dict.

        Supports both ``{"job_id": "..."}`` and
        ``{"message": "/monitorapi/.../orders/{id}"}`` payload shapes.
        """
        if not isinstance(response, dict):
            return None
        job_id = response.get("job_id")
        if job_id:
            return str(job_id)
        message = response.get("message")
        if isinstance(message, str) and "/orders/" in message:
            return message.rsplit("/", 1)[-1]
        return None

    def monitor_job(self, pool_uuid: str, node_id: str, job_id: str) -> bool:
        """
        Poll the monitor API until completion or timeout.
        Returns True on success-like status, False otherwise.
        """
        deadline = time.time() + self.options.monitor_timeout_sec
        seen_status: str | None = None
        stagnant = 0

        while time.time() < deadline:
            data = self.get_json(self.monitorapi(pool_uuid, node_id, job_id)) or {}
            status = str(data.get("status", "")).lower()

            log.debug(
                "monitor_job: job_id=%s status=%s data=%s",
                job_id, status, json.dumps(data)[:300]
            )

            if status in {"completed", "success", "ok"}:
                return True
            if status in {"failed", "error"}:
                return False

            stagnant = stagnant + 1 if status == seen_status else 0
            seen_status = status

            if stagnant >= self.options.monitor_stagnant_max:
                log.error("monitor_job: stagnant status=%s for %d polls (giving up)", status, stagnant)
                return False

            time.sleep(self.options.monitor_poll_interval_sec)

        log.error("Monitor timeout for job_id=%s", job_id)
        return False

    # ---------------- generic resource helpers ----------------
    def list_resource(self, pool_uuid: str, node_id: str, resource: str) -> JSON[str, Any]:
        """List a top-level resource under ``configapi`` (e.g., ``Repos``)."""
        return self.get_json(self.configapi(pool_uuid, node_id, resource))

    def list_subresource(self, pool_uuid: str, node_id: str, resource: str, subpath: str) -> JSON[str, Any]:
        """List a sub-resource (e.g., ``Repos/RepoPaths``)."""
        return self.get_json(self.configapi(pool_uuid, node_id, f"{resource.rstrip('/')}/{subpath.lstrip('/')}"))

    def create_resource(self, pool_uuid: str, node_id: str, resource: str, payload: Dict[str, Any], *, monitor: bool = True) -> Dict[str, Any]:
        """Create a resource and optionally monitor the resulting job.

        Returns:
            A dict with shape ``{"status": "Success"|"Failed", "result": ...}``.
        """
        res = self.post_json(self.configapi(pool_uuid, node_id, resource), {"data": payload})
        if not monitor or not self.options.monitor_enabled:
            return {"status": "Success", "result": res}
        job = self._extract_job_id(res)
        if job:
            ok = self.monitor_job(pool_uuid, node_id, job)
            return {"status": "Success" if ok else "Failed", "result": res}
        return {"status": "Success", "result": res}

    def update_resource(self, pool_uuid: str, node_id: str, resource: str, resource_id: str, payload: Dict[str, Any], *, monitor: bool = True) -> Dict[str, Any]:
        """Update a resource by id and optionally monitor the resulting job."""
        res = self.put_json(self.configapi(pool_uuid, node_id, f"{resource.rstrip('/')}/{resource_id}"), {"data": payload})
        if not monitor or not self.options.monitor_enabled:
            return {"status": "Success", "result": res}
        job = self._extract_job_id(res)
        if job:
            ok = self.monitor_job(pool_uuid, node_id, job)
            return {"status": "Success" if ok else "Failed", "result": res}
        return {"status": "Success", "result": res}

    def delete_resource(self, pool_uuid: str, node_id: str, resource: str, resource_id: str, *, monitor: bool = True) -> Dict[str, Any]:
        """Delete a resource by id and optionally monitor the resulting job."""
        res = self.delete_json(self.configapi(pool_uuid, node_id, f"{resource.rstrip('/')}/{resource_id}"))
        if not monitor or not self.options.monitor_enabled:
            return {"status": "Success", "result": res}
        job = self._extract_job_id(res)
        if job:
            ok = self.monitor_job(pool_uuid, node_id, job)
            return {"status": "Success" if ok else "Failed", "result": res}
        return {"status": "Success", "result": res}
