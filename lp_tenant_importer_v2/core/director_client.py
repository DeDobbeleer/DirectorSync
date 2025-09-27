"""
DirectorClient — JSON-first HTTP client for Logpoint Director API.
Includes built-in monitor polling for /monitorapi/* jobs.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .logging_utils import get_logger

log = get_logger(__name__)


@dataclass
class ClientOptions:
    verify: bool = True
    timeout_sec: int = 60
    monitor_timeout_sec: int = 180
    monitor_poll_interval_sec: float = 1.0


class DirectorClient:
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

    # ---------------- low-level ----------------
    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _req(self, method: str, path: str, *, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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

    def get_json(self, path: str) -> Dict[str, Any]:
        return self._req("GET", path)

    def post_json(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._req("POST", path, json_body=data)

    def put_json(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._req("PUT", path, json_body=data)

    def delete_json(self, path: str) -> Dict[str, Any]:
        return self._req("DELETE", path)

    # ---------------- helpers ----------------
    @staticmethod
    def configapi(pool_uuid: str, node_id: str, resource: str) -> str:
        return f"configapi/{pool_uuid}/{node_id}/{resource.strip('/')}"

    @staticmethod
    def monitorapi(pool_uuid: str, node_id: str, job_id: str) -> str:
        return f"monitorapi/{pool_uuid}/{node_id}/orders/{job_id}"

    def monitor_job(self, pool_uuid: str, node_id: str, job_id: str) -> bool:
        """
        Poll monitor API until completion or timeout. Return True if successful.
        """
        deadline = time.time() + self.options.monitor_timeout_sec
        while time.time() < deadline:
            data = self.get_json(self.monitorapi(pool_uuid, node_id, job_id))
            status = (data or {}).get("status")
            if status in {"completed", "success", "ok"}:
                return True
            if status in {"failed", "error"}:
                return False
            time.sleep(self.options.monitor_poll_interval_sec)
        log.error("Monitor timeout for job_id=%s", job_id)
        return False

    # --------------- Repositories ---------------
    def list_repositories(self, pool_uuid: str, node_id: str) -> Dict[str, Any]:
        return self.get_json(self.configapi(pool_uuid, node_id, "Repos"))

    def list_repository_paths(self, pool_uuid: str, node_id: str) -> Dict[str, Any]:
        return self.get_json(self.configapi(pool_uuid, node_id, "Repos/RepoPaths"))

    def create_repository(self, pool_uuid: str, node_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        res = self.post_json(self.configapi(pool_uuid, node_id, "Repos"), {"data": payload})
        job = (res or {}).get("message", "").split("/")[-1] if isinstance(res, dict) else None
        if job:
            ok = self.monitor_job(pool_uuid, node_id, job)
            return {"status": "Success" if ok else "Failed", "result": res}
        return {"status": "Success", "result": res}

    def update_repository(self, pool_uuid: str, node_id: str, repo_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        res = self.put_json(self.configapi(pool_uuid, node_id, f"Repos/{repo_id}"), {"data": payload})
        job = (res or {}).get("message", "").split("/")[-1] if isinstance(res, dict) else None
        if job:
            ok = self.monitor_job(pool_uuid, node_id, job)
            return {"status": "Success" if ok else "Failed", "result": res}
        return {"status": "Success", "result": res}
