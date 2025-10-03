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
import uuid
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Union, Tuple

import warnings
import urllib3
import requests

from .logging_utils import get_logger

log = get_logger(__name__)

JSON = Union[Dict[str, Any], List[Any]]
me = os.getenv("LP_SUPPRESS_TLS_WARNINGS")

_LOG_PREVIEW = int(os.getenv("LP_HTTP_PREVIEW", "600"))
_REDACT_KEYS = {"token", "authorization", "password", "api_token", "x-api-key"}

def _short_json(obj: Any, limit: int = _LOG_PREVIEW) -> str:
    try:
        if isinstance(obj, (dict, list)):
            s = json.dumps(obj, ensure_ascii=False)
        else:
            s = str(obj)
        return s[:limit]
    except Exception:
        return f"<unserializable:{type(obj).__name__}>"

def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in _REDACT_KEYS:
                out[k] = "***REDACTED***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj

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

# --- Helpers: extract monitor path and job id from response ---

    def _extract_monitor_path(self, response: Dict[str, Any]) -> Optional[str]:
        msg = isinstance(response, dict) and response.get("message")
        if isinstance(msg, str) and msg.lstrip().startswith(("monitorapi/", "/monitorapi/")):
            return msg.lstrip("/")
        return None


    def _extract_job_id(self, response: Dict[str, Any]) -> Optional[str]:
        if not isinstance(response, dict):
            return None
        for key in ("job", "orderId", "id"):
            val = response.get(key)
            if isinstance(val, str) and val:
                return val
        data = response.get("data")
        if isinstance(data, dict):
            for key in ("job", "orderId", "id"):
                val = data.get(key)
                if isinstance(val, str) and val:
                    return val
        return None

# --- Monitor by job id: modern flow, but also accept response.success ---

    def _monitor_error_text(data: Dict[str, Any]) -> str:
        """
        Produce a short human-readable error from a monitor payload.
        Looks into legacy `response.errors/message` and top-level `message/status`.
        """
        if not isinstance(data, dict):
            return "monitor: invalid payload"

        # Legacy: {response: {success, errors, message}}
        resp = data.get("response")
        if isinstance(resp, dict):
            errs = resp.get("errors")
            if isinstance(errs, list) and errs:
                # Join list of strings or dicts
                parts = []
                for e in errs:
                    if isinstance(e, str):
                        parts.append(e)
                    elif isinstance(e, dict):
                        # pick something readable
                        parts.append(e.get("message") or e.get("error") or _short_json(e, 200))
                    else:
                        parts.append(str(e))
                return "; ".join(parts)[:400]
            msg = resp.get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()[:400]

        # Fallbacks
        msg2 = data.get("message")
        if isinstance(msg2, str) and msg2.strip():
            return msg2.strip()[:400]

        status = data.get("status")
        if isinstance(status, str) and status.strip():
            return f"status={status.strip()[:100]}"

        return "monitor: failed (no error details)"

    def monitor_job(self, pool_uuid: str, node_id: str, job_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Poll 'monitorapi/{pool}/{node}/orders/{job_id}'.
        Return (ok, last_payload).
        """
        deadline = time.time() + self.options.monitor_timeout_sec
        seen_status, stagnant = None, 0
        last: Dict[str, Any] = {}

        while time.time() < deadline:
            data = self.get_json(self.monitorapi(pool_uuid, node_id, job_id)) or {}
            last = data

            resp = data.get("response")
            log.debug(f"monitor_job: running payload={_short_json(_redact(data))}" )
            if isinstance(resp, dict):
                success = resp.get("success")
                errors = resp.get("errors", [])
                if success is True:
                    log.debug("monitor_job: success payload=%s", _short_json(_redact(data)))
                    return True, data
                if success is False or errors:
                    log.error("monitor_job: failed payload=%s", _short_json(_redact(data)))
                    return False, data

            status = str(data.get("status", "")).lower()
            if status in {"completed", "success", "ok"}:
                log.debug("monitor_job: success status=%s payload=%s", status, _short_json(_redact(data)))
                return True, data
            if status in {"failed", "error"}:
                log.error("monitor_job: failed status=%s payload=%s", status, _short_json(_redact(data)))
                return False, data

            stagnant = stagnant + 1 if status == seen_status else 0
            seen_status = status
            time.sleep(self.options.monitor_poll_interval_sec)
            if stagnant >= self.options.monitor_stagnant_max:
                log.error("monitor_job: stagnant status=%s polls=%d last=%s",
                        status, stagnant, _short_json(_redact(data)))
                return False, data

        log.error("monitor_job: timeout last=%s", _short_json(_redact(last)))
        return False, last


# --- Monitor by URL: legacy flow reading response.success ---

    def monitor_job_url(self, monitor_path: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Poll a legacy monitor endpoint like 'monitorapi/...'.
        Return (ok, last_payload).
        """
        path = monitor_path.lstrip("/")
        deadline = time.time() + self.options.monitor_timeout_sec
        seen_status, stagnant = None, 0
        last: Dict[str, Any] = {}

        while time.time() < deadline:
            data = self.get_json(path) or {}
            last = data

            # Legacy: nested response.success/errors
            resp = data.get("response")
            if isinstance(resp, dict):
                success = resp.get("success")
                errors = resp.get("errors", [])
                if success is True:
                    log.debug("monitor_url: success payload=%s", _short_json(_redact(data)))
                    return True, data
                if success is False or errors:
                    log.error("monitor_url: failed payload=%s", _short_json(_redact(data)))
                    return False, data

            # Modern-ish fallback: top-level status
            status = str(data.get("status", "")).lower()
            if status in {"completed", "success", "ok"}:
                log.debug("monitor_url: success status=%s payload=%s", status, _short_json(_redact(data)))
                return True, data
            if status in {"failed", "error"}:
                log.error("monitor_url: failed status=%s payload=%s", status, _short_json(_redact(data)))
                return False, data

            stagnant = stagnant + 1 if status == seen_status else 0
            seen_status = status
            time.sleep(self.options.monitor_poll_interval_sec)
            if stagnant >= self.options.monitor_stagnant_max:
                log.error("monitor_url: stagnant status=%s polls=%d last=%s",
                        status, stagnant, _short_json(_redact(data)))
                return False, data

        log.error("monitor_url: timeout last=%s", _short_json(_redact(last)))
        return False, last

    # ---------------- generic resource helpers ----------------
    def list_resource(self, pool_uuid: str, node_id: str, resource: str) -> JSON[str, Any]:
        """List a top-level resource under ``configapi`` (e.g., ``Repos``)."""
        return self.get_json(self.configapi(pool_uuid, node_id, resource))

    def list_subresource(self, pool_uuid: str, node_id: str, resource: str, subpath: str) -> JSON[str, Any]:
        """List a sub-resource (e.g., ``Repos/RepoPaths``)."""
        return self.get_json(self.configapi(pool_uuid, node_id, f"{resource.rstrip('/')}/{subpath.lstrip('/')}"))

# --- Create / Update / Delete: prefer monitor URL, else job id, else synchronous ---
    def create_resource(
        self,
        pool_uuid: str,
        node_id: str,
        resource: str,
        payload: Dict[str, Any],
        monitor: bool = True,
    ) -> Dict[str, Any]:
        corr = uuid.uuid4().hex[:8]
        path = self.configapi(pool_uuid, node_id, resource)
        safe_payload = _redact({"data": payload})

        log.info("CREATE[%s] POST %s pool=%s node=%s resource=%s", corr, path, pool_uuid, node_id, resource)
        log.debug("CREATE[%s] payload=%s", corr, _short_json(safe_payload))

        try:
            res = self.post_json(path, safe_payload)
            log.debug("CREATE[%s] response=%s", corr, _short_json(_redact(res)))
        except Exception as e:
            log.exception("CREATE[%s] HTTP POST failed", e)
            return {"status": "fail", "result": "error", "monitor_ok": None, "monitor_branch": "disabled", "corr": e}

        if not monitor or not self.options.monitor_enabled:
            return {"status": "Success", "result": res, "monitor_ok": None, "monitor_branch": "disabled", "corr": corr}

        mon_path = self._extract_monitor_path(res)
        if mon_path:
            log.info("CREATE[%s] monitor via URL: %s", corr, mon_path)
            ok = self.monitor_job_url(mon_path)
            return {"status": "Success" if ok else "Failed", "result": res, "monitor_ok": ok, "monitor_branch": "url", "corr": corr}

        job = self._extract_job_id(res)
        if job:
            log.info("CREATE[%s] monitor via job id: %s", corr, job)
            ok = self.monitor_job(pool_uuid, node_id, job)
            return {"status": "Success" if ok else "Failed", "result": res, "monitor_ok": ok, "monitor_branch": "job", "corr": corr}

        log.info("CREATE[%s] no monitor info, treating as synchronous", corr)
        return {"status": "Success", "result": res, "monitor_ok": None, "monitor_branch": "sync", "corr": corr}

    def update_resource(
        self,
        pool_uuid: str,
        node_id: str,
        resource: str,
        resource_id: str,
        payload: Dict[str, Any],
        monitor: bool = True,
    ) -> Dict[str, Any]:
        
        corr = uuid.uuid4().hex[:8]
        base = self.configapi(pool_uuid, node_id, resource)
        path = f"{base}/{resource_id}"
        safe_payload = _redact({"data": payload})

        log.info("UPDATE[%s] PUT %s pool=%s node=%s resource=%s id=%s", corr, path, pool_uuid, node_id, resource, resource_id)
        log.debug("UPDATE[%s] payload=%s", corr, _short_json(safe_payload))

        try:
            res = self.put_json(path, safe_payload)
            log.debug("UPDATE[%s] response=%s", corr, _short_json(_redact(res)))
        except Exception:
            log.exception("UPDATE[%s] HTTP PUT failed", corr)
            raise

        if not monitor or not self.options.monitor_enabled:
            return {"status": "Success", "result": res, "monitor_ok": None, "monitor_branch": "disabled", "corr": corr}

        mon_path = self._extract_monitor_path(res)
        if mon_path:
            log.info("UPDATE[%s] monitor via URL: %s", corr, mon_path)
            ok = self.monitor_job_url(mon_path)
            return {"status": "Success" if ok else "Failed", "result": res, "monitor_ok": ok, "monitor_branch": "url", "corr": corr}

        job = self._extract_job_id(res)
        if job:
            log.info("UPDATE[%s] monitor via job id: %s", corr, job)
            ok = self.monitor_job(pool_uuid, node_id, job)
            return {"status": "Success" if ok else "Failed", "result": res, "monitor_ok": ok, "monitor_branch": "job", "corr": corr}

        log.info("UPDATE[%s] no monitor info, treating as synchronous", corr)
        return {"status": "Success", "result": res, "monitor_ok": None, "monitor_branch": "sync", "corr": corr}
    
    def delete_resource(
        self,
        pool_uuid: str,
        node_id: str,
        resource: str,
        resource_id: str,
        monitor: bool = True,
    ) -> Dict[str, Any]:
        corr = uuid.uuid4().hex[:8]
        base = self.configapi(pool_uuid, node_id, resource)
        path = f"{base}/{resource_id}"

        log.info("DELETE[%s] DELETE %s pool=%s node=%s resource=%s id=%s", corr, path, pool_uuid, node_id, resource, resource_id)

        try:
            res = self.delete_json(path)
            log.debug("DELETE[%s] response=%s", corr, _short_json(_redact(res)))
        except Exception:
            log.exception("DELETE[%s] HTTP DELETE failed", corr)
            raise

        if not monitor or not self.options.monitor_enabled:
            return {"status": "Success", "result": res, "monitor_ok": None, "monitor_branch": "disabled", "corr": corr}

        mon_path = self._extract_monitor_path(res)
        if mon_path:
            log.info("DELETE[%s] monitor via URL: %s", corr, mon_path)
            ok = self.monitor_job_url(mon_path)
            return {"status": "Success" if ok else "Failed", "result": res, "monitor_ok": ok, "monitor_branch": "url", "corr": corr}

        job = self._extract_job_id(res)
        if job:
            log.info("DELETE[%s] monitor via job id: %s", corr, job)
            ok = self.monitor_job(pool_uuid, node_id, job)
            return {"status": "Success" if ok else "Failed", "result": res, "monitor_ok": ok, "monitor_branch": "job", "corr": corr}

        log.info("DELETE[%s] no monitor info, treating as synchronous", corr)
        return {"status": "Success", "result": res, "monitor_ok": None, "monitor_branch": "sync", "corr": corr}



