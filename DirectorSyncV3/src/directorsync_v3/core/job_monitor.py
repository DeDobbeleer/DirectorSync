"""
Job monitor: poll a job endpoint until it reaches a terminal state.

Config (from profile):
monitor:
  path: "/jobs/{job_id}"
  status_field: "state"           # default "status"
  ok_states: ["done", "success"]  # required
  fail_states: ["error", "failed"]# required
  poll:
    interval_sec: 0.1             # default 0.05
    timeout_sec:  5.0             # default 5.0
"""

from __future__ import annotations

import time
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .director_client import DirectorClient, HttpError


class MonitorError(Exception):
    """Raised when a job reaches a failure state."""


class MonitorTimeout(Exception):
    """Raised when a job does not reach a terminal state in time."""


@dataclass
class MonitorConfig:
    path: str
    status_field: str = "status"
    ok_states: List[str] = None  # type: ignore[assignment]
    fail_states: List[str] = None  # type: ignore[assignment]
    interval_sec: float = 0.05
    timeout_sec: float = 5.0

    def __post_init__(self) -> None:
        self.ok_states = list(self.ok_states or [])
        self.fail_states = list(self.fail_states or [])
        if not self.ok_states or not self.fail_states:
            raise ValueError("MonitorConfig requires both ok_states and fail_states")


class JobMonitor:
    """Polls a job endpoint until a terminal state is reached."""

    def __init__(self, client: DirectorClient, cfg: MonitorConfig) -> None:
        self.client = client
        self.cfg = cfg

    @staticmethod
    def _format_url(template: str, sources: Dict[str, Any]) -> str:
        def repl(m: re.Match[str]) -> str:
            k = m.group(1)
            v = sources.get(k, "")
            return str(v if v is not None else "")
        return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", repl, template)

    def wait(self, *, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Poll GET <path> until status_field ∈ ok_states or fail_states.
        Returns the final JSON.
        Raises MonitorError on fail_state, MonitorTimeout on timeout.
        """
        url = self._format_url(self.cfg.path, context)
        deadline = time.time() + float(self.cfg.timeout_sec)
        last_json: Dict[str, Any] = {}

        while True:
            try:
                last_json = self.client.get_json(url)
            except HttpError as e:
                # HTTP error during polling → treat as failure if time permits retries
                last_json = {"_poll_error": str(e)}
            state = ""
            if isinstance(last_json, dict):
                state = str(last_json.get(self.cfg.status_field, ""))
            if state in self.cfg.ok_states:
                return last_json
            if state in self.cfg.fail_states:
                raise MonitorError(f"job state='{state}'")

            if time.time() >= deadline:
                raise MonitorTimeout(f"timeout waiting for job; last_state='{state}'")
            time.sleep(float(self.cfg.interval_sec))
