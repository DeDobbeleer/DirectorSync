"""High-level device management: list, export, and bulk delete with DG sync."""

import logging

if not __package__:
    from client import APIError, DirectorAPIClient
else:
    from .client import APIError, DirectorAPIClient


class DeviceManager:
    """Orchestrates device listing and safe bulk deletion with DeviceGroup cleanup."""

    def __init__(self, client: DirectorAPIClient, logger: logging.Logger) -> None:
        self.client = client
        self.logger = logger

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _unwrap_data(response: dict | list | None) -> list:
        """Unwrap a Director list response that may be wrapped in {'data': [...]}."""
        if isinstance(response, dict) and "data" in response:
            payload = response.get("data")
            return payload if isinstance(payload, list) else []
        if isinstance(response, list):
            return response
        return []

    @staticmethod
    def _extract_device_groups(device: dict) -> list[str]:
        """Return a list of DeviceGroup IDs attached to a device dict."""
        for key in ("devicegroup", "devicegroups", "device_groups", "groups"):
            val = device.get(key)
            if isinstance(val, list):
                return [str(v) for v in val if v]
            if isinstance(val, str):
                return [val]
        return []

    @staticmethod
    def _extract_ip(device: dict) -> str:
        """Normalize the IP field of a device to a comma-separated string."""
        ip = device.get("ip")
        if isinstance(ip, list):
            return ",".join(str(i) for i in ip)
        if isinstance(ip, str):
            return ip
        return ""

    @classmethod
    def _is_localhost(cls, device: dict) -> bool:
        """Return True if the device is the localhost sentinel (must never be deleted).

        Checks both the device name and its IP address(es).
        """
        name = str(device.get("name", "")).strip().lower()
        if name == "localhost":
            return True

        ip_str = cls._extract_ip(device)
        for forbidden in ("127.0.0.1", "::1"):
            if forbidden in ip_str:
                return True
        return False

    @classmethod
    def _extract_dg_members(cls, dg: dict) -> list[str]:
        """Return the member device IDs from a DeviceGroup dict."""
        devices = dg.get("devices")
        if isinstance(devices, dict):
            devices = devices.get("ids") or []
        if isinstance(devices, list):
            return [str(d) for d in devices if d]
        return []

    # ------------------------------------------------------------------
    # Director operations
    # ------------------------------------------------------------------

    def list_devices(self, pool_uuid: str, node_id: str) -> list[dict]:
        """Fetch the full device list for a given pool/node."""
        path = f"configapi/{pool_uuid}/{node_id}/Devices"
        self.logger.debug("Fetching devices from %s", path)
        raw = self.client.get_json(path)
        devices = self._unwrap_data(raw)
        self.logger.info("Retrieved %d devices from pool=%s node=%s", len(devices), pool_uuid, node_id)
        return devices

    def list_device_groups(self, pool_uuid: str, node_id: str) -> list[dict]:
        """Fetch all DeviceGroups for a given pool/node."""
        path = f"configapi/{pool_uuid}/{node_id}/DeviceGroups"
        self.logger.debug("Fetching device groups from %s", path)
        raw = self.client.get_json(path)
        groups = self._unwrap_data(raw)
        self.logger.info("Retrieved %d device groups from pool=%s node=%s", len(groups), pool_uuid, node_id)
        return groups

    def delete_device(
        self, pool_uuid: str, node_id: str, device_id: str
    ) -> tuple[bool, str | None]:
        """Delete a single device and monitor the async job if required.

        Returns (success, reason_or_none).
        """
        path = f"configapi/{pool_uuid}/{node_id}/Devices/{device_id}"
        self.logger.info("Deleting device %s from pool=%s node=%s", device_id, pool_uuid, node_id)

        try:
            res = self.client.delete_json(path)
        except APIError as exc:
            self.logger.error("DELETE failed for device %s: %s", device_id, exc)
            return False, str(exc)

        # Async branch 1: monitor URL
        monitor_path = self.client._extract_monitor_path(res)
        if monitor_path:
            self.logger.debug("Monitoring delete via URL: %s", monitor_path)
            ok, _data, reason = self.client.monitor_job_url(monitor_path)
            return ok, reason

        # Async branch 2: job id
        job_id = self.client._extract_job_id(res)
        if job_id:
            self.logger.debug("Monitoring delete via job_id: %s", job_id)
            ok, _data, reason = self.client.monitor_job(pool_uuid, node_id, job_id)
            return ok, reason

        # Synchronous
        self.logger.debug("Delete treated as synchronous for device %s", device_id)
        return True, None

    def update_device_group(
        self, pool_uuid: str, node_id: str, dg_id: str, payload: dict
    ) -> bool:
        """Update a DeviceGroup (e.g. to remove a deleted device)."""
        path = f"configapi/{pool_uuid}/{node_id}/DeviceGroups/{dg_id}"
        self.logger.debug("Updating DG %s on pool=%s node=%s", dg_id, pool_uuid, node_id)
        try:
            self.client.put_json(path, {"data": payload})
            return True
        except APIError as exc:
            self.logger.error("Failed to update DG %s: %s", dg_id, exc)
            return False

    # ------------------------------------------------------------------
    # Bulk delete with DG safety
    # ------------------------------------------------------------------

    def bulk_delete(
        self, pool_uuid: str, node_id: str, devices: list[dict]
    ) -> dict[str, int]:
        """Delete devices and synchronise DeviceGroup memberships.

        Devices identified as localhost are never deleted.
        DeviceGroups are updated ONLY when the device deletion succeeds.
        If a device deletion fails, no DG changes are made for that device.

        Args:
            pool_uuid: The SIEM pool UUID.
            node_id: The SIEM node UUID.
            devices: List of device dicts (must contain at least 'id', plus
                     'name' and 'ip' for localhost detection).

        Returns:
            A result counter dict with keys:
            deleted, failed, skipped_localhost, dg_updated.
        """
        # Fetch live DeviceGroups once per pool/node
        dgs = self.list_device_groups(pool_uuid, node_id)
        dg_map = {dg["id"]: dg for dg in dgs if dg.get("id")}

        results = {
            "deleted": 0,
            "failed": 0,
            "skipped_localhost": 0,
            "dg_updated": 0,
        }

        for dev in devices:
            dev_id = dev.get("id")
            dev_name = dev.get("name", "unknown")

            if not dev_id:
                self.logger.warning("Skipping device with missing id: %s", dev)
                results["failed"] += 1
                continue

            if self._is_localhost(dev):
                self.logger.warning(
                    "Skipping localhost device: %s (%s)", dev_name, dev_id
                )
                results["skipped_localhost"] += 1
                continue

            # Identify DGs that currently contain this device (live data)
            affected_dg_ids = []
            for dg_id, dg in dg_map.items():
                members = self._extract_dg_members(dg)
                if dev_id in members:
                    affected_dg_ids.append(dg_id)

            # 1. Delete the device
            ok, reason = self.delete_device(pool_uuid, node_id, dev_id)
            if not ok:
                self.logger.error(
                    "Device deletion failed: %s (%s) — reason: %s",
                    dev_name,
                    dev_id,
                    reason,
                )
                results["failed"] += 1
                continue

            self.logger.info("Device deleted successfully: %s (%s)", dev_name, dev_id)
            results["deleted"] += 1

            # 2. If deletion succeeded, purge the device from affected DGs
            for dg_id in affected_dg_ids:
                dg = dg_map[dg_id]
                members = self._extract_dg_members(dg)
                new_members = [m for m in members if m != dev_id]
                if len(new_members) == len(members):
                    continue

                payload = {
                    "name": dg.get("name", ""),
                    "description": dg.get("description", ""),
                    "devices": new_members,
                }
                if self.update_device_group(pool_uuid, node_id, dg_id, payload):
                    self.logger.info(
                        "Removed device %s from DG %s (%s)",
                        dev_id,
                        dg.get("name", dg_id),
                        dg_id,
                    )
                    results["dg_updated"] += 1
                    # Update in-memory map so subsequent iterations are consistent
                    dg["devices"] = new_members
                else:
                    self.logger.error(
                        "Failed to update DG %s after deleting device %s",
                        dg_id,
                        dev_id,
                    )

        self.logger.info(
            "Bulk delete summary for pool=%s node=%s: %s",
            pool_uuid,
            node_id,
            results,
        )
        return results
