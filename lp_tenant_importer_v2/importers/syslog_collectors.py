# lp_tenant_importer_v2/importers/syslog_collectors.py
"""
Syslog Collectors Importer (V2)

This importer implements the Excel-driven, device-scoped creation/update of
SyslogCollector plugins on Logpoint Director (API v2.7.0), matching the
DirectorSync V2 framework contracts (BaseImporter pipeline, logging, reporting).

Product truth (agreed):
- Input is filtered by app = "SyslogCollector".
- Context is Device-only (no LCP in this project).
- Mandatory fields for both Create and Update: device_id (resolved from
  device_name), charset, parser, proxy_condition.
- Proxy matrix:
  * use_as_proxy: proxy_ip = empty, hostname = empty, processpolicy = empty
  * uses_proxy: proxy_ip required (≥1) AND each IP must have at least one
    use_as_proxy on the target, hostname required, processpolicy required
  * None: proxy_ip = empty, hostname = empty, processpolicy required
- ProcessingPolicy resolution: Excel provides source PP id → map to name via
  ProcessingPolicies sheet → resolve to target PP id via API.
- We deliberately ignore any "log_collector" field.

The importer runs in three phases with barriers:
  Phase 1: apply all use_as_proxy rows (create/update/noop), re-inventory
  Phase 2: apply all None rows, optional re-inventory
  Phase 3: apply all uses_proxy rows ONLY if all proxy_ip exist on target
           (i.e., at least one use_as_proxy exists for each IP)
This guarantees referential integrity for proxy IPs.

Idempotence:
- NOOP when existing matches desired (order-insensitive compare for lists).
- UPDATE when existing differs on relevant fields.
- CREATE when missing.
- SKIP for validation/dependency issues (never mutates).

Dry-run:
- Performs full validation and resolution, simulates phases and barriers,
  emits "would CREATE/UPDATE/NOOP/SKIP", does not call mutating endpoints.

Logging:
- DEBUG: normalized desired/existing, diffs, mappings, proxy indices, endpoints
- INFO: per-phase summaries, decisions
- WARNING: degraded behavior / soft issues
- ERROR: hard failures (HTTP, schema, dependency)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import logging

from ..core.director_client import DirectorClient
from ..utils.validators import as_list, not_empty_str
from ..importers.base import BaseImporter


LOGGER = logging.getLogger(__name__)


# ------------------------------- Data Models ---------------------------------


@dataclass(frozen=True)
class DesiredCollector:
    """Normalized desired state from Excel for one device."""

    device_name: str
    device_id: str
    app: str  # must be "SyslogCollector"
    proxy_condition: str  # use_as_proxy | uses_proxy | None
    parser: str
    charset: str
    proxy_ips: Tuple[str, ...] = field(default_factory=tuple)  # sorted, unique
    hostnames: Tuple[str, ...] = field(default_factory=tuple)  # sorted, unique
    processpolicy_name: Optional[str] = None
    processpolicy_id: Optional[str] = None

    @property
    def key(self) -> str:
        # One collector per device in this project.
        return self.device_name


@dataclass
class ExistingCollector:
    """Canonical view of the existing SyslogCollector plugin on a device."""

    device_id: str
    collector_id: Optional[str]  # UUID required for PUT
    proxy_condition: str
    parser: str
    charset: str
    proxy_ips: Tuple[str, ...]
    hostnames: Tuple[str, ...]
    processpolicy_id: Optional[str]

    @classmethod
    def from_plugin(cls, device_id: str, plugin: Dict[str, Any]) -> "ExistingCollector":
        """
        Convert a raw plugin entry (Devices/{id}/plugins with app=SyslogCollector)
        to our canonical structure. We are defensive wrt attribute names.
        """
        # Defensive key extraction (accepts multiple variants seen across builds)
        def _listish(d: Dict[str, Any], *keys: str) -> Tuple[str, ...]:
            for k in keys:
                if k in d and d[k] is not None:
                    vals = as_list(d[k])
                    # Normalize: trim, drop empties, deduplicate, sort
                    vals = sorted({v.strip() for v in vals if isinstance(v, str) and v.strip()})
                    return tuple(vals)
            return tuple()

        def _str(d: Dict[str, Any], *keys: str) -> str:
            for k in keys:
                v = d.get(k)
                if isinstance(v, str):
                    return v.strip()
            return ""

        proxy_condition = _str(plugin, "proxy_condition", "condition", "mode") or "None"
        parser = _str(plugin, "parser")
        charset = _str(plugin, "charset")
        proxy_ips = _listish(plugin, "proxy_ip", "ips", "addresses")
        hostnames = _listish(plugin, "hostname", "hostnames")
        processpolicy_id = _str(plugin, "processpolicy", "processpolicy_id") or None
        collector_id = plugin.get("uuid") or plugin.get("id")

        return cls(
            device_id=device_id,
            collector_id=collector_id,
            proxy_condition=proxy_condition,
            parser=parser,
            charset=charset,
            proxy_ips=proxy_ips,
            hostnames=hostnames,
            processpolicy_id=processpolicy_id,
        )


# ------------------------------- Importer ------------------------------------


class SyslogCollectorsImporter(BaseImporter):
    """
    Excel-driven importer for SyslogCollector plugins.

    Sheet name(s):
      - "SyslogCollector" (preferred)
      - "SyslogCollectors" (backward-compatible)
    Required columns (after filtering on app="SyslogCollector"):
      - device_name, parser, charset, proxy_condition
    Conditional columns:
      - processpolicy (required for uses_proxy and None, empty for use_as_proxy)
      - proxy_ip (required for uses_proxy, empty otherwise)
      - hostname (required for uses_proxy, empty otherwise)
    """

    # ---- BaseImporter contract ----
    sheet_names = ("SyslogCollector", "SyslogCollectors")
    required_columns = (
        "app",
        "device_name",
        "parser",
        "charset",
        "proxy_condition",
    )

    # Fields used to assert NOOP vs UPDATE (compared canonically)
    compare_keys = (
        "proxy_condition",
        "parser",
        "charset",
        "proxy_ips",
        "hostnames",
        "processpolicy_id",
    )

    resource_name = "SyslogCollector"  # Used for client CRUD helper calls

    # --------------------------- Pipeline Overrides ---------------------------

    def validate(self) -> None:
        """
        Pre-validate the loaded DataFrame (self.df), build normalized desired
        items, resolve dependencies (devices, processing policies), and
        partition by phase.
        """
        self._ensure_df()
        df = self.df.copy()

        # Filter on app = SyslogCollector
        df = df[(df["app"].astype(str).str.strip() == "SyslogCollector")].copy()
        if df.empty:
            LOGGER.info("No rows with app=SyslogCollector; nothing to do.")
            self.desired: List[DesiredCollector] = []
            self.partition: Dict[str, List[DesiredCollector]] = {"A": [], "B": [], "C": []}
            return

        # Basic cell normalization
        for col in ("device_name", "parser", "charset", "proxy_condition", "processpolicy"):
            if col in df.columns:
                df[col] = df[col].astype(str).str.strip()

        # Resolve device_name -> device_id (batch per node later; here overall)
        # Collect unique device names first
        device_names = sorted({n for n in df["device_name"].tolist() if not_empty_str(n)})
        device_name_to_id = self._resolve_device_ids(device_names)

        # Resolve processing policy name -> target id (from PP name mapped from source)
        # The sheet "ProcessingPolicies" (source view) is used to map a source id to a name.
        pp_source_id_to_name = self._load_pp_source_id_to_name()
        pp_name_to_target_id = self._resolve_pp_name_to_target_id(set(pp_source_id_to_name.values()))

        # Optional: validate charset list from API if available (non-fatal)
        known_charsets = self._fetch_known_charsets()

        desired_items: List[DesiredCollector] = []
        seen_device: Set[str] = set()
        errors = 0

        for idx, row in df.iterrows():
            device_name = row.get("device_name") or ""
            parser = row.get("parser") or ""
            charset = row.get("charset") or ""
            condition = (row.get("proxy_condition") or "").strip()
            processpolicy_source_id = (row.get("processpolicy") or "").strip()
            proxy_ip_raw = (row.get("proxy_ip") or "").strip()
            hostname_raw = (row.get("hostname") or "").strip()

            if not device_name:
                self._report_skip(idx, device_name, "E-SC-VAL-005", "MissingField: device_name is required.")
                errors += 1
                continue

            # Duplicate guard: one row per device
            if device_name in seen_device:
                self._report_skip(
                    idx,
                    device_name,
                    "E-SC-VAL-009",
                    f"Duplicate device entry: device_name='{device_name}' already processed.",
                )
                errors += 1
                continue
            seen_device.add(device_name)

            # Device resolution
            device_id = device_name_to_id.get(device_name)
            if not device_id:
                self._report_skip(
                    idx,
                    device_name,
                    "E-SC-VAL-002",
                    f"DeviceNotFound: device='{device_name}' not found or ambiguous.",
                )
                errors += 1
                continue

            # Basic required fields
            if not parser:
                self._report_skip(idx, device_name, "E-SC-VAL-005", "MissingField: parser is required.")
                errors += 1
                continue
            if not charset:
                self._report_skip(idx, device_name, "E-SC-VAL-005", "MissingField: charset is required.")
                errors += 1
                continue
            if not condition or condition not in {"use_as_proxy", "uses_proxy", "None"}:
                self._report_skip(
                    idx,
                    device_name,
                    "E-SC-VAL-001",
                    "InvalidProxyCondition: expected one of {use_as_proxy, uses_proxy, None}.",
                )
                errors += 1
                continue

            # Optional charset validation
            if known_charsets and charset not in known_charsets:
                self._report_skip(
                    idx,
                    device_name,
                    "E-SC-VAL-004",
                    f'CharsetInvalid: charset="{charset}" unknown on target.',
                )
                errors += 1
                continue

            proxy_ips = self._normalize_list(proxy_ip_raw)
            hostnames = self._normalize_list(hostname_raw)

            # Proxy matrix validation
            if condition == "use_as_proxy":
                if proxy_ips:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-006", "MustBeEmpty: proxy_ip must be empty for use_as_proxy."
                    )
                    errors += 1
                    continue
                if hostnames:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-007", "MustBeEmpty: hostname must be empty for use_as_proxy."
                    )
                    errors += 1
                    continue
                if processpolicy_source_id:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-008", "MustBeEmpty: processpolicy must be empty for use_as_proxy."
                    )
                    errors += 1
                    continue
                pp_name = None
                pp_id = None

            elif condition == "uses_proxy":
                if not proxy_ips:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-005", "MissingField: proxy_ip is required for uses_proxy."
                    )
                    errors += 1
                    continue
                if not hostnames:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-005", "MissingField: hostname is required for uses_proxy."
                    )
                    errors += 1
                    continue
                if not processpolicy_source_id:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-005", "MissingField: processpolicy is required for uses_proxy."
                    )
                    errors += 1
                    continue
                pp_name = pp_source_id_to_name.get(processpolicy_source_id)
                if not pp_name:
                    self._report_skip(
                        idx,
                        device_name,
                        "E-SC-DEP-001",
                        f'MissingPP: source PP id="{processpolicy_source_id}" not mapped to a name in ProcessingPolicies sheet.',
                    )
                    errors += 1
                    continue
                pp_id = pp_name_to_target_id.get(pp_name)
                if not pp_id:
                    self._report_skip(
                        idx, device_name, "E-SC-DEP-001", f'MissingPP: processpolicy "{pp_name}" not found on target.'
                    )
                    errors += 1
                    continue

            else:  # condition == "None"
                if proxy_ips:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-006", "MustBeEmpty: proxy_ip must be empty for None."
                    )
                    errors += 1
                    continue
                if hostnames:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-007", "MustBeEmpty: hostname must be empty for None."
                    )
                    errors += 1
                    continue
                if not processpolicy_source_id:
                    self._report_skip(
                        idx, device_name, "E-SC-VAL-005", "MissingField: processpolicy is required for None."
                    )
                    errors += 1
                    continue
                pp_name = pp_source_id_to_name.get(processpolicy_source_id)
                if not pp_name:
                    self._report_skip(
                        idx,
                        device_name,
                        "E-SC-DEP-001",
                        f'MissingPP: source PP id="{processpolicy_source_id}" not mapped to a name in ProcessingPolicies sheet.',
                    )
                    errors += 1
                    continue
                pp_id = pp_name_to_target_id.get(pp_name)
                if not pp_id:
                    self._report_skip(
                        idx, device_name, "E-SC-DEP-001", f'MissingPP: processpolicy "{pp_name}" not found on target.'
                    )
                    errors += 1
                    continue

            desired_items.append(
                DesiredCollector(
                    device_name=device_name,
                    device_id=device_id,
                    app="SyslogCollector",
                    proxy_condition=condition,
                    parser=parser,
                    charset=charset,
                    proxy_ips=tuple(proxy_ips),
                    hostnames=tuple(hostnames),
                    processpolicy_name=pp_name,
                    processpolicy_id=pp_id,
                )
            )

        self.desired = desired_items

        # Partition by phase for orchestration
        part_A, part_B, part_C = [], [], []
        for item in desired_items:
            if item.proxy_condition == "use_as_proxy":
                part_A.append(item)
            elif item.proxy_condition == "None":
                part_B.append(item)
            else:
                part_C.append(item)
        self.partition = {"A": part_A, "B": part_B, "C": part_C}

        if errors:
            LOGGER.info("Validation produced %d SKIP rows; valid=%d", errors, len(desired_items))

        LOGGER.debug("Validation complete. Partition sizes: A=%d B=%d C=%d", len(part_A), len(part_B), len(part_C))

    def fetch_existing(self) -> None:
        """
        Inventory existing SyslogCollector plugins for devices referenced by the
        desired set (faster than a full node inventory).
        """
        if not hasattr(self, "desired") or not self.desired:
            self.existing_by_device: Dict[str, ExistingCollector] = {}
            self.proxy_index: Dict[str, int] = {}
            return

        client: DirectorClient = self.client
        pool_uuid = self.ctx.pool_uuid
        node_id = self.ctx.node_id

        existing_by_device: Dict[str, ExistingCollector] = {}
        proxy_index: Dict[str, int] = {}  # proxy_ip -> count of use_as_proxy on target

        for dev_id in sorted({d.device_id for d in self.desired}):
            try:
                plugins = client.list_subresource(pool_uuid, node_id, "Devices", dev_id, "plugins") or []
            except Exception as exc:  # noqa: BLE001
                LOGGER.error(
                    "Failed listing plugins for device_id=%s: %s", dev_id, exc, exc_info=LOGGER.isEnabledFor(logging.DEBUG)
                )
                continue

            for p in plugins:
                if str(p.get("app", "")).strip() != "SyslogCollector":
                    continue
                ec = ExistingCollector.from_plugin(dev_id, p)
                existing_by_device[dev_id] = ec

                # Build index of use_as_proxy proxy IPs
                if ec.proxy_condition == "use_as_proxy":
                    for ip in ec.proxy_ips:
                        proxy_index[ip] = proxy_index.get(ip, 0) + 1

        self.existing_by_device = existing_by_device
        self.proxy_index = proxy_index

        LOGGER.debug(
            "Fetched existing: collectors=%d, proxy_index(use_as_proxy IPs)=%d",
            len(existing_by_device),
            len(proxy_index),
        )

    def diff(self) -> None:
        """
        Compute decisions for each desired item against existing (NOOP/UPDATE/CREATE),
        without executing any mutation (actual apply happens in phases).
        """
        decisions: Dict[str, str] = {}  # device_id -> "noop"|"update"|"create"
        diffs: Dict[str, Dict[str, Tuple[Any, Any]]] = {}

        for item in self.desired:
            existing = self.existing_by_device.get(item.device_id)

            if existing is None:
                decisions[item.device_id] = "create"
                diffs[item.device_id] = {}
                continue

            # Canonical compare
            desired_tuple = self._canon_tuple(item)
            existing_tuple = (
                existing.proxy_condition,
                existing.parser,
                existing.charset,
                tuple(sorted(existing.proxy_ips)),
                tuple(sorted(existing.hostnames)),
                existing.processpolicy_id,
            )

            if desired_tuple == existing_tuple:
                decisions[item.device_id] = "noop"
                diffs[item.device_id] = {}
            else:
                decisions[item.device_id] = "update"
                diffs[item.device_id] = self._compute_diff_map(desired_tuple, existing_tuple)

        self.decisions = decisions
        self.diffs = diffs

    def apply(self) -> None:
        """
        Orchestrate Phases A → B → C with barriers and (re-)inventory.

        - Phase A (use_as_proxy): apply all create/update; re-inventory.
        - Phase B (None): apply all create/update; optional re-inventory.
        - Phase C (uses_proxy): only apply rows whose proxy_ip are present
          on target (proxy_index) after Phase A; otherwise SKIP.
        """
        if not self.desired:
            return

        # Phase 1: use_as_proxy
        self._apply_phase(self.partition["A"], phase="A")

        # Barrier + re-inventory
        self._re_inventory()

        # Phase 2: None
        self._apply_phase(self.partition["B"], phase="B")

        # Optional barrier (cheap inventory may be skipped), but keep it for safety
        self._re_inventory()

        # Phase 3: uses_proxy
        self._apply_phase(self.partition["C"], phase="C", enforce_proxy=True)

    # ------------------------------ Internals ---------------------------------

    # ---- Helpers: API resolutions ----

    def _resolve_device_ids(self, device_names: Iterable[str]) -> Dict[str, str]:
        """
        Resolve device_name -> device_id by listing devices on the target node.
        """
        client: DirectorClient = self.client
        pool_uuid = self.ctx.pool_uuid
        node_id = self.ctx.node_id

        name_to_id: Dict[str, str] = {}
        try:
            devices = client.list_resource(pool_uuid, node_id, "Devices") or []
        except Exception as exc:  # noqa: BLE001
            LOGGER.error("Failed listing Devices: %s", exc, exc_info=LOGGER.isEnabledFor(logging.DEBUG))
            return name_to_id

        # Build normalized map
        normalized_lookup = {str(d.get("name", "")).strip(): str(d.get("id", "")).strip() for d in devices}
        for name in device_names:
            dev_id = normalized_lookup.get(name)
            if dev_id:
                name_to_id[name] = dev_id
        LOGGER.debug("Resolved device ids: %d/%d", len(name_to_id), len(set(device_names)))
        return name_to_id

    def _load_pp_source_id_to_name(self) -> Dict[str, str]:
        """
        Load the ProcessingPolicies sheet (source view) to map source PP id -> name.
        If sheet is absent, return empty mapping.
        """
        try:
            sheet = self.load_sheet("ProcessingPolicies")
        except Exception:
            sheet = None

        mapping: Dict[str, str] = {}
        if sheet is None or sheet.empty:
            return mapping

        # Accept common column names
        id_col = None
        for candidate in ("id", "pp_id", "policy_id"):
            if candidate in sheet.columns:
                id_col = candidate
                break
        name_col = None
        for candidate in ("policy_name", "name"):
            if candidate in sheet.columns:
                name_col = candidate
                break

        if not id_col or not name_col:
            return mapping

        for _, row in sheet.iterrows():
            src_id = str(row.get(id_col, "")).strip()
            name = str(row.get(name_col, "")).strip()
            if src_id and name:
                mapping[src_id] = name
        LOGGER.debug("Loaded PP source id->name mappings: %d", len(mapping))
        return mapping

    def _resolve_pp_name_to_target_id(self, names: Iterable[str]) -> Dict[str, str]:
        """
        Resolve PP name -> target PP id on the current node.
        """
        if not names:
            return {}

        client: DirectorClient = self.client
        pool_uuid = self.ctx.pool_uuid
        node_id = self.ctx.node_id

        try:
            pps = client.list_resource(pool_uuid, node_id, "ProcessingPolicy") or []
        except Exception as exc:  # noqa: BLE001
            LOGGER.error(
                "ProcessingPolicy API unavailable: %s", exc, exc_info=LOGGER.isEnabledFor(logging.DEBUG)
            )
            return {}

        by_name: Dict[str, str] = {}
        for pp in pps:
            name = str(pp.get("policy_name", "") or pp.get("name", "")).strip()
            pp_id = str(pp.get("id", "")).strip()
            if name and pp_id:
                by_name[name] = pp_id

        resolved = {n: by_name[n] for n in set(names) if n in by_name}
        LOGGER.debug("Resolved PP names: %d/%d", len(resolved), len(set(names)))
        return resolved

    def _fetch_known_charsets(self) -> Set[str]:
        """
        (Optional) Fetch known charsets from API, non-fatal if unavailable.
        """
        client: DirectorClient = self.client
        pool_uuid = self.ctx.pool_uuid
        node_id = self.ctx.node_id
        try:
            data = client.list_resource(pool_uuid, node_id, "Charsets") or []
        except Exception:
            return set()
        result = {str(x).strip() for x in data if isinstance(x, str)}
        return result

    # ---- Helpers: comparison, diffs, normalization ----

    @staticmethod
    def _normalize_list(raw: str) -> List[str]:
        """
        Split a list-like cell value on comma or pipe, trim, deduplicate, sort.
        """
        if not raw:
            return []
        parts = []
        for chunk in raw.replace("|", ",").split(","):
            s = chunk.strip()
            if s:
                parts.append(s)
        return sorted(set(parts))

    @staticmethod
    def _canon_tuple(item: DesiredCollector) -> Tuple[Any, ...]:
        return (
            item.proxy_condition,
            item.parser,
            item.charset,
            item.proxy_ips,
            item.hostnames,
            item.processpolicy_id,
        )

    @staticmethod
    def _compute_diff_map(
        desired_tuple: Tuple[Any, ...], existing_tuple: Tuple[Any, ...]
    ) -> Dict[str, Tuple[Any, Any]]:
        keys = ("proxy_condition", "parser", "charset", "proxy_ips", "hostnames", "processpolicy_id")
        out: Dict[str, Tuple[Any, Any]] = {}
        for i, k in enumerate(keys):
            if desired_tuple[i] != existing_tuple[i]:
                out[k] = (existing_tuple[i], desired_tuple[i])
        return out

    # ---- Helpers: Phase orchestration ----

    def _apply_phase(self, items: List[DesiredCollector], phase: str, enforce_proxy: bool = False) -> None:
        """
        Apply a phase: plan → (create/update/noop) respecting dry-run mode.
        """
        if not items:
            LOGGER.info("Phase %s: no items.", phase)
            return

        created = updated = noop = skipped = 0

        for item in items:
            # Enforce proxy existence for uses_proxy in Phase C
            if enforce_proxy and item.proxy_condition == "uses_proxy":
                missing = [ip for ip in item.proxy_ips if self.proxy_index.get(ip, 0) <= 0]
                if missing:
                    self._add_row(
                        result="skip",
                        action="Skip: missing dependency (proxy)",
                        error="E-SC-DEP-002 " + ", ".join(f'MissingProxy: proxy_ip="{ip}"' for ip in missing),
                        device=item.device_name,
                    )
                    skipped += 1
                    continue

            existing = self.existing_by_device.get(item.device_id)
            decision = (
                "create"
                if existing is None
                else ("noop" if self._canon_tuple(item) == self._canon_tuple_from_existing(existing) else "update")
            )

            if decision == "noop":
                self._add_row(result="noop", action="Identical", device=item.device_name)
                noop += 1
                continue

            if self.ctx.dry_run:
                self._add_row(result=decision, action=f"would {decision}", device=item.device_name)
                if decision == "create":
                    created += 1
                else:
                    updated += 1
                continue

            try:
                if decision == "create":
                    self._create(item)
                    created += 1
                else:
                    self._update(item, existing)
                    updated += 1
            except Exception as exc:  # noqa: BLE001
                self._add_row(
                    result="skip",
                    action=f"Skip: {decision} failed",
                    error=f"E-SC-API Fail: {exc}",
                    device=item.device_name,
                )
                LOGGER.error("Phase %s %s failed for device=%s: %s", phase, decision, item.device_name, exc,
                             exc_info=LOGGER.isEnabledFor(logging.DEBUG))
                skipped += 1

        LOGGER.info("Phase %s summary: create=%d update=%d noop=%d skip=%d", phase, created, updated, noop, skipped)

    def _re_inventory(self) -> None:
        """Barrier: (wait monitors handled by DirectorClient), then re-inventory."""
        # DirectorClient monitor handling is expected in create/update helpers.
        # Here we just rebuild existing_by_device and proxy_index.
        self.fetch_existing()
        LOGGER.debug("Re-inventory complete after barrier.")

    @staticmethod
    def _canon_tuple_from_existing(existing: ExistingCollector) -> Tuple[Any, ...]:
        return (
            existing.proxy_condition,
            existing.parser,
            existing.charset,
            tuple(sorted(existing.proxy_ips)),
            tuple(sorted(existing.hostnames)),
            existing.processpolicy_id,
        )

    # ---- Helpers: CRUD ----

    def _create(self, item: DesiredCollector) -> None:
        """POST SyslogCollector payload."""
        client: DirectorClient = self.client
        pool_uuid = self.ctx.pool_uuid
        node_id = self.ctx.node_id

        payload = self._build_payload(item)
        LOGGER.debug("Create payload for device=%s: %s", item.device_name, payload)

        monitor = client.create_resource(pool_uuid, node_id, self.resource_name, payload)
        self._record_monitor(item.device_name, result="create", monitor=monitor)

        # Update local cache (best-effort): reflect as existing
        self.existing_by_device[item.device_id] = ExistingCollector(
            device_id=item.device_id,
            collector_id=None,  # unknown until next inventory
            proxy_condition=item.proxy_condition,
            parser=item.parser,
            charset=item.charset,
            proxy_ips=item.proxy_ips,
            hostnames=item.hostnames,
            processpolicy_id=item.processpolicy_id,
        )

        # If we created a use_as_proxy, update proxy_index immediately
        if item.proxy_condition == "use_as_proxy":
            for ip in item.proxy_ips:
                self.proxy_index[ip] = self.proxy_index.get(ip, 0) + 1

    def _update(self, item: DesiredCollector, existing: ExistingCollector) -> None:
        """PUT SyslogCollector/{id} payload."""
        client: DirectorClient = self.client
        pool_uuid = self.ctx.pool_uuid
        node_id = self.ctx.node_id

        if not existing or not existing.collector_id:
            # If id is missing, rely on re-inventory; but normally Devices/{id}/plugins returns uuid
            raise RuntimeError("Existing collector id is missing; cannot perform PUT.")

        payload = self._build_payload(item)
        LOGGER.debug(
            "Update payload for device=%s (collector_id=%s): %s",
            item.device_name,
            existing.collector_id,
            payload,
        )

        monitor = client.update_resource(pool_uuid, node_id, self.resource_name, existing.collector_id, payload)
        self._record_monitor(item.device_name, result="update", monitor=monitor)

        # Update local cache
        existing.proxy_condition = item.proxy_condition
        existing.parser = item.parser
        existing.charset = item.charset
        existing.proxy_ips = item.proxy_ips
        existing.hostnames = item.hostnames
        existing.processpolicy_id = item.processpolicy_id

    @staticmethod
    def _build_payload(item: DesiredCollector) -> Dict[str, Any]:
        """
        Build POST/PUT payload conforming to the API matrix.
        Device context only.
        """
        base = {
            "device_id": item.device_id,
            "proxy_condition": item.proxy_condition,
            "parser": item.parser,
            "charset": item.charset,
        }

        if item.proxy_condition == "use_as_proxy":
            # must be empty: proxy_ip, hostname, processpolicy
            return base

        if item.proxy_condition == "None":
            # require processpolicy id, must be empty: proxy sets
            base["processpolicy"] = item.processpolicy_id
            return base

        # uses_proxy
        base["processpolicy"] = item.processpolicy_id
        if item.proxy_ips:
            base["proxy_ip"] = list(item.proxy_ips)
        if item.hostnames:
            base["hostname"] = list(item.hostnames)
        return base

    # ---- Helpers: reporting ----

    def _add_row(
        self,
        *,
        result: str,
        action: str,
        device: str,
        error: Optional[str] = None,
        status: Optional[str] = None,
        monitor_ok: Optional[bool] = None,
        monitor_branch: Optional[str] = None,
    ) -> None:
        """
        Adapter to the common reporting row structure used by the framework.
        """
        row = {
            "siem": self.ctx.siem_id,
            "node": self.ctx.node_name,
            "name": device,
            "result": result,
            "action": action,
            "status": status or "—",
            "monitor_ok": "—" if monitor_ok is None else monitor_ok,
            "monitor_branch": monitor_branch or "—",
            "error": error or "—",
            "corr": "—",
        }
        self.rows.append(row)

    def _record_monitor(self, device_name: str, *, result: str, monitor: Any) -> None:
        """
        Standardized monitor recording into the report row. The DirectorClient
        returns a monitor object/URL; we reflect it in the table like other importers.
        """
        ok, branch, status = self._parse_monitor(monitor)
        self._add_row(
            result=result,
            action=result.capitalize(),
            device=device_name,
            status=status,
            monitor_ok=ok,
            monitor_branch=branch,
        )

    @staticmethod
    def _parse_monitor(monitor: Any) -> Tuple[bool, str, str]:
        """
        Extract a (ok, branch, status) tuple from the monitor result.
        Compatible with the common DirectorClient helper semantics.
        """
        if monitor is None:
            return True, "—", "—"
        # The actual structure depends on DirectorClient; keep this generic.
        ok = True
        branch = str(monitor.get("monitor_url") or monitor.get("branch") or "—")
        status = str(monitor.get("status") or "OK")
        return ok, branch, status

    def _report_skip(self, idx: int, device_name: str, code: str, msg: str) -> None:
        LOGGER.debug("Row %s device=%s SKIP: %s %s", idx, device_name, code, msg)
        self._add_row(result="skip", action="Skip: validation", device=device_name, error=f"{code} {msg}")
