from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping

from .profiles import ResourceProfile


def build_payloads(
    profile: ResourceProfile,
    items: Iterable[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Generic payload builder driven entirely by profile.mapping.

    - Simple field mappings use mapping.desired_to_api.
    - Array/list mappings use mapping.arrays, where each entry
      describes:
        - 'source': the name of the collection in the item
        - 'dest': the name of the array in the API payload
        - 'fields': per-field mapping from item to payload.
    """
    mapping_cfg = profile.mapping
    field_map: Mapping[str, str] = mapping_cfg.get("desired_to_api", {})
    arrays_cfg: Iterable[Mapping[str, Any]] = mapping_cfg.get("arrays", []) or []

    payloads: List[Dict[str, Any]] = []

    for item in items:
        payload: Dict[str, Any] = {}

        # 1) Simple field mappings
        for src_field, dest_field in field_map.items():
            if src_field in item and item[src_field] is not None:
                payload[dest_field] = item[src_field]

        # 2) Array/list mappings
        for array_cfg in arrays_cfg:
            source_name = str(array_cfg.get("source"))
            dest_name = str(array_cfg.get("dest"))
            field_mappings: Mapping[str, str] = array_cfg.get("fields", {})

            collection = item.get(source_name) or []
            if not isinstance(collection, Iterable):
                # Be defensive: skip if the collection is not iterable
                continue

            array_values: List[Dict[str, Any]] = []
            for element in collection:
                if not isinstance(element, Mapping):
                    continue
                elem_payload: Dict[str, Any] = {}
                for src_field, dest_field in field_mappings.items():
                    if src_field in element and element[src_field] is not None:
                        elem_payload[dest_field] = element[src_field]
                array_values.append(elem_payload)

            payload[dest_name] = array_values

        payloads.append(payload)

    return payloads
