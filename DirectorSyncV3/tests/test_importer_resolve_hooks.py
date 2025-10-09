from pathlib import Path

from directorsync_v3.core.importer import GenericImporter
from directorsync_v3.core.profiles import ProfileLoader


def _profile_with_resolve(base: Path) -> None:
    (base / "_defaults.yml").write_text(
        """
version: 1
diff:
  list_as_sets: ["policy_ids"]
  ignore_fields: []
""",
        encoding="utf-8",
    )
    (base / "pp.yml").write_text(
        """
version: 1
extends: "_defaults"
resource: "policies"
endpoint: { list: "/p", create: "/p", update: "/p/{id}" }
identity: { id_field: "id", name_field: "name", natural_key: ["name"] }
xlsx:
  mapping:
    name:       { col: "Name", transform: ["norm_str"] }
    node_name:  { col: "Node", transform: ["norm_str"] }
    pol_names:  { expr: "${P1};${P2}", transform: [ {fn: "split", sep: ";"}, "uniq", "sort" ] }
resolve:
  node_id:
    from: "nodes"
    lookup: { by: "name", using: "${node_name}" }
  policy_ids:
    from: "policies"
    lookup_many: { by: "name", using: "${pol_names}" }
prechecks:
  - { type: "non_empty", field: "name" }
  - { type: "must_exist_many", field: "policy_ids", min: 2 }
hooks:
  preprocess_row: "make_upper"
  post_payload:   "add_flag"
payload:
  name: "${name}"
  node_id: "${node_id}"
  policy_ids: "${policy_ids}"
  flag: "unset"   # will be overridden by post_payload
""",
        encoding="utf-8",
    )


def test_resolve_and_hooks_and_cache(tmp_path, monkeypatch):
    base = tmp_path / "resources" / "profiles"
    base.mkdir(parents=True)
    _profile_with_resolve(base)

    pl = ProfileLoader(search_paths=[str(base)])
    prof = pl.load("pp")

    # In-memory inventories + call counters (cache should limit calls to 1 per inventory)
    calls = {"nodes": 0, "policies": 0}
    inventories = {
        "nodes": [
            {"id": "N1", "name": "ALPHA"},
            {"id": "N2", "name": "BETA"},
        ],
        "policies": [
            {"id": "P1", "name": "a"},
            {"id": "P2", "name": "b"},
            {"id": "P3", "name": "c"},
        ],
    }

    def provider(name: str):
        calls[name] += 1
        return inventories.get(name, [])

    # Hooks registry
    def make_upper(mapped):
        # Uppercase the 'name' to match remote natural key
        mapped = dict(mapped)
        if "name" in mapped and isinstance(mapped["name"], str):
            mapped["name"] = mapped["name"].upper()
        return mapped

    def add_flag(payload, mapped):
        payload = dict(payload)
        payload["flag"] = "ok"
        return payload

    importer = GenericImporter(
        prof,
        inventories=provider,
        hooks={"make_upper": make_upper, "add_flag": add_flag},
    )

    # Input rows
    rows = [
        {"Name": "alpha", "Node": "ALPHA", "P1": "a", "P2": "b"},  # CREATED
        {"Name": "beta",  "Node": "BETA",  "P1": "a", "P2": "c"},  # UPDATED (policies differ)
        {"Name": "gamma", "Node": "BETA",  "P1": "a", "P2": ""},   # SKIP (must_exist_many fails)
    ]

    # Remote items (note: names are already uppercased by hook)
    remote = [
        {"name": "BETA", "node_id": "N2", "policy_ids": ["a", "b"], "flag": "ok"},
        {"name": "GAMMA", "node_id": "N2", "policy_ids": ["a", "b"], "flag": "ok"},
    ]

    results, counts = importer.run(rows, remote)

    # Cache: each inventory fetched once
    assert calls["nodes"] == 1 and calls["policies"] == 1

    # Status counts
    assert counts["CREATED"] == 1
    assert counts["UPDATED"] == 1
    assert counts["SKIP"] == 1
    assert "UNCHANGED" not in counts

    # Row by row
    assert results[0].status == "CREATED" and results[0].natural_key == ("ALPHA",)
    assert results[1].status == "UPDATED" and results[1].natural_key == ("BETA",)
    assert results[2].status == "SKIP"

def test_hook_failure_marks_error(tmp_path):
    base = tmp_path / "resources" / "profiles"
    base.mkdir(parents=True)
    (base / "_defaults.yml").write_text("version: 1\n", encoding="utf-8")
    (base / "h.yml").write_text(
        """
version: 1
extends: "_defaults"
resource: "hooked"
endpoint: { list: "/h", create: "/h", update: "/h/{id}" }
identity: { id_field: "id", name_field: "name", natural_key: ["name"] }
xlsx:
  mapping:
    name: { col: "Name" }
hooks:
  preprocess_row: "boom"
payload:
  name: "${name}"
""",
        encoding="utf-8",
    )

    pl = ProfileLoader(search_paths=[str(base)])
    prof = pl.load("h")

    def boom(mapped):
        raise ValueError("boom!")

    importer = GenericImporter(prof, hooks={"boom": boom})

    rows = [{"Name": "X"}]
    remote = []

    results, counts = importer.run(rows, remote)
    assert counts["ERROR"] == 1
    assert results[0].status == "ERROR" and "boom!" in results[0].error
