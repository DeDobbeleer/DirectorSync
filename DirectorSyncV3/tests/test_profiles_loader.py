import json
from pathlib import Path

from directorsync_v3.core.profiles import ProfileLoader


def test_load_and_inherit_defaults(tmp_path, monkeypatch):
    base = tmp_path / "resources" / "profiles"
    base.mkdir(parents=True)
    (base / "_defaults.yml").write_text(
        "version: 1\ndiff:\n  ignore_fields: [id, updated_at]\n",
        encoding="utf-8",
    )
    (base / "repos.yml").write_text(
        """
version: 1
extends: "_defaults"
resource: "repositories"
endpoint:
  list: "/x"
  create: "/x"
  update: "/x/{id}"
identity:
  id_field: "id"
  name_field: "name"
  natural_key: ["name"]
xlsx:
  mapping:
    name: { col: "Name", transform: ["norm_str"] }
payload:
  name: "${name}"
""",
        encoding="utf-8",
    )

    pl = ProfileLoader(search_paths=[str(base)])
    prof = pl.load("repos")

    # Mapping, payload, identity
    mapped = prof.map_row({"Name": "  Repo A  "})
    assert mapped["name"] == "Repo A"
    payload = prof.build_payload(mapped)
    assert payload["name"] == "Repo A"
    assert prof.natural_key == ["name"]

    # Diff ignore_fields inherited
    current = {"id": 1, "name": "Repo A", "updated_at": "x"}
    desired = {"name": "Repo A"}
    assert prof.make_comparable(current) == prof.make_comparable(desired)


def test_transforms_split_uniq_sort_and_csv(tmp_path):
    base = tmp_path / "resources" / "profiles"
    base.mkdir(parents=True)
    (base / "_defaults.yml").write_text("version: 1\n", encoding="utf-8")
    (base / "p.yml").write_text(
        """
version: 1
extends: "_defaults"
resource: "tags"
endpoint: { list: "/t", create: "/t", update: "/t/{id}" }
identity: { id_field: "id", name_field: "name", natural_key: ["name"] }
xlsx:
  mapping:
    name: { col: "Name" }
    tags:
      expr: "${T};${U}"
      transform:
        - { fn: "split", sep: ";" }
        - "uniq"
        - "sort"
        - { fn: "csv", sep: "|" }
payload:
  name: "${name}"
  tags_csv: "${tags}"
""",
        encoding="utf-8",
    )

    pl = ProfileLoader(search_paths=[str(base)])
    prof = pl.load("p")

    mapped = prof.map_row({"Name": "X", "T": "b;a", "U": "a;c"})
    # tags goes through split->uniq->sort->csv
    assert mapped["tags"] == "a|b|c"
    payload = prof.build_payload(mapped)
    assert payload["tags_csv"] == "a|b|c"


def test_prechecks_and_diff_sets(tmp_path):
    base = tmp_path / "resources" / "profiles"
    base.mkdir(parents=True)
    (base / "_defaults.yml").write_text(
        """
version: 1
diff:
  list_as_sets: ["items"]
  ignore_fields: []
""",
        encoding="utf-8",
    )
    (base / "p.yml").write_text(
        """
version: 1
extends: "_defaults"
resource: "demo"
endpoint: { list: "/d", create: "/d", update: "/d/{id}" }
identity: { id_field: "id", name_field: "name", natural_key: ["name"] }
xlsx:
  mapping:
    name: { col: "Name", transform: ["norm_str"] }
    items: { expr: "${A};${B}", transform: [ {fn: "split", sep: ";"}, "uniq" ] }
prechecks:
  - { type: "non_empty", field: "name" }
  - { type: "must_exist_many", field: "items" }
payload:
  name: "${name}"
  items: "${items}"
""",
        encoding="utf-8",
    )

    pl = ProfileLoader(search_paths=[str(base)])
    prof = pl.load("p")

    # Precheck OK
    mapped = prof.map_row({"Name": " X ", "A": "b;a", "B": "a"})
    ok, reason = prof.precheck(mapped)
    assert ok and reason == ""
    desired = prof.build_payload(mapped)
    # Diff: items compared as sets (sorted)
    current = {"name": "X", "items": ["a", "b"]}
    assert prof.make_comparable(current) == prof.make_comparable(desired)

    # Precheck KO: empty name
    mapped2 = prof.map_row({"Name": "   ", "A": "", "B": ""})
    ok2, reason2 = prof.precheck(mapped2)
    assert not ok2 and "name" in reason2
