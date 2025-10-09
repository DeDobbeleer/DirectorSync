from pathlib import Path

from directorsync_v3.core.importer import GenericImporter
from directorsync_v3.core.profiles import ProfileLoader
from directorsync_v3.core.logging_setup import build_logger


def _write_profile(base: Path) -> None:
    (base / "_defaults.yml").write_text(
        """
version: 1
diff:
  list_as_sets: ["items"]
  ignore_fields: []
""",
        encoding="utf-8",
    )
    (base / "demo.yml").write_text(
        """
version: 1
extends: "_defaults"
resource: "demo"
endpoint: { list: "/d", create: "/d", update: "/d/{id}" }
identity: { id_field: "id", name_field: "name", natural_key: ["name"] }
xlsx:
  mapping:
    name:  { col: "Name", transform: ["norm_str"] }
    items: { expr: "${A};${B}", transform: [ {fn: "split", sep: ";"}, "uniq" ] }
    age:   { col: "Age" }
prechecks:
  - { type: "non_empty", field: "name" }
payload:
  name:  "${name}"
  items: "${items}"
  age:   "${age}"
""",
        encoding="utf-8",
    )


def test_importer_create_update_unchanged_skip_error(tmp_path, monkeypatch):
    base = tmp_path / "resources" / "profiles"
    base.mkdir(parents=True)
    _write_profile(base)

    pl = ProfileLoader(search_paths=[str(base)])
    prof = pl.load("demo")

    # Logger under tmp (noisy output avoided in console by test runner)
    monkeypatch.chdir(tmp_path)
    logger = build_logger(
        name="ds_step5",
        run_id="r1",
        action="demo",
        base_dir="logs",
        console_level="INFO",
        file_level="DEBUG",
        extra={"tenant": "t", "pool": "p", "profile": "demo"},
    )

    importer = GenericImporter(prof, logger=logger)

    # Input rows
    rows = [
        # -> CREATED (no remote)
        {"Name": "Alpha", "A": "x;y", "B": "y", "Age": "33"},
        # -> UPDATED (remote exists but items differ ignoring order)
        {"Name": "Beta", "A": "b;a", "B": "", "Age": "40"},
        # -> UNCHANGED (same after normalization)
        {"Name": "Gamma", "A": "c;d", "B": "d", "Age": "50"},
        # -> SKIP (empty name after norm_str)
        {"Name": "   ", "A": "", "B": "", "Age": "10"},
    ]

    # Remote items (as if from API)
    remote = [
        {"name": "Beta", "items": ["a", "c"], "age": "40"},          # differs (missing a-> ok, but has c)
        {"name": "Gamma", "items": ["c", "d"], "age": "50"},         # same (set compare)
    ]

    results, counts = importer.run(rows, remote)

    # Status distribution
    assert counts["CREATED"] == 1
    assert counts["UPDATED"] == 1
    assert counts["UNCHANGED"] == 1
    assert counts["SKIP"] == 1
    assert "ERROR" not in counts and "EXCEPTION" not in counts

    # Order and keys
    assert results[0].status == "CREATED" and results[0].natural_key == ("Alpha",)
    assert results[1].status == "UPDATED" and results[1].natural_key == ("Beta",)
    assert results[2].status == "UNCHANGED" and results[2].natural_key == ("Gamma",)
    assert results[3].status == "SKIP"

    # Logs written to files
    assert (tmp_path / "logs/app.log").exists()


def test_importer_row_error_and_exception(tmp_path):
    # Build a profile that forces a transform error (to_int on 'age' with non-numeric)
    base = tmp_path / "resources" / "profiles"
    base.mkdir(parents=True)
    (base / "_defaults.yml").write_text("version: 1\n", encoding="utf-8")
    (base / "err.yml").write_text(
        """
version: 1
extends: "_defaults"
resource: "err"
endpoint: { list: "/d", create: "/d", update: "/d/{id}" }
identity: { id_field: "id", name_field: "name", natural_key: ["name"] }
xlsx:
  mapping:
    name: { col: "Name", transform: ["norm_str"] }
    age:  { col: "Age", transform: ["to_int"] }
prechecks:
  - { type: "non_empty", field: "name" }
payload:
  name: "${name}"
  age: "${age}"
""",
        encoding="utf-8",
    )

    pl = ProfileLoader(search_paths=[str(base)])
    prof = pl.load("err")
    importer = GenericImporter(prof)  # null logger

    rows = [
        {"Name": "X", "Age": "NaN"},     # TransformError -> ERROR
        {"Name": "Y", "Age": "20"},      # OK (no remote) -> CREATED
    ]
    remote = []

    results, counts = importer.run(rows, remote)

    assert counts["ERROR"] == 1
    assert counts["CREATED"] == 1
    assert results[0].status == "ERROR" and "Cannot convert to int" in results[0].error
