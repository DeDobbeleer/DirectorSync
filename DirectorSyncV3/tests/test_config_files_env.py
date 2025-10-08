import os
import textwrap

from directorsync_v3.core.config import load_config


def test_file_then_env_then_cli_precedence(tmp_path, monkeypatch):
    # Create config file
    (tmp_path / "directorsync.yml").write_text(textwrap.dedent("""
      director:
        base_url: "https://file.example"
        token: "FILE"
      logging:
        console_level: "WARNING"
      context:
        tenant: "file_tenant"
        pool_uuid: "pool_file"
    """), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    # Env override
    monkeypatch.setenv("DSYNC_DIRECTOR__BASE_URL", "https://env.example")
    monkeypatch.setenv("DSYNC_DIRECTOR__VERIFY_TLS", "false")

    # CLI override
    cfg = load_config(
        {"director": {"base_url": "https://cli.example"}},
        files=(str(tmp_path / "directorsync.yml"),),
    )

    assert cfg.director.base_url == "https://cli.example"   # CLI wins
    assert cfg.director.verify_tls is False                  # env coerced to bool
    assert cfg.logging.console_level == "WARNING"            # from file
    assert cfg.context.tenant == "file_tenant"               # from file (not overridden)


def test_env_interpolation(tmp_path, monkeypatch):
    (tmp_path / "directorsync.yml").write_text(textwrap.dedent("""
      director:
        token: "${MY_TOKEN}"
    """), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MY_TOKEN", "SECRET_123")
    # Run in dry_run so required fields are not mandatory for this unit test
    cfg = load_config({"app": {"dry_run": True}}, files=(str(tmp_path / "directorsync.yml"),))    
    assert cfg.director.token == "SECRET_123"


def test_required_fields_validation_non_dry_run(tmp_path, monkeypatch):
    (tmp_path / "directorsync.yml").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    # Not dry_run; required keys must be present
    try:
        load_config({"app": {"dry_run": False}}, files=(str(tmp_path / "directorsync.yml"),))
    except ValueError as exc:
        msg = str(exc)
        assert "director.base_url" in msg and "context.tenant" in msg and "context.pool_uuid" in msg
    else:
        raise AssertionError("Expected ValueError for missing required keys")
