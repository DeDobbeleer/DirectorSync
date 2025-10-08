from directorsync_v3.core.config import load_config


def test_defaults_and_run_id_generated():
    # In unit tests we run in dry_run to avoid requiring base_url/tenant/pool
    cfg = load_config({"app": {"dry_run": True}})
    assert cfg.logging.console_level == "INFO"
    rid1 = cfg.run_id
    rid2 = cfg.run_id
    assert isinstance(rid1, str) and len(rid1) >= 8
    assert rid1 == rid2  # stable once generated


def test_cli_overrides_take_precedence():
    cfg = load_config({
        "context": {"tenant": "acme", "pool_uuid": "0000"},
        "app": {"dry_run": True, "concurrency": 8},
        "logging": {"console_level": "WARNING"},
    })
    assert cfg.context.tenant == "acme"
    assert cfg.app.dry_run is True
    assert cfg.app.concurrency == 8
    assert cfg.logging.console_level == "WARNING"