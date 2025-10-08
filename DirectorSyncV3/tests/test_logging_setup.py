import os
from pathlib import Path

from directorsync_v3.core.logging_setup import build_logger


def test_logger_creates_files_and_redacts(tmp_path, monkeypatch):
    # Keep logs under tmp
    monkeypatch.chdir(tmp_path)

    logger = build_logger(
        name="ds",
        run_id="run123",
        action="repositories",
        base_dir="logs",
        console_level="INFO",
        file_level="DEBUG",
        extra={"tenant": "t1", "pool": "p1", "profile": "repos"},
    )

    # Emit messages with secrets
    logger.info("hello Authorization: Bearer abc123")
    logger.error("password=secret-x, token: tkn999 | api_key=AKIA123")

    # Check files exist
    app_log = Path("logs/app.log")
    assert app_log.exists()

    # Daily action-based file (subdir YYYY-MM-DD)
    dated_dirs = list(Path("logs").glob("20*"))
    assert dated_dirs, "dated directory not created"
    files = list(dated_dirs[0].glob("repositories_run123.log"))
    assert files, "action-based log file not created"

    # Redaction present in both files
    content = app_log.read_text(encoding="utf-8")
    assert "***REDACTED***" in content
    assert "abc123" not in content and "secret-x" not in content and "AKIA123" not in content

    action_content = files[0].read_text(encoding="utf-8")
    assert "***REDACTED***" in action_content
    assert "tkn999" not in action_content


def test_rotating_file_captures_debug(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    logger = build_logger(
        name="ds_test2",
        run_id="r42",
        action="proc",
        base_dir="logs",
        console_level="INFO",
        file_level="DEBUG",
    )
    logger.debug("debug-line-42")
    content = Path("logs/app.log").read_text(encoding="utf-8")
    assert "DEBUG" in content and "debug-line-42" in content
