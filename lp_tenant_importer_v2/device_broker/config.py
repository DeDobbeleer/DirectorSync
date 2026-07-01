"""Configuration helpers: .env parser, pools.json loader, and logging setup."""

import datetime
import json
import logging
import sys
from pathlib import Path


class ConfigurationError(Exception):
    """Raised when a configuration file is missing or invalid."""


def load_env(env_path: str) -> dict:
    """Parse a simple KEY=VALUE .env file (no external dependencies).

    Lines starting with '#' or empty lines are ignored.
    Values are stripped of surrounding whitespace.
    Raises ConfigurationError if the file does not exist.
    """
    path = Path(env_path)
    if not path.is_file():
        raise ConfigurationError(f"Environment file not found: {env_path}")

    env = {}
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()

    required = ("LP_DIRECTOR_URL", "LP_DIRECTOR_API_TOKEN")
    missing = [k for k in required if not env.get(k)]
    if missing:
        raise ConfigurationError(
            f"Missing required variables in {env_path}: {', '.join(missing)}"
        )

    return env


def load_pools(pools_path: str) -> list[dict]:
    """Load the pools.json configuration file.

    Expected top-level structure:
    {
        "pools": [
            {
                "name": "...",
                "pool_uuid": "...",
                "nodes": [
                    {"name": "...", "node_id": "..."}
                ]
            }
        ]
    }
    """
    path = Path(pools_path)
    if not path.is_file():
        raise ConfigurationError(f"Pools file not found: {pools_path}")

    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    if not isinstance(data, dict) or "pools" not in data:
        raise ConfigurationError(
            f"Invalid pools file '{pools_path}': missing top-level 'pools' key"
        )

    pools = data["pools"]
    if not isinstance(pools, list):
        raise ConfigurationError(
            f"Invalid pools file '{pools_path}': 'pools' must be a list"
        )

    for idx, pool in enumerate(pools):
        if not isinstance(pool, dict):
            raise ConfigurationError(
                f"Invalid pool at index {idx}: must be an object"
            )
        if not pool.get("pool_uuid"):
            raise ConfigurationError(
                f"Pool at index {idx} is missing 'pool_uuid'"
            )
        nodes = pool.get("nodes", [])
        if not isinstance(nodes, list):
            raise ConfigurationError(
                f"Pool '{pool.get('name', idx)}': 'nodes' must be a list"
            )
        for nidx, node in enumerate(nodes):
            if not isinstance(node, dict) or not node.get("node_id"):
                raise ConfigurationError(
                    f"Pool '{pool.get('name', idx)}': node at index {nidx} "
                    f"is missing 'node_id'"
                )

    return pools


def setup_logging(log_dir: str) -> logging.Logger:
    """Configure file + console logging.

    File receives DEBUG level; console receives INFO level.
    Returns the root logger for device_broker.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_path / f"device_broker_{timestamp}.log"

    logger = logging.getLogger("device_broker")
    logger.setLevel(logging.DEBUG)
    logger.handlers = []

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s | %(message)s"
    )

    # File handler
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logger.info("Logging initialized. Log file: %s", log_file)
    return logger
