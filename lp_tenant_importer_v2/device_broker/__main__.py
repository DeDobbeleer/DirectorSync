"""CLI entry point for the Device Broker."""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

# Support both `python __main__.py` and `python -m package.module` styles
if not __package__:
    from config import ConfigurationError, load_env, load_pools, setup_logging
    from client import APIError, DirectorAPIClient
    from manager import DeviceManager
else:
    from .config import ConfigurationError, load_env, load_pools, setup_logging
    from .client import APIError, DirectorAPIClient
    from .manager import DeviceManager


def cmd_list(args: argparse.Namespace) -> int:
    """List devices and export them to a TSV file."""
    try:
        env = load_env(args.env_file)
        pools = load_pools(args.pools_file)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    logger = setup_logging(args.log_dir)
    client = DirectorAPIClient(
        env["LP_DIRECTOR_URL"],
        env["LP_DIRECTOR_API_TOKEN"],
        verify_ssl=not args.no_verify_ssl,
    )
    manager = DeviceManager(client, logger)

    fieldnames = [
        "pool_uuid",
        "node_id",
        "device_id",
        "device_name",
        "ip",
        "device_groups",
        "delete",
    ]
    rows: list[dict] = []

    for pool in pools:
        pool_uuid = pool["pool_uuid"]
        for node in pool.get("nodes", []):
            node_id = node["node_id"]
            node_name = node.get("name", node_id)
            logger.info("Listing devices for pool=%s node=%s", pool_uuid, node_name)
            try:
                devices = manager.list_devices(pool_uuid, node_id)
            except APIError as exc:
                logger.error(
                    "Failed to list devices for %s/%s: %s",
                    pool_uuid,
                    node_name,
                    exc,
                )
                continue

            for dev in devices:
                dev_id = dev.get("id", "")
                dev_name = dev.get("name", "")
                ip_str = manager._extract_ip(dev)
                dg_list = manager._extract_device_groups(dev)
                # Default everything to ##no##; user must manually flip to ##yes##
                delete_flag = "##no##"
                rows.append(
                    {
                        "pool_uuid": pool_uuid,
                        "node_id": node_id,
                        "device_id": dev_id,
                        "device_name": dev_name,
                        "ip": ip_str,
                        "device_groups": ",".join(dg_list),
                        "delete": delete_flag,
                    }
                )

    output_path = Path(args.output)
    try:
        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, delimiter="\t")
            writer.writeheader()
            writer.writerows(rows)
    except OSError as exc:
        logger.error("Cannot write output file %s: %s", output_path, exc)
        print(f"Error writing {output_path}: {exc}", file=sys.stderr)
        return 1

    logger.info("Exported %d devices to %s", len(rows), output_path)
    print(f"Exported {len(rows)} devices to {output_path}")
    return 0


def cmd_bulk_delete(args: argparse.Namespace) -> int:
    """Bulk delete devices from a TSV file where delete=##yes##."""
    try:
        env = load_env(args.env_file)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    logger = setup_logging(args.log_dir)
    client = DirectorAPIClient(
        env["LP_DIRECTOR_URL"],
        env["LP_DIRECTOR_API_TOKEN"],
        verify_ssl=not args.no_verify_ssl,
    )
    manager = DeviceManager(client, logger)

    input_path = Path(args.input)
    if not input_path.is_file():
        logger.error("Input file not found: %s", input_path)
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1

    # Read TSV and filter delete=##yes##
    rows: list[dict] = []
    try:
        with input_path.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh, delimiter="\t")
            for row in reader:
                raw = row.get("delete", "").strip().lower().replace("#", "")
                if raw == "yes":
                    rows.append(row)
    except Exception as exc:
        logger.error("Failed to read input file %s: %s", input_path, exc)
        print(f"Error reading {input_path}: {exc}", file=sys.stderr)
        return 1

    # Explicit localhost pre-check for audit trail
    safe_rows = []
    localhost_skipped_in_file = 0
    for row in rows:
        name = row.get("device_name", "").strip().lower()
        ip = row.get("ip", "")
        if name == "localhost" or "127.0.0.1" in ip or "::1" in ip:
            logger.error(
                "FORCIBLY SKIPPED localhost device marked for deletion: %s (%s)",
                row.get("device_name"),
                row.get("device_id"),
            )
            localhost_skipped_in_file += 1
        else:
            safe_rows.append(row)
    rows = safe_rows

    if localhost_skipped_in_file:
        logger.warning(
            "%d localhost device(s) were found with delete=##yes## and will be ignored.",
            localhost_skipped_in_file,
        )

    if not rows:
        logger.info("No devices marked for deletion (delete=##yes##). Nothing to do.")
        print("No devices marked for deletion.")
        return 0

    if args.dry_run:
        logger.info("DRY RUN mode — no actual deletions will be performed.")
        print(f"DRY RUN: would delete {len(rows)} devices (localhost exclusions applied).")
        for row in rows:
            print(
                f"  - {row['device_name']} ({row['device_id']}) "
                f"@ {row['pool_uuid']}/{row['node_id']}"
            )
        return 0

    # Group by pool/node to minimise API round-trips
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["pool_uuid"], row["node_id"])].append(row)

    total = {
        "deleted": 0,
        "failed": 0,
        "skipped_localhost": localhost_skipped_in_file,
        "dg_updated": 0,
    }

    for (pool_uuid, node_id), dev_rows in grouped.items():
        devices = []
        for row in dev_rows:
            devices.append(
                {
                    "id": row.get("device_id", ""),
                    "name": row.get("device_name", ""),
                    "ip": row.get("ip", ""),
                }
            )
        logger.info(
            "Starting bulk delete for pool=%s node=%s (%d devices)",
            pool_uuid,
            node_id,
            len(devices),
        )
        try:
            res = manager.bulk_delete(pool_uuid, node_id, devices)
        except APIError as exc:
            logger.error(
                "Bulk delete aborted for %s/%s: %s", pool_uuid, node_id, exc
            )
            print(
                f"Error during bulk delete for {pool_uuid}/{node_id}: {exc}",
                file=sys.stderr,
            )
            continue

        for key in total:
            total[key] += res.get(key, 0)

    logger.info(
        "Overall bulk delete complete — deleted=%d failed=%d "
        "skipped_localhost=%d dg_updated=%d",
        total["deleted"],
        total["failed"],
        total["skipped_localhost"],
        total["dg_updated"],
    )
    print(
        f"Bulk delete complete.\n"
        f"  Deleted:             {total['deleted']}\n"
        f"  Failed:              {total['failed']}\n"
        f"  Skipped (localhost): {total['skipped_localhost']}\n"
        f"  DG memberships updated: {total['dg_updated']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="device_broker",
        description=(
            "Guardsix Fleet Device Broker — list devices and perform "
            "safe bulk deletions with DeviceGroup synchronisation."
        ),
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to the .env file containing API credentials (default: .env)",
    )
    parser.add_argument(
        "--pools-file",
        default="pools.json",
        help="Path to the pools.json topology file (default: pools.json)",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory where log files are written (default: logs)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification (INSECURE)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------
    # list command
    # ------------------------------------------------------------------
    p_list = subparsers.add_parser(
        "list", help="List all devices and export them to a TSV file"
    )
    p_list.add_argument(
        "-o",
        "--output",
        default="devices_export.txt",
        help="Output TSV file path (default: devices_export.txt)",
    )

    # ------------------------------------------------------------------
    # bulk-delete command
    # ------------------------------------------------------------------
    p_del = subparsers.add_parser(
        "bulk-delete",
        help="Delete devices marked 'delete=##yes##' in the TSV file",
    )
    p_del.add_argument(
        "-i",
        "--input",
        default="devices_export.txt",
        help="Input TSV file path (default: devices_export.txt)",
    )
    p_del.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the deletion without calling the Director API",
    )

    args = parser.parse_args()

    if args.command == "list":
        return cmd_list(args)
    if args.command == "bulk-delete":
        return cmd_bulk_delete(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
