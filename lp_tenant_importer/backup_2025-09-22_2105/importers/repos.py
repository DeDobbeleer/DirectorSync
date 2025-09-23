import logging
import pandas as pd
from typing import List, Dict, Any, Tuple
from pathlib import Path
from core.http import DirectorClient

logger = logging.getLogger(__name__)

def import_repos_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List],
    xlsx_path: str,
    dry_run: bool,
    targets: List[str],
) -> Tuple[List[Dict], bool]:
    """Import repositories from XLSX to specified SIEM nodes.

    Args:
        client: DirectorClient instance for API calls.
        pool_uuid: Tenant pool UUID.
        nodes: Dictionary of SIEM nodes by role (backends, all_in_one).
        xlsx_path: Path to XLSX file.
        dry_run: If True, simulate without API calls.
        targets: List of target roles (e.g., ['backends', 'all_in_one']).

    Returns:
        Tuple of (results list, any_error boolean).

    Raises:
        FileNotFoundError: If XLSX file is missing.
        ValueError: If XLSX parsing fails or sheet is invalid.
    """
    results = []
    any_error = False

    # Validate XLSX file
    xlsx_path = Path(xlsx_path)
    if not xlsx_path.exists():
        logger.error("XLSX file not found: %s", xlsx_path)
        raise FileNotFoundError(f"XLSX file not found: {xlsx_path}")

    # Check if any target nodes are available
    available_nodes = any(nodes.get(target, []) for target in targets)
    if not available_nodes:
        logger.warning("No nodes available for targets: %s", targets)
        results.append({
            "siem": "none",
            "node": "none",
            "name": "N/A",
            "result": "SKIPPED",
            "action": "NO_NODES",
            "error": f"No nodes for targets: {targets}",
        })
        return results, False

    try:
        # Read Repo sheet
        logger.debug("Reading Repo sheet from %s", xlsx_path)
        df = pd.read_excel(xlsx_path, sheet_name="Repo", skiprows=0)
        # Drop header row if it contains 'row1'
        if 'row1' in df.iloc[0].astype(str).str.lower().values:
            df = df.iloc[1:].reset_index(drop=True)
        if df.empty:
            logger.warning("Repo sheet is empty in %s", xlsx_path)
            results.append({
                "siem": "none",
                "node": "none",
                "name": "N/A",
                "result": "SKIPPED",
                "action": "EMPTY_SHEET",
            })
            return results, False

        logger.debug("Found %d repos in XLSX", len(df))
        # Convert to list of dicts, clean data
        repos = df.to_dict("records")
        for repo in repos:
            name = str(repo.get("cleaned_repo_name", "")).strip()
            if not name:
                logger.warning("Skipping repo with empty name: %s", repo)
                continue

            paths = [path.strip() for path in str(repo.get("storage_paths", "")).split("|") if path.strip()]
            retentions = [r.strip() for r in str(repo.get("retention_days", "")).split("|") if r.strip()]

            # Validate lengths
            if len(paths) != len(retentions):
                logger.warning("Mismatched paths and retentions for repo %s: using default retention 90 for all paths", name)
                retentions = ["90"] * len(paths)

            storage = []
            for path, retention in zip(paths, retentions):
                try:
                    retention = int(float(retention))
                except ValueError as e:
                    logger.warning("Invalid retention_days '%s' for path '%s' in repo %s: using default 90", retention, path, name)
                    retention = 90
                storage.append({"path": path, "retention_days": retention})

            cleaned_repo = {
                "name": name,
                "storage": storage,
                "active": str(repo.get("active", "true")).lower() == "true",
            }

            logger.debug("Processing repo: %s with storage: %s", cleaned_repo["name"], cleaned_repo["storage"])
            # Process for each target role
            for target in targets:
                if target not in nodes or not nodes[target]:
                    logger.warning("No nodes for target role %s", target)
                    continue
                for node in nodes.get(target, []):
                    siem_id = node["id"]
                    node_name = node["name"]
                    result = {
                        "siem": siem_id,
                        "node": node_name,
                        "name": cleaned_repo["name"],
                        "result": "PENDING",
                        "action": "NONE",
                    }

                    if dry_run:
                        result["result"] = "SKIPPED"
                        result["action"] = "DRY_RUN"
                        logger.info(
                            "Dry-run: Would import repo %s to %s (%s)",
                            cleaned_repo["name"],
                            node_name,
                            siem_id,
                        )
                    else:
                        try:
                            # Check if repo exists
                            endpoint = client.build_endpoint(pool_uuid, siem_id, "repos")
                            existing_repos = client.get(endpoint).get("repos", [])
                            existing = next(
                                (r for r in existing_repos if r["name"] == cleaned_repo["name"]), None
                            )

                            if existing:
                                # Update existing repo
                                client.put(endpoint + f"/{existing['id']}", cleaned_repo)
                                result["action"] = "UPDATED"
                                logger.info(
                                    "Updated repo %s on %s (%s)", cleaned_repo["name"], node_name, siem_id
                                )
                            else:
                                # Create new repo
                                client.post(endpoint, cleaned_repo)
                                result["action"] = "CREATED"
                                logger.info(
                                    "Created repo %s on %s (%s)", cleaned_repo["name"], node_name, siem_id
                                )

                            result["result"] = "SUCCESS"
                        except Exception as e:
                            result["result"] = "FAILED"
                            result["error"] = str(e)
                            any_error = True
                            logger.error(
                                "Failed to import repo %s to %s (%s): %s",
                                cleaned_repo["name"],
                                node_name,
                                siem_id,
                                e,
                            )

                    results.append(result)

        if not results:
            logger.warning("No repos processed for %s", xlsx_path)
            results.append({
                "siem": "none",
                "node": "none",
                "name": "N/A",
                "result": "SKIPPED",
                "action": "NO_DATA",
            })

    except Exception as e:
        logger.error("Failed to parse Repo sheet in %s: %s", xlsx_path, e)
        raise ValueError(f"Failed to parse Repo sheet: {e}")

    return results, any_error