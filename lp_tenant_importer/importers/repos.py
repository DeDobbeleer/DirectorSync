import logging
import os
from typing import Dict, List, Tuple
import pandas as pd
from core.http import DirectorClient
from core.nodes import Node, collect_nodes

logger = logging.getLogger(__name__)

def import_repos_for_nodes(client: DirectorClient, pool_uuid: str, nodes: Dict[str, List[Node]], xlsx_path: str, dry_run: bool, targets: List[str], force_create: bool = False) -> Tuple[List[Dict], bool]:
    """Import or update repositories for all nodes.

    Args:
        client: DirectorClient instance.
        pool_uuid: Tenant pool UUID.
        nodes: Dictionary of node types and their instances.
        xlsx_path: Path to the Excel configuration file.
        dry_run: If True, do not make changes.
        targets: List of target node roles.
        force_create: If True, ignore missing storage paths.

    Returns:
        List of result rows and a flag indicating if any error occurred.
    """
    rows = []
    any_error = False

    try:
        df = pd.read_excel(xlsx_path, sheet_name="Repo")
        logger.debug("Reading Repo sheet from %s", xlsx_path)
    except Exception as e:
        logger.error("Failed to read Repo sheet from %s: %s", xlsx_path, e)
        return [], True

    column_mapping = {
        "cleaned_repo_name": "name",
        "storage_paths": "storage_paths",
        "retention_days": "retention_days",
        "active": "active"
    }
    required_columns = ["name", "storage_paths", "retention_days", "active"]

    df = df.rename(columns=column_mapping)

    if not all(col in df.columns for col in required_columns):
        missing_cols = [col for col in required_columns if col not in df.columns]
        logger.error("Missing required columns in Repo sheet: %s", missing_cols)
        return [], True

    logger.debug("Found %d repos in XLSX", len(df))
    for index, row in df.iterrows():
        name = row["name"]
        active = bool(row["active"])
        storage_paths = [p.strip() for p in row["storage_paths"].replace("|", ",").split(",") if p.strip()]
        
        # TODO convert as str
        if isinstance(row["retention_days"], int):
            retention_days = str(row["retention_days"])
        else:
            retention_days = [str(r).strip() for r in str(row["retention_days"]).replace("|", ",").split(",") if r.strip()]
            
        if len(storage_paths) != len(retention_days):
            logger.error("Mismatch between storage_paths and retention_days for repo %s: %s vs %s", name, storage_paths, retention_days)
            rows.append({"siem": "", "node": "", "name": name, "result": "Fail", "action": "NONE", "error": "Mismatch in storage and retention data"})
            any_error = True
            continue
        storage_data = [{"path": path + "/", "retention": int(retention)} for path, retention in zip(storage_paths, retention_days)]
        logger.debug("Processing repo: %s with storage: %s", name, storage_data)

        for node_type, node_list in nodes.items():
            if node_type not in targets:
                continue
            for node in node_list:
                siem_id = node.id
                if not force_create:
                    missing_paths = client.check_storage_paths(pool_uuid, siem_id, [item["path"] for item in storage_data])
                    if missing_paths:
                        logger.warning("Skipping repo %s on %s (%s): missing storage paths %s", name, node.name, siem_id, missing_paths)
                        rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "MISSING_STORAGE", "action": "SKIP", "error": f"Missing paths: {missing_paths}"})
                        continue

                try:
                    existing_repos = client.get_existing_repos(pool_uuid, siem_id)
                    repo_data = {"name": name, "repopath": storage_data, "active": active}
                    existing_repo = next((r for r in existing_repos if r["name"] == name), None)
                    if existing_repo:
                        current_repopath = {item["path"]: item["retention"] for item in existing_repo.get("repopath", [])}
                        new_repopath = {item["path"]: item["retention"] for item in storage_data}
                        if current_repopath == new_repopath and existing_repo.get("active") == active:
                            logger.info("Repo %s already exists with matching config on %s (%s), marking as NOOP", name, node.name, siem_id)
                            rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "(N/A)", "action": "NOOP", "error": None})
                        else:
                            if not dry_run:
                                result = client.update_repo(pool_uuid, siem_id, existing_repo["id"], repo_data)
                                if "monitorapi" in result:
                                    job_status = client.monitor_job(result["monitorapi"])
                                    if job_status.get("success"):
                                        logger.info("Repo %s updated successfully on %s (%s)", name, node.name, siem_id)
                                        rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "Success", "action": "UPDATE", "error": None})
                                    else:
                                        logger.error("Failed to update repo %s on %s (%s): %s", name, node.name, siem_id, job_status.get("error"))
                                        rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "Fail", "action": "UPDATE", "error": job_status.get("error", "Unknown error")})
                                        any_error = True
                                else:
                                    logger.error("Failed to update repo %s on %s (%s): Invalid response from API", name, node.name, siem_id)
                                    rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "Fail", "action": "UPDATE", "error": "Invalid response from API"})
                                    any_error = True
                            else:
                                rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "MISSING_STORAGE", "action": "SKIP", "error": "Update would be applied"})
                    else:
                        if not dry_run:
                            result = client.create_repo(pool_uuid, siem_id, repo_data)
                            if result.get("status") == "noop":
                                logger.info("Repo %s already exists on %s (%s), marking as NOOP", name, node.name, siem_id)
                                rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "(N/A)", "action": "NOOP", "error": None})
                            elif "monitorapi" in result:
                                job_status = client.monitor_job(result["monitorapi"])
                                if job_status.get("success"):
                                    logger.info("Repo %s created successfully on %s (%s)", name, node.name, siem_id)
                                    rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "Success", "action": "CREATE", "error": None})
                                else:
                                    logger.error("Failed to create repo %s on %s (%s): %s", name, node.name, siem_id, job_status.get("error"))
                                    rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "Fail", "action": "CREATE", "error": job_status.get("error", "Unknown error")})
                                    any_error = True
                            else:
                                logger.error("Failed to create repo %s on %s (%s): Invalid response from API", name, node.name, siem_id)
                                rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "Fail", "action": "CREATE", "error": "Invalid response from API"})
                                any_error = True
                        else:
                            rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "MISSING_STORAGE", "action": "SKIP", "error": ""})
                except Exception as e:
                    logger.error("Failed to process repo %s on %s (%s): %s", name, node.name, siem_id, str(e))
                    rows.append({"siem": siem_id, "node": node.name, "name": name, "result": "Fail", "action": "NONE", "error": str(e)})
                    any_error = True

    return rows, any_error