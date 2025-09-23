import pandas as pd
from logging_utils import logger
from core.nodes import get_nodes_by_role

def import_repos(client, config_file, dry_run=False, nonzero_on_skip=False, force_create=False):
    logger.info("Starting import of Repos")
    df = pd.read_excel(config_file, sheet_name="repos", skiprows=0)  # 6 rows
    nodes = get_nodes_by_role()  # backends + all_in_one
    backends = nodes.get("backends", [])
    if not backends:
        logger.warning("No backends or all_in_one nodes found. Skipping repos import.")
        return [{"action": "NO_NODES", "reason": "No backends"}]
    
    results = []
    
    for _, row in df.iterrows():
        repo_name = row["repo_name"]
        paths_str = row.get("storage_paths", "")
        days_str = row.get("retention_days", "")
        if "|" in paths_str:
            paths = [p.strip() for p in paths_str.split("|")]
            days = [int(d.strip()) for d in days_str.split("|")]
            repopath = [{"path": path, "retention": day} for path, day in zip(paths, days)]
        else:
            repopath = [{"path": paths_str.strip(), "retention": int(days_str.strip())}]
        
        repo_data = {
            "data": {
                "name": repo_name,
                "hiddenrepopath": repopath,
                "active": True
            }
        }
        
        for node in backends:
            pool_uuid = node.get("pool_uuid")
            logpoint_identifier = node.get("siem", node.get("id"))
            if not pool_uuid or not logpoint_identifier:
                logger.warning(f"Missing pool_uuid or logpoint_identifier for node {node.get('name')}")
                continue
            
            base_endpoint = f"/configapi/{pool_uuid}/{logpoint_identifier}/Repos"
            get_endpoint = f"{base_endpoint}/{repo_name}"
            action = "NONE"
            result = "NOOP"
            error = ""
            
            # Vérifier chemins de stockage
            if not force_create:
                existing_paths, missing_paths = client.check_storage_paths(pool_uuid, logpoint_identifier, [p["path"] for p in repopath])
                if missing_paths:
                    action = "MISSING_STORAGE_PATHS"
                    result = "SKIPPED"
                    error = f"Missing paths: {missing_paths}"
                    results.append({
                        "siem": logpoint_identifier,
                        "node": node.get("name"),
                        "name": repo_name,
                        "result": result,
                        "action": action,
                        "error": error
                    })
                    logger.warning(f"Skipping repo {repo_name} on {node.get('name')} ({logpoint_identifier}): missing storage paths {missing_paths}")
                    continue
            
            # Vérifier existence repo
            existing_repos = client.make_api_request("GET", base_endpoint)
            existing_repo = next((r for r in existing_repos if r.get("name") == repo_name), None) if existing_repos else None
            
            if existing_repo:
                if existing_repo.get("repopath") != repopath:
                    action = "UPDATE"
                    result = "UPDATE"
                    if not dry_run:
                        response = client.make_api_request("PUT", get_endpoint, payload=repo_data)
                        if response.get("status") == "Success":
                            status = client.monitor_job(response.get("message"), pool_uuid, logpoint_identifier)
                            if status.get("success"):
                                logger.info(f"Updated repo {repo_name} on {node.get('name')}: {status.get('message')}")
                                result = "SUCCESS"
                            else:
                                logger.error(f"Failed to update repo {repo_name} on {node.get('name')}: {status.get('errors', ['Unknown error'])}")
                                action = "FAILED"
                                result = "FAILED"
                                error = str(status.get("errors", ["Unknown error"])[0])
                        else:
                            logger.error(f"PUT failed for repo {repo_name} on {node.get('name')}: {response}")
                            action = "FAILED"
                            result = "FAILED"
                            error = "PUT request failed"
                else:
                    action = "NONE"
                    result = "NOOP"
                    logger.info(f"Repo {repo_name} already exists with matching config on {node.get('name')} ({logpoint_identifier}), marking as NOOP")
            else:
                action = "CREATE"
                result = "CREATE"
                if not dry_run:
                    status = client.create_repo(pool_uuid, logpoint_identifier, repo_data)
                    if status.get("success"):
                        logger.info(f"Created repo {repo_name} on {node.get('name')}: {status.get('message')}")
                        result = "SUCCESS"
                    else:
                        logger.error(f"Failed to create repo {repo_name} on {node.get('name')}: {status.get('errors', ['Unknown error'])}")
                        action = "FAILED"
                        result = "FAILED"
                        error = str(status.get("errors", ["Unknown error"])[0])
            
            results.append({
                "siem": logpoint_identifier,
                "node": node.get("name"),
                "name": repo_name,
                "result": result,
                "action": action,
                "error": error
            })
    
    if nonzero_on_skip and any(r["action"] == "MISSING_STORAGE_PATHS" for r in results):
        logger.warning("Non-zero exit due to skipped repos")
        exit(2)
    
    logger.info(f"Repos import completed. Results: {results}")
    return results