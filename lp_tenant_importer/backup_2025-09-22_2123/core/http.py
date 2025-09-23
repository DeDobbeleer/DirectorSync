import requests
import time
from typing import Dict, List, Optional
import logging

from logging_utils import setup_logging

logger = logging.getLogger(__name__)

class DirectorClient:
    def __init__(self, base_url: str, api_token: str, verify: bool = True, timeout: int = 30, proxies: Dict = None):
        """Initialize the DirectorClient with API credentials and settings.
        
        Args:
            base_url: Base URL of the API server.
            api_token: API authentication token.
            verify: Whether to verify SSL certificates.
            timeout: Request timeout in seconds.
            proxies: Dictionary of proxy settings.
        """
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.verify = verify
        self.timeout = timeout
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_token}"})

    def check_storage_paths(self, pool_uuid: str, logpoint_id: str, paths: List[str]) -> List[str]:
        """Check which storage paths exist on the SIEM.
        
        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            paths: List of storage paths to check.

        Returns:
            List of paths that do not exist.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/Repos/RepoPaths"
        try:
            response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            existing_paths = [item for item in response.json() if item in paths]  # Assuming a simple list
            missing_paths = [p for p in paths if p not in existing_paths]
            logger.debug("Checked storage paths: existing=%s, missing=%s", existing_paths, missing_paths)
            return missing_paths
        except requests.RequestException as e:
            logger.error("Failed to check storage paths: %s", e)
            return paths  # Assume all are missing on error

    def get_existing_repos(self, pool_uuid: str, logpoint_id: str) -> List[Dict]:
        """Fetch existing repositories from the SIEM.
        
        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.

        Returns:
            List of repository dictionaries.
        """
        url = f"{self.base_url}/api/v1/repos"
        try:
            response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            repos = response.json().get("repos", [])
            logger.debug("Fetched %d existing repos", len(repos))
            return repos
        except requests.RequestException as e:
            logger.error("Failed to fetch existing repos: %s", e)
            return []

    def create_repo(self, pool_uuid: str, logpoint_id: str, repo: Dict) -> Dict:
        """Create a new repository (async).
        
        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            repo: Repository dictionary with name, storage_paths, active.

        Returns:
            Response dictionary with monitorapi.
        """
        url = f"{self.base_url}/api/v1/repos"
        try:
            response = self.session.post(url, json=repo, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            result = response.json()
            logger.info("Created repo %s, monitorapi: %s", repo["name"], result.get("monitorapi"))
            return result
        except requests.RequestException as e:
            logger.error("Failed to create repo %s: %s", repo["name"], e)
            raise

    def update_repo(self, pool_uuid: str, logpoint_id: str, repo_id: str, repo: Dict) -> Dict:
        """Update an existing repository (async).
        
        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            repo_id: Repository ID.
            repo: Repository dictionary with updated fields.

        Returns:
            Response dictionary with monitorapi.
        """
        url = f"{self.base_url}/api/v1/repos/{repo_id}"
        try:
            response = self.session.put(url, json=repo, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            result = response.json()
            logger.info("Updated repo %s, monitorapi: %s", repo_id, result.get("monitorapi"))
            return result
        except requests.RequestException as e:
            logger.error("Failed to update repo %s: %s", repo_id, e)
            raise

    def monitor_job(self, monitorapi: str, max_attempts: int = 10, interval: int = 5) -> Dict:
        """Monitor an async job until completion.
        
        Args:
            monitorapi: Monitor API URL (assumed to be a string).
            max_attempts: Maximum polling attempts.
            interval: Polling interval in seconds.

        Returns:
            Final job status dictionary (with success and error fields).
        """
        url = monitorapi if monitorapi.startswith("http") else f"{self.base_url}/{monitorapi.lstrip('/')}"
        for attempt in range(max_attempts):
            try:
                response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
                response.raise_for_status()
                status = response.json()
                logger.debug("Job status (attempt %d/%d): %s", attempt + 1, max_attempts, status)
                if status.get("success") is not None:
                    return status
                time.sleep(interval)
            except requests.RequestException as e:
                logger.error("Failed to monitor job: %s", e)
                break
        logger.error("Job monitoring timed out after %d attempts", max_attempts)
        return {"success": False, "error": "Timeout"}

    # Existing methods (get, post, put, etc.) assumed here
    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform a GET request.
        
        Args:
            url: Relative or absolute URL.
            **kwargs: Additional request parameters.

        Returns:
            Response object.
        """
        full_url = url if url.startswith("http") else f"{self.base_url}/{url.lstrip('/')}"
        return self.session.get(full_url, verify=self.verify, timeout=self.timeout, proxies=self.proxies, **kwargs)

    def post(self, url: str, json: Dict = None, **kwargs) -> requests.Response:
        """Perform a POST request.
        
        Args:
            url: Relative or absolute URL.
            json: JSON payload.
            **kwargs: Additional request parameters.

        Returns:
            Response object.
        """
        full_url = url if url.startswith("http") else f"{self.base_url}/{url.lstrip('/')}"
        return self.session.post(full_url, json=json, verify=self.verify, timeout=self.timeout, proxies=self.proxies, **kwargs)

    def put(self, url: str, json: Dict = None, **kwargs) -> requests.Response:
        """Perform a PUT request.
        
        Args:
            url: Relative or absolute URL.
            json: JSON payload.
            **kwargs: Additional request parameters.

        Returns:
            Response object.
        """
        full_url = url if url.startswith("http") else f"{self.base_url}/{url.lstrip('/')}"
        return self.session.put(full_url, json=json, verify=self.verify, timeout=self.timeout, proxies=self.proxies, **kwargs)
  ```

**Changements** :
- Ajout de `check_storage_paths` pour vérifier les `paths` via `GET /configapi/{pool_UUID}/{logpoint_identifier}/Repos/RepoPaths`.
- Ajout de `get_existing_repos` pour lister les repos existants via `GET /api/v1/repos`.
- Ajout de `create_repo` et `update_repo` pour POST/PUT (async avec `monitorapi`).
- Ajout de `monitor_job` pour poller jusqu’à `success: true/false`, avec fallback à `error: Timeout`.
- Conservation des méthodes `get`, `post`, `put` pour compatibilité avec le code existant.
- Logging détaillé pour chaque étape.

### Mise à jour de `repos.py`
J’ajuste `repos.py` pour utiliser la nouvelle couche API et implémenter la logique métier.

<xaiArtifact artifact_id="372ae9e6-5c19-4acb-b8e1-e5b3a48c38c5" artifact_version_id="54176723-0ab3-4cc8-a4dd-79e638a2fff2" title="repos.py" contentType="text/python">
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

            # Validate lengths and set default retention if needed
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
            # Process for each target node
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

                    # Check storage paths
                    missing_paths = client.check_storage_paths(pool_uuid, siem_id, [s["path"] for s in cleaned_repo["storage"]])
                    if missing_paths:
                        result["result"] = "SKIPPED"
                        result["action"] = "MISSING_STORAGE_PATHS"
                        result["error"] = f"Missing paths: {missing_paths}"
                        logger.warning("Skipping repo %s on %s (%s): missing storage paths %s", name, node_name, siem_id, missing_paths)
                    else:
                        # Check existing repos
                        existing_repos = client.get_existing_repos(pool_uuid, siem_id)
                        existing = next((r for r in existing_repos if r["name"] == cleaned_repo["name"]), None)

                        if existing and self._compare_repos(existing, cleaned_repo):
                            result["result"] = "SKIPPED"
                            result["action"] = "NOOP"
                            logger.info("No changes needed for repo %s on %s (%s)", name, node_name, siem_id)
                        elif dry_run:
                            result["result"] = "SKIPPED"
                            result["action"] = "DRY_RUN"
                            logger.info("Dry-run: Would import repo %s to %s (%s)", name, node_name, siem_id)
                        else:
                            try:
                                if not existing:
                                    response = client.create_repo(pool_uuid, siem_id, cleaned_repo)
                                    status = client.monitor_job(response["monitorapi"])
                                    if status.get("success"):
                                        result["action"] = "CREATED"
                                        result["result"] = "SUCCESS"
                                        logger.info("Created repo %s on %s (%s)", name, node_name, siem_id)
                                    else:
                                        result["action"] = "FAILED"
                                        result["result"] = "FAILED"
                                        result["error"] = status.get("error", "Unknown error")
                                        any_error = True
                                        logger.error("Failed to create repo %s on %s (%s): %s", name, node_name, siem_id, result["error"])
                                else:
                                    response = client.update_repo(pool_uuid, siem_id, existing["id"], cleaned_repo)
                                    status = client.monitor_job(response["monitorapi"])
                                    if status.get("success"):
                                        result["action"] = "UPDATED"
                                        result["result"] = "SUCCESS"
                                        logger.info("Updated repo %s on %s (%s)", name, node_name, siem_id)
                                    else:
                                        result["action"] = "FAILED"
                                        result["result"] = "FAILED"
                                        result["error"] = status.get("error", "Unknown error")
                                        any_error = True
                                        logger.error("Failed to update repo %s on %s (%s): %s", name, node_name, siem_id, result["error"])
                            except Exception as e:
                                result["result"] = "FAILED"
                                result["error"] = str(e)
                                any_error = True
                                logger.error("Failed to process repo %s on %s (%s): %s", name, node_name, siem_id, e)

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

    def _compare_repos(self, existing: Dict, new: Dict) -> bool:
        """Compare two repo configurations for NOOP decision.
        
        Args:
            existing: Existing repo from API.
            new: New repo from XLSX.

        Returns:
            True if identical, False otherwise.
        """
        if existing["name"] != new["name"] or existing["active"] != new["active"]:
            return False
        # Compare storage paths (order-independent)
        existing_storage = {s["path"]: s["retention_days"] for s in existing.get("storage_paths", [])}
        new_storage = {s["path"]: s["retention_days"] for s in new.get("storage", [])}
        return existing_storage == new_storage

    except Exception as e:
        logger.error("Failed to parse Repo sheet in %s: %s", xlsx_path, e)
        raise ValueError(f"Failed to parse Repo sheet: {e}")

    return results, any_error
```

**Changements** :
- Intégration de `check_storage_paths` pour valider tous les `storage_paths` avant traitement.
- Utilisation de `get_existing_repos` pour vérifier l’existence et comparer avec `_compare_repos` pour NOOP.
- Appel de `create_repo` ou `update_repo` avec `monitor_job` pour gérer l’async.
- Statuts : "MISSING_STORAGE_PATHS" pour SKIP dû à des `paths` absents, "NOOP" pour pas de changement, "CREATED"/"UPDATED" pour succès, "FAILED" pour échec.
- Comparaison basée sur `name`, `active`, et `storage_paths` (ordre indépendant).

### Mise à jour de `test_all.py`
Ajout de logs pour vérifier les statuts.

<xaiArtifact artifact_id="55061304-c5be-422a-a4de-8837bc90b396" artifact_version_id="ab27c28f-2f7d-463a-a566-30e8fa90910c" title="test_all.py" contentType="text/python">
import os
import subprocess
import logging
from pathlib import Path
from logging_utils import setup_logging
from core.nodes import collect_nodes
from config_loader import load_tenants_file, get_tenant
import pandas as pd

# Configure logging
logging.getLogger().handlers = []
setup_logging()
logger = logging.getLogger(__name__)

# Verify XLSX content
xlsx_path = "core_config.xlsx"
logger.info("Checking for XLSX file: %s", xlsx_path)
if not Path(xlsx_path).exists():
    logger.error("%s not found. Please place your real core_config.xlsx in the directory.", xlsx_path)
    print(f"ERROR: {xlsx_path} not found. Please place your real core_config.xlsx in the directory.")
    exit(1)

logger.debug("Verifying XLSX content for %s", xlsx_path)
sheet_names = pd.ExcelFile(xlsx_path).sheet_names
logger.info("Available sheets: %s", sheet_names)
print(f"Available sheets: {sheet_names}")

for sheet in ["Repo", "RoutingPolicy", "Alert", "NormalizationPolicy", "ProcessingPolicy", "EnrichmentPolicy"]:
    if sheet in sheet_names:
        logger.debug("Reading sheet: %s", sheet)
        df = pd.read_excel(xlsx_path, sheet_name=sheet, skiprows=0)
        # Drop header row if it contains 'row1'
        if 'row1' in df.iloc[0].astype(str).str.lower().values:
            df = df.iloc[1:].reset_index(drop=True)
        logger.info("Sheet '%s': %d rows, columns: %s", sheet, len(df), list(df.columns))
        print(f"Sheet '{sheet}': {len(df)} rows, columns: {list(df.columns)}")
        if not df.empty:
            logger.debug("First row of %s: %s", sheet, df.iloc[0].to_dict())
            print(f"First row: {df.iloc[0].to_dict()}")
    else:
        logger.warning("Sheet '%s' not found in XLSX", sheet)
        print(f"Sheet '{sheet}' not found in XLSX")

# Test nodes
logger.info("Loading tenants.yml and collecting nodes for tenant 'core'")
config = load_tenants_file("./tenants.yml")
tenant = get_tenant(config, "core")
nodes = collect_nodes(tenant)
logger.info("Nodes: %s", nodes)
print(f"Nodes: {nodes}")

# Test CLI commands
commands = [
    ["python", "main.py", "--help"],
    [
        "python",
        "main.py",
        "import-repos",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-routing-policies",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-alerts",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-normalization-policies",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-processing-policies",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-enrichment-policies",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
]

for cmd in commands:
    logger.info("Running command: %s", " ".join(cmd))
    print(f"\nRunning: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        logger.error("Command failed with exit code %d: %s", result.returncode, result.stderr)
        print(f"Error (exit code {result.returncode}): {result.stderr}")
    else:
        logger.debug("Command succeeded: %s", result.stdout)
```

**Changements** :
- Pas de modification directe, mais prêt à afficher les nouveaux statuts ("MISSING_STORAGE_PATHS", "NOOP") une fois `repos.py` mis à jour.

### Actions immédiates
- **Sauvegarde** : Fais `mkdir -p backup_2025-09-22_2115` et copie les fichiers :
  ```bash
  cp main.py repos.py routing_policies.py alerts.py normalization_policies.py processing_policies.py enrichment_policies.py core/http.py core/nodes.py config_loader.py logging_utils.py test_all.py backup_2025-09-22_2115/
  ```
- **Commit** : `git add .`, `git commit -m "Added API layer and updated repos.py for sync"`, `git push`.

### Prochaines étapes (pour demain, 21:00 CEST)
1. **Tester** : Exécute `python test_all.py` pour vérifier que `import-repos` affiche 12 lignes avec statuts corrects (ex. : "MISSING_STORAGE_PATHS" si un `path` n’existe pas, "NOOP" si identique).
2. **Ajustements** : Si des `storage_paths` manquent dans ton SIEM test, on simulera via `core/http.py` (mock ou config mock dans `.env`).
3. **Générer binaire** :
   ```bash
   pip install auto-py-to-exe
   auto-py-to-exe --onefile --add-data "tenants.yml;." --add-data ".env;." --output-dir dist
   ```
   Tester sur Windows : `dist\lp_importer.exe import-repos --tenant core --xlsx core_config.xlsx --dry-run --format table`.
4. **Prochain élément** : Passer à `EnrichmentPolicy` avec la même logique (checks API, async monitoring).

### Question
La sauvegarde dans `backup_2025-09-22_2115` te convient-elle ? Tout est validé pour avancer sur `core/http.py` et `repos.py` ? Si oui, je te donne le code final demain après test. Sinon, dis-moi ce qu’il faut ajuster. 😎