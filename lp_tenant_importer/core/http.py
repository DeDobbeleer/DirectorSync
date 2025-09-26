import requests
import time
from typing import Dict, List, Any, Optional
import logging
import os.path
import json

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
        logger.debug("Initialized with base_url=%s, api_token=**** (raw length=%d)", base_url, len(api_token))
        self.verify = verify
        self.timeout = timeout
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"})
        logger.debug("Headers set: %s", self.session.headers)

    def get(self, url: str, **kwargs) -> requests.Response:
        full_url = url if url.startswith("http") else f"{self.base_url}/{url.lstrip('/')}"
        return self.session.get(full_url, verify=self.verify, timeout=self.timeout, proxies=self.proxies, **kwargs)

    def post(self, url: str, json: Dict = None, **kwargs) -> requests.Response:
        full_url = url if url.startswith("http") else f"{self.base_url}/{url.lstrip('/')}"
        return self.session.post(full_url, json=json, verify=self.verify, timeout=self.timeout, proxies=self.proxies, **kwargs)

    def put(self, url: str, json: Dict = None, **kwargs) -> requests.Response:
        full_url = url if url.startswith("http") else f"{self.base_url}/{url.lstrip('/')}"
        return self.session.put(full_url, json=json, verify=self.verify, timeout=self.timeout, proxies=self.proxies, **kwargs)  

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
            logger.debug("Raw response from ...: %s", json.dumps(response.json() if response.status_code == 200 else {}, separators=(',', ':')))
            data = response.json()
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and "paths" in data[0]:
                existing_paths = [os.path.normpath(p) for p in data[0]["paths"]]
            else:
                existing_paths = []
            normalized_paths = [os.path.normpath(p) for p in paths]
            missing_paths = [p for p in normalized_paths if p not in existing_paths]
            logger.debug("Checked storage paths: existing=%s, missing=%s", existing_paths, missing_paths)
            return missing_paths
        except requests.RequestException as e:
            logger.error("Failed to check storage paths: %s (Response: %s)", str(e), getattr(e.response, 'text', 'No response'))
            return paths

    def get_existing_repos(self, pool_uuid: str, logpoint_id: str) -> List[Dict]:
        """Fetch existing repositories from the SIEM.

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.

        Returns:
            List of repository dictionaries.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/Repos"
        try:
            response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from ...: %s", json.dumps(response.json() if response.status_code == 200 else {}, separators=(',', ':')))
            try:
                data = response.json()
                if isinstance(data, list):
                    repos = data
                elif isinstance(data, dict) and "repos" in data:
                    repos = data.get("repos", [])
                else:
                    repos = []
            except ValueError as e:
                logger.error("Invalid JSON response: %s", e)
                repos = []
            logger.debug("Fetched %d existing repos", len(repos))
            return repos
        except requests.RequestException as e:
            logger.error("Failed to fetch existing repos: %s (Response: %s)", str(e), getattr(e.response, 'text', 'No response'))
            return []

    def create_repo(self, pool_uuid: str, logpoint_id: str, repo: Dict) -> Dict:
        """Create a new repository (async) or mark as NOOP if exists.

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            repo: Repository dictionary with name, repopath, active.

        Returns:
            Response dictionary with monitorapi and status.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/Repos"
        # Vérifier si le repo existe déjà
        existing_repos = self.get_existing_repos(pool_uuid, logpoint_id)
        repo_name = repo["name"]
        if any(r["name"] == repo_name for r in existing_repos):
            logger.info("Repo %s already exists, marking as NOOP", repo_name)
            return {"monitorapi": None, "status": "noop"}  # Format compatible avec repos.py

        # Utiliser directement les données de l'Excel
        repo_data = {
            "data": {
                "hiddenrepopath": [{"path": item["path"], "retention": item["retention"]} for item in repo["repopath"]],
                "name": repo_name,
                "active": repo.get("active", True)
            }
        }
        logger.debug("Formatted request body for %s: %s", url, json.dumps(repo_data, indent=2))
        try:
            response = self.session.post(url, json=repo_data, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            result = response.json()
            # Extraire monitorapi depuis le champ message si status est Success
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
                result["monitorapi"] = result["message"]
            if result.get("monitorapi"):
                logger.info("Monitoring job at %s", result["monitorapi"])
                job_status = self.monitor_job(result["monitorapi"])
                if job_status.get("success"):
                    logger.info("Repo %s created successfully", repo_name)
                    return {"monitorapi": result["monitorapi"], "status": "success"}
                else:
                    logger.error("Repo %s creation failed: %s", repo_name, job_status.get("error", "Unknown error"))
                    return {"monitorapi": result["monitorapi"], "status": "failed", "error": job_status.get("error")}
            return result
        except requests.RequestException as e:
            logger.error("Failed to create repo %s: %s (Response: %s)", repo_name, str(e), getattr(e.response, 'text', 'No response'))
            raise

    def update_repo(self, pool_uuid: str, logpoint_id: str, repo_id: str, repo: Dict) -> Dict:
        """Update an existing repository (async) using Excel as the sole source of truth.

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            repo_id: Repository ID.
            repo: Repository dictionary with updated fields.

        Returns:
            Response dictionary with monitorapi.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/Repos/{repo_id}"
        # Utiliser directement les données de l'Excel, écrasant l'existant
        repo_data = {
            "data": {
                "hiddenrepopath": [{"path": item["path"], "retention": item["retention"]} for item in repo["repopath"]],
                "name": repo.get("name", ""),
                "active": repo.get("active", True)
            }
        }
        logger.debug("Update request body for %s: %s", url, json.dumps(repo_data, indent=2))
        try:
            response = self.session.put(url, json=repo_data, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            try:
                result = response.json()
            except ValueError as e:
                logger.error("Invalid JSON response: %s", e)
                result = {"monitorapi": f"/mock/monitor/{repo_id}"}
            # Extraire monitorapi depuis le champ message si status est Success
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
                result["monitorapi"] = result["message"]
            logger.info("Updated repo %s, monitorapi: %s", repo_id, result.get("monitorapi"))
            return result
        except requests.RequestException as e:
            logger.error("Failed to update repo %s: %s (Response: %s)", repo_id, str(e), getattr(e.response, 'text', 'No response'))
            raise
    
    def monitor_job(self, monitorapi: str, max_attempts: int = 30, interval: float = 2) -> Dict:
        """Monitor an async job until completion (success: true or false).

        Args:
            monitorapi: Monitor API URL (assumed to be a string).
            max_attempts: Maximum polling attempts.
            interval: Polling interval in seconds (default: 2).

        Returns:
            Final job status dictionary (with success and error fields).
        """
        url = monitorapi if monitorapi.startswith("http") else f"{self.base_url}/{monitorapi.lstrip('/')}"
        for attempt in range(1, max_attempts + 1):
            try:
                response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
                response.raise_for_status()
                logger.debug("Raw response from %s: %s", url, response.text)
                try:
                    status = response.json()
                    logger.debug(f"monitorapi status: {status}")
                except ValueError as e:
                    logger.error("Invalid JSON response: %s", e)
                    return {"success": False, "error": "Invalid JSON"}
                logger.debug("Job status (attempt %d/%d): %s", attempt, max_attempts, status)
                
                response_data = status.get("response", {})
                success = response_data.get("success")
                errors = response_data.get("errors", [])
                
                if success is not None or errors:
                    if success:
                        logger.info(f"Job succeeded: {response_data.get('message', 'No message')}")
                    else:
                        logger.error(f"Job failed: {errors or response_data.get('message', 'No error details')}")
                    return response_data  # Sortie immédiate
                time.sleep(interval)
            except requests.RequestException as e:
                logger.error("Failed to monitor job: %s (Response: %s)", str(e), getattr(e.response, 'text', 'No response'))
                return {"success": False, "error": str(e)}
        logger.error("Job monitoring timed out after %d attempts", max_attempts)
        return {"success": False, "error": "Timeout"}        

    def check_repos(self, pool_uuid: str, logpoint_id: str, repo_names: List[str]) -> List[str]:
        """Check which repositories exist on the SIEM.

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            repo_names: List of repository names to check.

        Returns:
            List of repo names that do not exist.
        """
        existing_repos = self.get_existing_repos(pool_uuid, logpoint_id)
        existing_names = [repo["name"] for repo in existing_repos]
        missing_repos = [name for name in repo_names if name and name not in existing_names]
        logger.debug("Checked repos: existing=%s, missing=%s", existing_names, missing_repos)
        return missing_repos

    def get_existing_routing_policies(self, pool_uuid: str, logpoint_id: str) -> List[Dict]:
        """Fetch existing routing policies from the SIEM.

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.

        Returns:
            List of routing policy dictionaries.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies"
        try:
            response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from ...: %s", json.dumps(response.json() if response.status_code == 200 else {}, separators=(',', ':')))
            data = response.json()
            policies = data if isinstance(data, list) else data.get("data", [])
            logger.debug("Fetched %d existing routing policies", len(policies))
            return policies
        except requests.RequestException as e:
            logger.error("Failed to fetch existing routing policies: %s (Response: %s)", str(e), getattr(e.response, 'text', 'No response'))
            return []

    def create_routing_policy(self, pool_uuid: str, logpoint_id: str, policy: Dict) -> Dict:
        """Create a new routing policy (async).

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            policy: Policy dictionary with policy_name, catch_all, active, routing_criteria.

        Returns:
            Response dictionary with monitorapi.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies"
        payload = {"data": policy}
        logger.debug("Create request body for %s: %s", url, json.dumps(payload, indent=2))
        try:
            response = self.session.post(url, json=payload, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            result = response.json()
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("/monitorapi/"):
                result["monitorapi"] = result["message"]
            return result
        except requests.RequestException as e:
            logger.error("Failed to create routing policy %s: %s (Response: %s)", policy["policy_name"], str(e), getattr(e.response, 'text', 'No response'))
            raise

    def update_routing_policy(self, pool_uuid: str, logpoint_id: str, policy_id: str, policy: Dict) -> Dict:
        """Update an existing routing policy (async).

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            policy_id: Policy ID.
            policy: Updated policy dictionary.

        Returns:
            Response dictionary with monitorapi.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies/{policy_id}"
        payload = {"data": policy}
        logger.debug("Update request body for %s: %s", url, json.dumps(payload, indent=2))
        try:
            response = self.session.put(url, json=payload, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            result = response.json()
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("/monitorapi/"):
                result["monitorapi"] = result["message"]
            return result
        except requests.RequestException as e:
            logger.error("Failed to update routing policy %s: %s (Response: %s)", policy_id, str(e), getattr(e.response, 'text', 'No response'))
            raise
    
    def get_existing_normalization_policies(self, pool_uuid: str, logpoint_id: str) -> List[Dict]:
        """Fetch existing normalization policies from the SIEM.

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.

        Returns:
            List of normalization policy dictionaries.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy"
        try:
            response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            data = response.json()
            policies = data if isinstance(data, list) else data.get("data", [])
            logger.debug("Fetched %d existing normalization policies", len(policies))
            return policies
        except requests.RequestException as e:
            logger.error("Failed to fetch existing normalization policies: %s (Response: %s)", str(e), getattr(e.response, 'text', 'No response'))
            return []

    def create_normalization_policy(self, pool_uuid: str, logpoint_id: str, policy: Dict) -> Dict:
        """Create a new normalization policy (async).

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            policy: Policy dictionary with name, normalization_packages (list of IDs str), compiled_normalizer (list of names str).

        Returns:
            Dict with status 'success' or 'failed', error if failed.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy"
        payload = {
            "data": {
                "name": policy["name"],
                "norm_packages": ",".join(policy.get("normalization_packages", [])),
                "compiled_normalizer": ",".join(policy.get("compiled_normalizer", []))
            }
        }
        logger.debug("Create request body for %s: %s", url, json.dumps(payload, indent=2))
        try:
            response = self.session.post(url, json=payload, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            result = response.json()
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
                # Add leading / for URL
                monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
                logger.info("Monitoring job for create %s at %s", policy["name"], monitorapi)
                job_status = self.monitor_job(monitorapi)
                if job_status.get("success"):
                    logger.info("Normalization policy %s created successfully", policy["name"])
                    return {"status": "success"}
                else:
                    error = json.dumps(job_status, indent=2)
                    logger.error("Create job failed for %s: %s", policy["name"], error)
                    return {"status": "failed", "error": error}
            else:
                logger.warning("Unexpected initial response for create %s: %s", policy["name"], json.dumps(result, indent=2))
                return {"status": "failed", "error": json.dumps(result, indent=2)}
        except requests.RequestException as e:
            logger.error("Failed to create normalization policy %s: %s (Response: %s)", policy["name"], str(e), getattr(e.response, 'text', 'No response'))
            return {"status": "failed", "error": str(e)}

    def update_normalization_policy(self, pool_uuid: str, logpoint_id: str, policy_id: str, policy: Dict) -> Dict:
        """Update an existing normalization policy (async).

        Args:
            pool_uuid: Tenant pool UUID.
            logpoint_id: SIEM identifier.
            policy_id: Policy ID.
            policy: Updated policy dictionary with normalization_packages (list of IDs str), compiled_normalizer (list of names str).

        Returns:
            Dict with status 'success' or 'failed', error if failed.
        """
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{policy_id}"
        payload = {
            "data": {
                "norm_packages": ",".join(policy.get("normalization_packages", [])),
                "compiled_normalizer": ",".join(policy.get("compiled_normalizer", []))
            }
        }
        logger.debug("Update request body for %s: %s", url, json.dumps(payload, indent=2))
        try:
            response = self.session.put(url, json=payload, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            result = response.json()
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
                # Add leading / for URL
                monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
                logger.info("Monitoring job for update %s at %s", policy_id, monitorapi)
                job_status = self.monitor_job(monitorapi)
                if job_status.get("success"):
                    logger.info("Normalization policy %s updated successfully", policy_id)
                    return {"status": "success"}
                else:
                    error = json.dumps(job_status, indent=2)
                    logger.error("Update job failed for %s: %s", policy_id, error)
                    return {"status": "failed", "error": error}
            else:
                logger.warning("Unexpected initial response for update %s: %s", policy_id, json.dumps(result, indent=2))
                return {"status": "failed", "error": json.dumps(result, indent=2)}
        except requests.RequestException as e:
            logger.error("Failed to update normalization policy %s: %s (Response: %s)", policy_id, str(e), getattr(e.response, 'text', 'No response'))
            return {"status": "failed", "error": str(e)}
   
    def get_existing_processing_policies(self, pool_uuid: str, logpoint_id: str) -> List[Dict]:
        """Fetch existing processing policies from the SIEM."""
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy"
        try:
            response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            data = response.json()
            policies = data if isinstance(data, list) else data.get("data", [])
            logger.debug("Fetched %d existing processing policies", len(policies))
            return policies
        except requests.RequestException as e:
            logger.error("Failed to fetch existing processing policies: %s", str(e.response.text))
            return []

    def create_processing_policy(self, pool_uuid: str, logpoint_id: str, policy: Dict) -> Dict:
        """Create a new processing policy (async)."""
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy"
        payload = {
            "data": {
                "policy_name": policy["name"],
                "norm_policy": policy.get("norm_policy", ""),
                "enrich_policy": policy.get("enrich_policy", "None"),
                "routing_policy": policy.get("routing_policy", "None"),
                "tid": ""
            }
        }
        logger.debug("Create request body for %s: %s", url, json.dumps(payload, indent=2))
        try:
            response = self.session.post(url, json=payload, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            
            result = response.json()
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
                monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
                logger.info("Monitoring job for create %s at %s", policy["name"], monitorapi)
                job_status = self.monitor_job(monitorapi)
                if job_status.get("success"):
                    logger.info("Processing policy %s created successfully", policy["name"])
                    return {"status": "success"}
                else:
                    error = json.dumps(job_status, indent=2)
                    logger.error("Create job failed for %s: %s", policy["name"], error)
                   
                    return {"status": "failed", "error": error}
            return {"status": "failed", "error": json.dumps(result, indent=2)}
        except requests.RequestException as e:
            logger.error("Failed to create processing policy %s: %s", policy["name"], str(e.response.text))
            return {"status": "failed", "error": str(e)}

    def update_processing_policy(self, pool_uuid: str, logpoint_id: str, policy_id: str, policy: Dict) -> Dict:
        """Update an existing processing policy (async)."""
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{policy_id}"
        payload = {
            "data": {
                "id": policy_id,
                "policy_name": policy["name"],
                "norm_policy": policy.get("norm_policy", ""),
                "enrich_policy": policy.get("enrich_policy", "None"),
                "routing_policy": policy.get("routing_policy", "None"),
                "active": True
            }
        }
        logger.debug("Update request body for %s: %s", url, json.dumps(payload, indent=2))
        try:
            response = self.session.put(url, json=payload, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            result = response.json()
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
                monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
                logger.info("Monitoring job for update %s at %s", policy_id, monitorapi)
                job_status = self.monitor_job(monitorapi)
                if job_status.get("success"):
                    logger.info("Processing policy %s updated successfully", policy_id)
                    return {"status": "success"}
                else:
                    error = json.dumps(job_status, indent=2)
                    logger.error("Update job failed for %s: %s", policy_id, error)
                    return {"status": "failed", "error": error}
            return {"status": "failed", "error": json.dumps(result, indent=2)}
        except requests.RequestException as e:
            logger.error("Failed to update processing policy %s: %s", policy_id, str(e.response.text))
            return {"status": "failed", "error": str(e.response.text)}

    def get_enrichment_sources(self, pool_uuid: str, logpoint_id: str) -> List[str]:
        """Fetch available enrichment sources for a specific node.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.

        Returns:
            List[str]: List of source names (e.g., ['threat_intelligence', 'GeoIp']).

        Raises:
            ValueError: If the JSON response is invalid.
            requests.exceptions.RequestException: If API request fails.
        """
        logger.debug("Fetching enrichment sources for pool %s, node %s", pool_uuid, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/EnrichmentSource"
        response = self.get(url)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise ValueError(f"Invalid response format: {data}")
        sources = [source.get("name", "") for source in data if source.get("name")]
        logger.debug("Retrieved %d sources: %s", len(sources), sources)
        return sources

    def get_enrichment_policies(self, pool_uuid: str, logpoint_id: str) -> List[Dict[str, Any]]:
        """Retrieve existing enrichment policies for a node.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.

        Returns:
            List[Dict[str, Any]]: List of policy dictionaries.
        """
        logger.debug("Fetching enrichment policies for pool %s, node %s", pool_uuid, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy"
        response = self.get(url)
        response.raise_for_status()
        policies = response.json()
        if not isinstance(policies, list):
            logger.warning("Unexpected response format for policies: %s", policies)
            return []
        logger.debug("Found %d existing policies", len(policies))
        return policies

    def create_enrichment_policy(self, pool_uuid: str, logpoint_id: str, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new enrichment policy with async job monitoring.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            policy_data (Dict[str, Any]): The policy data under 'data' key.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Creating enrichment policy on node %s", logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy"
        response = self.post(url, json=policy_data)
        response.raise_for_status()
        result = response.json()
        logger.debug("Creation response: %s", result)

        if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for update %s", monitorapi)
            
            job_success = self.monitor_job(monitorapi)
            if job_success:
                logger.info("Enrichment policy creation succeeded on %s", logpoint_id)
                return {"status": "Success", "result": job_success}
            else:
                logger.error("Enrichment policy creation job failed on %s", logpoint_id)
                return {"status": "Fail", "error": "Job failed"}
        else:
            logger.error("Creation failed on %s: %s", logpoint_id, result.get("error", "Unknown error"))
            return {"status": "Fail", "error": result.get("error", "Unknown error")}

    def update_enrichment_policy(self, pool_uuid: str, logpoint_id: str, policy_id: str, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing enrichment policy with async job monitoring.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            policy_id (str): The policy ID to update.
            policy_data (Dict[str, Any]): The policy data under 'data' key with 'id'.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Updating policy %s on node %s", policy_id, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy/{policy_id}"
        response = self.put(url, json=policy_data)
        response.raise_for_status()
        result = response.json()
        logger.debug("Update response: %s", result)

        if result.get("status") == "Success" and "message" in result and result.get('message', '') and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for update %s at %s", policy_id, monitorapi)
            
            job_success = self.monitor_job(monitorapi)
            if job_success:
                logger.info("Enrichment policy update succeeded on %s", logpoint_id)
                return {"status": "Success", "result": job_success}
            else:
                logger.error("Enrichment policy update job failed on %s", logpoint_id)
                return {"status": "Fail", "error": "Job failed"}
        else:
            logger.error("Update failed on %s: %s", logpoint_id, result.get("error", "Unknown error"))
            return {"status": "Fail", "error": result.get("error", "Unknown error")}
         
    def get_device_groups(self, pool_uuid: str, logpoint_id: str) -> List[Dict[str, Any]]:
        """Retrieve existing device groups for a node.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.

        Returns:
            List[Dict[str, Any]]: List of device group dictionaries.
        """
        logger.debug("Fetching device groups for pool %s, node %s", pool_uuid, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups"
        response = self.get(url)
        response.raise_for_status()
        device_groups = response.json()
        if not isinstance(device_groups, list):
            logger.warning("Unexpected response format for device groups: %s", device_groups)
            return []
        logger.debug("Found %d existing device groups", len(device_groups))
        return device_groups

    def create_device_group(self, pool_uuid: str, logpoint_id: str, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new device group with async job monitoring.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            group_data (Dict[str, Any]): The group data under 'data' key.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Creating device group on node %s", logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups"
        response = self.post(url, json=group_data)
        response.raise_for_status()
        result = response.json()
        logger.debug("Creation response: %s", result)

        if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for update %s", monitorapi)
            
            job_success = self.monitor_job(monitorapi)
            if job_success:
                logger.info("Device group creation succeeded on %s", logpoint_id)
                return {"status": "Success", "result": job_success}
            else:
                logger.error("Device group creation job failed on %s", logpoint_id)
                return {"status": "Fail", "error": "Job failed"}
        else:
            logger.error("Creation failed on %s: %s", logpoint_id, result.get("error", "Unknown error"))
            return {"status": "Fail", "error": result.get("error", "Unknown error")}

    def update_device_group(self, pool_uuid: str, logpoint_id: str, group_id: str, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing device group with async job monitoring.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            group_id (str): The group ID to update.
            group_data (Dict[str, Any]): The group data under 'data' key with 'id'.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Updating device group %s on node %s", group_id, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups/{group_id}"
        response = self.put(url, json=group_data)
        response.raise_for_status()
        result = response.json()
        logger.debug("Update response: %s", result)

        if result.get("status") == "Success" and "message" in result and result.get('message', '') and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for update %s at %s", group_id, monitorapi)
            
            job_success = self.monitor_job(monitorapi)
            if job_success:
                logger.info("Device group update succeeded on %s", logpoint_id)
                return {"status": "Success", "result": job_success}
            else:
                logger.error("Device group update job failed on %s", logpoint_id)
                return {"status": "Fail", "error": "Job failed"}
        else:
            logger.error("Update failed on %s: %s", logpoint_id, result.get("error", "Unknown error"))
            return {"status": "Fail", "error": result.get("error", "Unknown error")}   
        
    def get_devices(self, pool_uuid: str, logpoint_id: str) -> List[Dict[str, Any]]:
        """Retrieve existing devices for a node.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.

        Returns:
            List[Dict[str, Any]]: List of device dictionaries.
        """
        logger.debug("Fetching devices for pool %s, node %s", pool_uuid, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/Devices"
        response = self.get(url)
        response.raise_for_status()
        devices = response.json()
        if not isinstance(devices, list):
            logger.warning("Unexpected response format for devices: %s", devices)
            return []
        logger.debug("Found %d existing devices", len(devices))
        return devices

    def create_device(self, pool_uuid: str, logpoint_id: str, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new device with async job monitoring.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            device_data (Dict[str, Any]): The device data under 'data' key.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Creating device on node %s", logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/Devices"
        response = self.post(url, json=device_data)
        response.raise_for_status()
        result = response.json()
        logger.debug("Creation response: %s", result)

        if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for device creation at %s", monitorapi)
            
            job_result = self.monitor_job(monitorapi)
            if job_result.get("success", False):
                logger.info("Device creation succeeded on %s", logpoint_id)
                return {"status": "Success", "result": job_result}
            else:
                logger.error("Device creation job failed on %s", logpoint_id)
                return {"status": "Fail", "error": "Job failed"}
        else:
            logger.error("Device creation failed on %s: %s", logpoint_id, result.get("error", "Unknown error"))
            return {"status": "Fail", "error": result.get("error", "Unknown error")}

    def update_device(self, pool_uuid: str, logpoint_id: str, device_id: str, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing device with async job monitoring.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            device_id (str): The device ID to update.
            device_data (Dict[str, Any]): The device data under 'data' key with 'id'.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Updating device %s on node %s", device_id, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/Devices/{device_id}"
        response = self.put(url, json=device_data)
        response.raise_for_status()
        result = response.json()
        logger.debug("Update response: %s", result)

        if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for device update at %s", monitorapi)
            
            job_result = self.monitor_job(monitorapi)
            if job_result.get("success", False):
                logger.info("Device update succeeded on %s", logpoint_id)
                return {"status": "Success", "result": job_result}
            else:
                logger.error("Device update job failed on %s", logpoint_id)
                return {"status": "Fail", "error": "Job failed"}
        else:
            logger.error("Device update failed on %s: %s", logpoint_id, result.get("error", "Unknown error"))
            return {"status": "Fail", "error": result.get("error", "Unknown error")}

    def create_syslog_collector(self, pool_uuid: str, logpoint_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new Syslog Collector with async job monitoring.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            payload (Dict[str, Any]): The collector data under 'data' key.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Creating Syslog Collector on node %s", logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/SyslogCollector"
        response = self.post(url, json=payload)
        response.raise_for_status()
        result = response.json()
        logger.debug("Creation response: %s", result)

        if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for Syslog Collector creation at %s", monitorapi)
            job_result = self.monitor_job(monitorapi)
            if job_result.get("success", False):
                logger.info("Syslog Collector creation succeeded on %s", logpoint_id)
                return {"status": "Success", "message": monitorapi}
            else:
                logger.error("Syslog Collector creation job failed on %s", logpoint_id)
                return {"status": "Fail", "error": job_result.get("error", "Unknown error")}
        else:
            error = json.dumps(job_result, indent=2)
            logger.error("Create job failed for %s", error)
            logger.error("Syslog Collector creation failed on %s: %s", logpoint_id, error)
            return {"status": "Fail", "error": error}

    def update_syslog_collector(self, pool_uuid: str, logpoint_id: str, collector_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing Syslog Collector with async job monitoring.

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            collector_id (str): The Syslog Collector ID to update.
            payload (Dict[str, Any]): The updated collector data under 'data' key with 'id'.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Updating Syslog Collector %s on node %s", collector_id, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/SyslogCollector/{collector_id}"
        response = self.put(url, json=payload)
        response.raise_for_status()
        result = response.json()
        logger.debug("Update response: %s", result)

        if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for Syslog Collector update at %s", monitorapi)
            job_result = self.monitor_job(monitorapi)
            if job_result.get("success", False):
                logger.info("Syslog Collector update succeeded on %s", logpoint_id)
                return {"status": "Success", "message": monitorapi}
            else:
                logger.error("Syslog Collector update job failed on %s", logpoint_id)
                return {"status": "Fail", "error": job_result.get("error", "Unknown error")}
        else:
            logger.error("Syslog Collector update failed on %s: %s", logpoint_id, result.get("error", "Unknown error"))
            return {"status": "Fail", "error": result.get("error", "Unknown error")}

    def delete_syslog_collector(self, pool_uuid: str, logpoint_id: str, collector_id: str) -> Dict[str, Any]:
        """Delete an existing Syslog Collector with async job monitoring (optional).

        Args:
            pool_uuid (str): The tenant pool UUID.
            logpoint_id (str): The SIEM node ID.
            collector_id (str): The Syslog Collector ID to delete.

        Returns:
            Dict[str, Any]: API response with 'status' and job result.

        Raises:
            requests.exceptions.RequestException: If API call fails.
        """
        logger.debug("Deleting Syslog Collector %s on node %s", collector_id, logpoint_id)
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/SyslogCollector/{collector_id}"
        response = self.session.delete(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
        response.raise_for_status()
        result = response.json()
        logger.debug("Delete response: %s", result)

        if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
            monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
            logger.info("Monitoring job for Syslog Collector deletion at %s", monitorapi)
            job_result = self.monitor_job(monitorapi)
            if job_result.get("success", False):
                logger.info("Syslog Collector deletion succeeded on %s", logpoint_id)
                return {"status": "Success", "message": monitorapi}
            else:
                logger.error("Syslog Collector deletion job failed on %s", logpoint_id)
                return {"status": "Fail", "error": job_result.get("error", "Unknown error")}
        else:
            logger.error("Syslog Collector deletion failed on %s: %s", logpoint_id, result.get("error", "Unknown error"))
            return {"status": "Fail", "error": result.get("error", "Unknown error")}
