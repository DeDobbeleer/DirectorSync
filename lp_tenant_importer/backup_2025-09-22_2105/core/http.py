import os
import logging
import json
from pathlib import Path
from typing import Dict, Any, Optional
import requests
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from retrying import retry

from logging_utils import setup_logging

logger = logging.getLogger(__name__)


class DirectorClient:
    """HTTP client for Logpoint Director API with auth, retries, and logging."""

    def __init__(
        self,
        base_url: str,
        token: str,
        verify: bool = True,
        timeout: int = 30,
        proxies: Optional[Dict[str, str]] = None,
        artifacts_dir: str = "./artifacts",
    ) -> None:
        """Initialize the client with API configuration.

        Args:
            base_url: Base URL for Logpoint Director API.
            token: Bearer token for authentication.
            verify: Whether to verify TLS certificates.
            timeout: Request timeout in seconds.
            proxies: Optional HTTP/HTTPS proxy settings.
            artifacts_dir: Directory to save API artifacts.

        Raises:
            ValueError: If base_url or token is empty.
        """
        if not base_url or not token:
            logger.error("Base URL or token is empty")
            raise ValueError("Base URL and token must be provided")
        
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify = verify
        self.timeout = timeout
        self.proxies = proxies or {}
        self.artifacts_dir = Path(artifacts_dir)
        self.session = Session()
        
        # Configure retries
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def _retry_on_error(self, response: requests.Response) -> bool:
        """Determine if a response requires a retry.

        Args:
            response: HTTP response object.

        Returns:
            True if status code is 429 or 5xx, False otherwise.
        """
        return response.status_code in {429, 500, 502, 503, 504}

    @retry(retry_on_result=_retry_on_error, stop_max_attempt_number=3, wait_exponential_multiplier=1000)
    def _request(
        self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Execute HTTP request with logging and artifact saving.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            endpoint: API endpoint (e.g., '/api/v1/pools/...').
            data: Optional JSON payload for POST/PUT.
            params: Optional query parameters.

        Returns:
            Response JSON as a dictionary.

        Raises:
            requests.RequestException: If the request fails.
        """
        url = f"{self.base_url}{endpoint}"
        log_data = {"method": method.upper(), "url": url, "params": params}

        if os.getenv("LP_HTTP_DEBUG", "false").lower() == "true":
            log_data["headers"] = dict(self.session.headers)
        if os.getenv("LP_LOG_BODY_FULL", "false").lower() == "true" and data:
            log_data["data"] = data

        logger.debug("API request: %s", json.dumps(log_data, ensure_ascii=False))

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout,
                verify=self.verify,
                proxies=self.proxies,
            )
            response.raise_for_status()

            log_response = {"status": response.status_code, "url": url}
            if os.getenv("LP_LOG_BODY_FULL", "false").lower() == "true":
                try:
                    log_response["body"] = response.json()
                except ValueError:
                    log_response["body"] = response.text[:1000]  # Limit non-JSON

            logger.debug("API response: %s", json.dumps(log_response, ensure_ascii=False))
            self._save_artifact(method, url, data, response)
            return response.json() if response.text else {}

        except requests.RequestException as e:
            logger.error("API request failed: %s %s - %s", method, url, str(e))
            raise

    def _save_artifact(
        self, method: str, url: str, data: Optional[Dict], response: requests.Response
    ) -> None:
        """Save request and response as JSON artifact.

        Args:
            method: HTTP method.
            url: Request URL.
            data: Request payload, if any.
            response: HTTP response object.
        """
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        timestamp = response.headers.get("Date", "unknown").replace(":", "_")
        filename = self.artifacts_dir / f"api_{method}_{url.replace('/', '_')}_{timestamp}.json"
        artifact = {
            "method": method,
            "url": url,
            "request_data": data,
            "status": response.status_code,
            "response_body": response.json() if response.text else None,
        }
        try:
            with filename.open("w", encoding="utf-8") as file:
                json.dump(artifact, file, ensure_ascii=False, indent=2)
            logger.debug("Saved artifact: %s", filename)
        except Exception as e:
            logger.warning("Failed to save artifact %s: %s", filename, str(e))

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Send GET request to the API.

        Args:
            endpoint: API endpoint.
            params: Optional query parameters.

        Returns:
            Response JSON as a dictionary.
        """
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send POST request to the API.

        Args:
            endpoint: API endpoint.
            data: JSON payload.

        Returns:
            Response JSON as a dictionary.
        """
        return self._request("POST", endpoint, data=data)

    def put(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send PUT request to the API.

        Args:
            endpoint: API endpoint.
            data: JSON payload.

        Returns:
            Response JSON as a dictionary.
        """
        return self._request("PUT", endpoint, data=data)

    def delete(self, endpoint: str) -> Dict[str, Any]:
        """Send DELETE request to the API.

        Args:
            endpoint: API endpoint.

        Returns:
            Response JSON as a dictionary.
        """
        return self._request("DELETE", endpoint)

    def build_endpoint(self, pool_uuid: str, siem_id: str, resource: str) -> str:
        """Build API endpoint for a specific resource.

        Args:
            pool_uuid: Tenant pool UUID.
            siem_id: SIEM ID.
            resource: API resource (e.g., 'repos', 'alerts').

        Returns:
            Formatted endpoint string.
        """
        return f"/api/v1/pools/{pool_uuid}/siems/{siem_id}/{resource}"


if __name__ == "__main__":
    setup_logging()
    client = DirectorClient(
        base_url=os.getenv("LP_DIRECTOR_URL", "https://example.com"),
        token=os.getenv("LP_TOKEN", "dummy"),
        verify=os.getenv("LP_VERIFY", "true").lower() == "true",
        timeout=int(os.getenv("LP_HTTP_TIMEOUT", "30")),
    )
    endpoint = client.build_endpoint("pool_uuid", "siem_id", "repos")
    logger.debug("Sample endpoint: %s", endpoint)