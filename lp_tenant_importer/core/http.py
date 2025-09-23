import requests
import time
from urllib.parse import urlparse
from logging_utils import logger

class DirectorClient:
    def __init__(self, base_url, api_token, verify_ssl=True):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "User-Agent": "python-requests/2.32.5",
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        logger.debug(f"Initialized with base_url={base_url}, api_token=**** (length={len(api_token)}), verify_ssl={verify_ssl}")

    def make_api_request(self, method, endpoint, payload=None):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            logger.debug(f"Making {method} request to {url} with payload: {payload}")
            response = requests.request(
                method,
                url,
                json=payload,
                headers=self.headers,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            result = response.json() if response.content else {}
            logger.debug(f"Raw response from {url}: {result}")
            return result
        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {str(e)}")
            return {"status": "Error", "errors": [str(e)]}

    def monitor_job(self, monitor_url, pool_uuid, logpoint_identifier, max_attempts=30, interval=2):
        """Monitor an async job until completion or timeout."""
        logger.info(f"Monitoring job at {monitor_url}")
        try:
            # Extraire request_id depuis l'URL (ex. : monitorapi/.../orders/{request_id})
            parsed_url = urlparse(f"https://dummy/{monitor_url}")
            request_id = parsed_url.path.split("/")[-1]
            endpoint = f"/monitorapi/{pool_uuid}/{logpoint_identifier}/orders/{request_id}"
            
            for attempt in range(1, max_attempts + 1):
                response = self.make_api_request("GET", endpoint)
                logger.debug(f"Raw response from {endpoint}: {response}")
                
                response_data = response.get("response", {})
                success = response_data.get("success")
                errors = response_data.get("errors", [])
                
                logger.debug(f"Job status (attempt {attempt}/{max_attempts}): success={success}, errors={errors}")
                
                # Sortir dès que success est défini (True/False) ou errors non vide
                if success is not None or errors:
                    if success:
                        logger.info(f"Job succeeded: {response_data.get('message', 'No message')}")
                    else:
                        logger.error(f"Job failed: {errors or ['No error details']}")
                    return response_data
                else:
                    logger.info(f"Job pending (attempt {attempt}/{max_attempts})")
                    if attempt < max_attempts:
                        time.sleep(interval)
            
            logger.error(f"Job monitoring timed out after {max_attempts * interval}s")
            # Fallback : Retourner timeout mais sans retry
            return {"success": False, "errors": ["Timeout - operation may still be processing"]}
        except Exception as e:
            logger.error(f"Error monitoring job: {str(e)}")
            return {"success": False, "errors": [str(e)]}