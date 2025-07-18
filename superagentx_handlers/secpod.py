import logging
import os

import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

SECPOD_BASE_URL = "https://saner.secpod.com"
SECPOD_API_ENDPOINT = "/AncorWebService/perform"

class SecPodHandler(BaseHandler):
    """
    A handler for managing interactions with SecPod SanerNow for vulnerability data.
    This class provides methods to retrieve vulnerability information.
    """

    def __init__(
        self,
        api_key: str = None,
        base_url: str = SECPOD_BASE_URL
    ):
        super().__init__()
        self.api_key = api_key or os.getenv("SECPOD_API_KEY")
        self.base_url = base_url

        if not self.api_key:
            logger.error("SecPod API Key not provided or set in SECPOD_API_KEY environment variable. "
                         "Handler will not be able to make API calls.")
            return

        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"SAML {self.api_key}"
            }
            self.client = aiohttp.ClientSession(base_url=self.base_url, headers=headers)
            logger.debug("SecPodHandler initialized with API credentials.")
            self._is_initialized = True
        except Exception as e:
            logger.error(f"Error initializing SecPodHandler: {e}", exc_info=True)
            self._is_initialized = False

    @tool
    async def list_vulnerabilities(self, discovered_after: int = None) -> list:
        """
        Asynchronously lists all vulnerabilities from SecPod SanerNow with all available details.
        Optionally, takes a Unix timestamp (in milliseconds) to list vulnerabilities discovered after that time.

        Parameter:
            discovered_after (int): A Unix timestamp (in milliseconds)
                                    to filter vulnerabilities discovered
                                    after this time. If None or 0, no time filter is applied.
        """
        final_vulnerabilities: list = []

        try:
            payload = {
                "command": "listVulnerabilities",
                "parameters": {}
            }
            if discovered_after:
                payload["parameters"]["startDetectedDate"] = discovered_after

            logger.info("Initiating SecPod vulnerability listing.")
            async with self.client.post(SECPOD_API_ENDPOINT, json=payload) as response:
                response.raise_for_status()
                response_data = await response.json()

            if (isinstance(response_data, dict)
                    and "data" in response_data
                    and isinstance(response_data["data"], list)):
                final_vulnerabilities = response_data["data"]
            elif (isinstance(response_data, dict)
                  and "vulnerabilities" in response_data
                  and isinstance(response_data["vulnerabilities"], list)):
                final_vulnerabilities = response_data["vulnerabilities"]
            elif isinstance(response_data, list):
                final_vulnerabilities = response_data
            else:
                logger.warning("SecPod API response format unexpected. Returning empty list.")
                final_vulnerabilities = []

            logger.info(f"Successfully retrieved {len(final_vulnerabilities)} vulnerabilities from SecPod.")

        except aiohttp.ClientResponseError as e:
            logger.error(
                f"HTTP error during SecPod API call: {e.status} - {e.message}", # Access status and message
                exc_info=True
            )
        except aiohttp.ClientError as e:
            logger.error(
                f"Network error during SecPod API call: {e}",
                exc_info=True
            )
        except Exception as e:
            logger.error(
                f"An unexpected error occurred while listing SecPod vulnerabilities: {e}",
                exc_info=True
            )

        return final_vulnerabilities
