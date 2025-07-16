import os
import logging
import aiohttp  # Using aiohttp for async HTTP requests
import asyncio  # For async operations like polling
import time  # For timestamps

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from typing import Dict, Any  # Keep Dict, Any for type hints if specific keys are needed

logger = logging.getLogger(__name__)

# Base URL for Tenable.io API - adjust if using Nessus Manager directly or a different cloud instance
TENABLE_IO_BASE_URL = "https://cloud.tenable.com"
VULN_EXPORT_API_PATH = "/vulns/export"
VULN_EXPORT_STATUS_PATH = "/vulns/export/{export_uuid}/status"
VULN_EXPORT_CHUNKS_PATH = "/vulns/export/{export_uuid}/chunks/{chunk_id}"


class NessusHandler(BaseHandler):
    """
    A handler for managing interactions with Tenable.io (Nessus) for vulnerability data.
    This class provides methods to retrieve vulnerability information.
    """

    def __init__(
            self,
            access_key: str = None,
            secret_key: str = None,
            base_url: str = TENABLE_IO_BASE_URL
    ):
        super().__init__()
        self.access_key = access_key or os.getenv("TENABLE_ACCESS_KEY")
        self.secret_key = secret_key or os.getenv("TENABLE_SECRET_KEY")
        self.base_url = base_url
        self._is_initialized = False
        self.client: aiohttp.ClientSession = None  # Initialize client as None

        if not self.access_key or not self.secret_key:
            logger.error("Tenable Access Key or Secret Key not provided. "
                         "Handler will not be able to make API calls.")
            return

        try:
            # Initialize aiohttp.ClientSession
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Tenable-Access-Key": self.access_key,
                "Tenable-Secret-Key": self.secret_key
            }
            # aiohttp.ClientSession should be created within an async context,
            # but for handler initialization, we create it here and rely on
            # the close method for proper cleanup.
            self.client = aiohttp.ClientSession(base_url=self.base_url, headers=headers)
            logger.debug("NessusHandler initialized with Tenable.io API credentials.")
            self._is_initialized = True
        except Exception as e:
            logger.error(f"Error initializing NessusHandler: {e}", exc_info=True)
            self._is_initialized = False

    async def close(self):
        """
        Closes the aiohttp client session.
        It's important to call this when the handler is no longer needed.
        """
        if self.client and not self.client.closed:
            await self.client.close()
            logger.debug("NessusHandler aiohttp client session closed.")

    @tool
    async def list_vulnerabilities(self, discovered_after: int = None) -> list:
        """
        Lists all vulnerabilities from Nessus (Tenable.io) with all available details.
        Optionally, takes a Unix timestamp (in milliseconds) to list vulnerabilities discovered after that time.

        Parameter:
            discovered_after (int): A Unix timestamp (in milliseconds)
                                    to filter vulnerabilities discovered
                                    after this time. If None or 0, no time filter is applied.
        """
        if not self._is_initialized:
            logger.error("NessusHandler not initialized. Cannot list vulnerabilities.")
            return []

        final_vulnerabilities: list = []

        try:
            payload = {}
            if discovered_after:
                payload["filters"] = {
                    "last_found": {
                        "gt": discovered_after
                    }
                }

            logger.info("Initiating Nessus vulnerability export job.")
            async with self.client.post(VULN_EXPORT_API_PATH, json=payload) as response:
                response.raise_for_status()  # Raises aiohttp.ClientResponseError for bad responses
                export_data = await response.json()

            export_uuid = export_data.get("export_uuid")

            if not export_uuid:
                logger.error("Failed to initiate vulnerability export: No export_uuid received.")
            else:
                logger.debug(f"Nessus export job initiated with UUID: {export_uuid}")

                status = ""
                status_data = {}
                while status != "ready":
                    logger.debug(f"Polling Nessus export job {export_uuid} status...")
                    async with self.client.get(
                            VULN_EXPORT_STATUS_PATH.format(export_uuid=export_uuid)) as status_response:
                        status_response.raise_for_status()
                        status_data = await status_response.json()

                    status = status_data.get("status")

                    if status == "error":
                        logger.error(f"Nessus export job {export_uuid} failed with error status.")
                        break

                    if status != "ready":
                        await asyncio.sleep(5)

                if status == "ready":
                    logger.info(f"Nessus export job {export_uuid} is ready. Downloading chunks.")

                    chunks = status_data.get("chunks", [])
                    for chunk_id in chunks:
                        logger.debug(f"Downloading chunk {chunk_id} for export {export_uuid}...")
                        async with self.client.get(
                                VULN_EXPORT_CHUNKS_PATH.format(export_uuid=export_uuid, chunk_id=chunk_id)
                        ) as chunk_response:
                            chunk_response.raise_for_status()
                            final_vulnerabilities.extend(await chunk_response.json())
                        logger.debug(f"Downloaded chunk {chunk_id}. "
                                     f"Total vulnerabilities so far: {len(final_vulnerabilities)}")

                    logger.info(f"Successfully retrieved {len(final_vulnerabilities)} vulnerabilities from Nessus.")

        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error during Nessus API call: {e.status} - {e.message}",
                         exc_info=True)
            final_vulnerabilities = []
        except aiohttp.ClientError as e:
            logger.error(f"Client error during Nessus API call: {e}", exc_info=True)
            final_vulnerabilities = []
        except Exception as e:
            logger.error(f"An unexpected error occurred while listing Nessus vulnerabilities: {e}", exc_info=True)
            final_vulnerabilities = []

        return final_vulnerabilities
