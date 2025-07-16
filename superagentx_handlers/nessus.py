import os
import logging
import httpx # Using httpx for async HTTP requests
import asyncio # For async operations like polling
import time # For timestamps

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from typing import List, Dict, Any

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
        self._is_initialized = False # Initialize flag for handler readiness

        # Explicitly check for critical configuration, but log and set flag instead of raising
        if not self.access_key or not self.secret_key:
            logger.error("Tenable Access Key or Secret Key not provided. "
                         "Handler will not be able to make API calls.")
            return # Exit init early if critical config is missing

        try:
            self.client = httpx.AsyncClient(base_url=self.base_url)
            self.client.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Tenable-Access-Key": self.access_key,
                "Tenable-Secret-Key": self.secret_key
            })
            logger.debug("NessusHandler initialized with Tenable.io API credentials.")
            self._is_initialized = True
        except Exception as e:
            logger.error(f"Error initializing NessusHandler: {e}", exc_info=True)
            self._is_initialized = False # Ensure flag is false on failure

    @tool
    async def list_vulnerabilities(self, discovered_after: int = None) -> List[Dict[str, Any]]:
        """
        Asynchronously lists all vulnerabilities from Nessus (Tenable.io) with all available details.
        Optionally, takes a Unix timestamp (in milliseconds) to list vulnerabilities discovered after that time.

        Parameter:
            discovered_after (int, optional): A Unix timestamp (in milliseconds)
                                              to filter vulnerabilities discovered
                                              after this time. If None or 0, no time filter is applied.
        """
        if not self._is_initialized:
            logger.error("NessusHandler not initialized. Cannot list vulnerabilities.")
            return []

        # Initialize result variable outside try-except for single return point
        final_vulnerabilities: List[Dict[str, Any]] = []

        try:
            # Prepare export request payload
            payload = {}
            if discovered_after:
                payload["filters"] = {
                    "last_found": {
                        "gt": discovered_after
                    }
                }
            # else: payload remains an empty dictionary, meaning no filters applied (all vulnerabilities)

            # Step 1: Initiate the vulnerability export job
            logger.info("Initiating Nessus vulnerability export job.")
            response = await self.client.post(VULN_EXPORT_API_PATH, json=payload)
            response.raise_for_status()
            export_data = response.json()
            export_uuid = export_data.get("export_uuid")

            if not export_uuid:
                logger.error("Failed to initiate vulnerability export: No export_uuid received.")
                # final_vulnerabilities remains empty
            else:
                logger.debug(f"Nessus export job initiated with UUID: {export_uuid}")

                # Step 2: Poll the export job status until it's ready
                status = ""
                status_data = {}
                while status != "ready":
                    logger.debug(f"Polling Nessus export job {export_uuid} status...")
                    status_response = await self.client.get(VULN_EXPORT_STATUS_PATH.format(export_uuid=export_uuid))
                    status_response.raise_for_status()
                    status_data = status_response.json()
                    status = status_data.get("status")

                    if status == "error":
                        logger.error(f"Nessus export job {export_uuid} failed with error status.")
                        break # Exit the polling loop on error

                    if status != "ready":
                        await asyncio.sleep(5) # Wait 5 seconds before polling again

                if status == "ready": # Only proceed to download if status is ready
                    logger.info(f"Nessus export job {export_uuid} is ready. Downloading chunks.")

                    # Step 3: Download chunks and collect vulnerabilities
                    chunks = status_data.get("chunks", [])
                    for chunk_id in chunks:
                        logger.debug(f"Downloading chunk {chunk_id} for export {export_uuid}...")
                        chunk_response = await self.client.get(
                            VULN_EXPORT_CHUNKS_PATH.format(export_uuid=export_uuid, chunk_id=chunk_id)
                        )
                        chunk_response.raise_for_status()
                        final_vulnerabilities.extend(chunk_response.json())
                        logger.debug(f"Downloaded chunk {chunk_id}. "
                                     f"Total vulnerabilities so far: {len(final_vulnerabilities)}")

                    logger.info(f"Successfully retrieved {len(final_vulnerabilities)} vulnerabilities from Nessus.")

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during Nessus API call: {e.response.status_code} - {e.response.text}",
                         exc_info=True)
            final_vulnerabilities = [] # Ensure empty list on HTTP error
        except httpx.RequestError as e:
            logger.error(f"Network error during Nessus API call: {e}", exc_info=True)
            final_vulnerabilities = [] # Ensure empty list on network error
        except Exception as e:
            logger.error(f"An unexpected error occurred while listing Nessus vulnerabilities: {e}", exc_info=True)
            final_vulnerabilities = [] # Ensure empty list on unexpected error

        return final_vulnerabilities # Single return point for the function
