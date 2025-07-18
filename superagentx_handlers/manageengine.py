import logging
import os

import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

# Base URL for Tenable.io API
TENABLE_IO_BASE_URL = "https://cloud.tenable.com"


class ManageEngineHandler(BaseHandler):
    """
    A handler for integrating with Tenable.io APIs, providing tools to manage
    assets, scans, and import vulnerabilities. This handler is designed to be
    used as a source of Tenable.io data for ManageEngine platform.
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

        if not self.access_key or not self.secret_key:
            logger.error("Tenable Access Key or Secret Key not provided. "
                         "Handler will not be able to make API calls. "
                         "Please set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY environment variables.")
            return

        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Tenable-Access-Key": self.access_key,
                "Tenable-Secret-Key": self.secret_key
            }
            self.client = aiohttp.ClientSession(base_url=self.base_url, headers=headers)
            logger.debug("ManageEngineHandler initialized successfully.")
            self._is_initialized = True
        except Exception as e:
            logger.error(f"Error initializing ManageEngineHandler: {e}", exc_info=True)
            self._is_initialized = False

    @staticmethod
    async def _list_all_paginated_data(
            client: aiohttp.ClientSession,
            path: str,
            result_key: str,
            params: dict = None
    ) -> list:
        """
        Helper method to handle pagination for Tenable.io API calls.
        Tenable.io uses offset/limit pagination.
        """
        all_data: list = []
        offset = 0
        limit = 200

        while True:
            current_params = params.copy() if params else {}
            current_params['offset'] = offset
            current_params['limit'] = limit

            try:
                async with client.get(path, params=current_params) as response:
                    response.raise_for_status()
                    data = await response.json()

                items = data.get(result_key, [])
                all_data.extend(items)

                total = data.get('pagination', {}).get('total')
                if total is None:
                    if len(items) < limit:
                        break
                elif offset + len(items) >= total:
                    break

                offset += len(items)
                if not items and total is not None:
                    break

            except aiohttp.ClientResponseError as e:
                logger.error(f"HTTP error during pagination for {path}: {e.status} - {e.message}", exc_info=True)
                break
            except aiohttp.ClientError as e:
                logger.error(f"Network error during pagination for {path}: {e}", exc_info=True)
                break
            except Exception as e:
                logger.error(f"An unexpected error occurred during pagination for {path}: {e}", exc_info=True)
                break
        return all_data

    @tool
    async def list_assets(self) -> list:
        """
        Retrieves a list of assets.
        """
        path = "/assets"
        assets: list = []
        try:
            assets = await self._list_all_paginated_data(self.client, path, 'assets')
            logger.info(f"Successfully retrieved {len(assets)} assets.")
        except Exception as e:
            logger.error(f"Error listing assets: {e}", exc_info=True)
        return assets

    @tool
    async def get_asset_info(self, asset_id: str) -> dict | None:
        """
        Retrieves detailed information for a specific asset.

        Parameters:
            asset_id (str): The unique ID of the asset.
        """
        path = f"/assets/{asset_id}"
        asset_info: dict | None = None
        try:
            async with self.client.get(path) as response:
                response.raise_for_status()
                asset_info = await response.json()
            logger.info(f"Successfully retrieved info for asset ID: {asset_id}.")
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error getting asset {asset_id} info: {e.status} - {e.message}", exc_info=True)
        except aiohttp.ClientError as e:
            logger.error(f"Network error getting asset {asset_id} info: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred getting asset {asset_id} info: {e}", exc_info=True)
        return asset_info

    @tool
    async def list_scans(self, folder_id: int = None) -> list:
        """
        Retrieves a list of scans.

        Parameters:
            folder_id (int, optional): The ID of the folder to list scans from.
        """
        path = "/scans"
        params = {'folder_id': folder_id} if folder_id is not None else {}
        scans: list = []
        try:
            all_scans: list = []
            offset = 0
            limit = 50
            while True:
                current_params = params.copy()
                current_params['offset'] = offset
                current_params['limit'] = limit
                async with self.client.get(path, params=current_params) as response:
                    response.raise_for_status()
                    data = await response.json()

                scans_page = data.get('scans', [])
                all_scans.extend(scans_page)

                if len(scans_page) < limit:
                    break
                offset += limit

            scans = all_scans
            logger.info(f"Successfully retrieved {len(scans)} scans.")
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error listing scans: {e.status} - {e.message}", exc_info=True)
        except aiohttp.ClientError as e:
            logger.error(f"Network error listing scans: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred listing scans: {e}", exc_info=True)
        return scans

    @tool
    async def get_scan_details(self, scan_id: int) -> dict | None:
        """
        Retrieves detailed information for a specific scan.

        Parameters:
            scan_id (int): The ID of the scan.
        """
        path = f"/scans/{scan_id}"
        scan_details: dict | None = None
        try:
            async with self.client.get(path) as response:
                response.raise_for_status()
                scan_details = await response.json()
            logger.info(f"Successfully retrieved details for scan ID: {scan_id}.")
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error getting scan {scan_id} details: {e.status} - {e.message}", exc_info=True)
        except aiohttp.ClientError as e:
            logger.error(f"Network error getting scan {scan_id} details: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred getting scan {scan_id} details: {e}", exc_info=True)
        return scan_details

    @tool
    async def get_scan_history(self, scan_id: int) -> list:
        """
        Retrieves the history of a specific scan.

        Parameters:
            scan_id (int): The ID of the scan.
        """
        path = f"/scans/{scan_id}/history"
        scan_history: list = []
        try:
            async with self.client.get(path) as response:
                response.raise_for_status()
                data = await response.json()
                scan_history = data.get('history', [])
            logger.info(f"Successfully retrieved history for scan ID: {scan_id}.")
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error getting scan {scan_id} history: {e.status} - {e.message}", exc_info=True)
        except aiohttp.ClientError as e:
            logger.error(f"Network error getting scan {scan_id} history: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred getting scan {scan_id} history: {e}", exc_info=True)
        return scan_history

    @tool
    async def get_scan_history_details(self, scan_id: int, history_id: int) -> dict | None:
        """
        Retrieves detailed information for a specific scan history entry.

        Parameters:
            scan_id (int): The ID of the scan.
            history_id (int): The ID of the scan history entry.
        """
        path = f"/scans/{scan_id}/history/{history_id}"
        history_details: dict | None = None
        try:
            async with self.client.get(path) as response:
                response.raise_for_status()
                history_details = await response.json()
            logger.info(f"Successfully retrieved details for scan history {history_id} of scan {scan_id}.")
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error getting scan history {history_id} details: {e.status} - {e.message}",
                         exc_info=True)
        except aiohttp.ClientError as e:
            logger.error(f"Network error getting scan history {history_id} details: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred getting scan history {history_id} details: {e}",
                         exc_info=True)
        return history_details

    @tool
    async def import_vulnerabilities(self, source: str, vuln_type: str, assets: list) -> dict:
        """
        Imports vulnerability data into Tenable.io.

        Parameters:
            source (str): The source of the scan that generated the vulnerability data (e.g., 'security_center').
            vuln_type (str): The type of scan that identified the vulnerabilities (e.g., 'vm', 'was', 'pc').
            assets (list): An array of asset objects with vulnerabilities information.
        """
        path = "/import/vulnerabilities"
        payload = {
            "source": source,
            "type": vuln_type,
            "assets": assets
        }

        import_status: dict = {}
        try:
            async with self.client.post(path, json=payload) as response:
                response.raise_for_status()
                import_status = await response.json()
            logger.info(f"Successfully initiated vulnerability import.")
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error during vulnerability import: {e.status} - {e.message}",
                         exc_info=True)
            import_status = {"error": f"HTTP Error: {e.status} - {e.message}"}
        except aiohttp.ClientError as e:
            logger.error(f"Network error during vulnerability import: {e}", exc_info=True)
            import_status = {"error": f"Network Error: {e}"}
        except Exception as e:
            logger.error(f"An unexpected error occurred during vulnerability import: {e}",
                         exc_info=True)
            import_status = {"error": f"Unexpected Error: {e}"}
        return import_status

