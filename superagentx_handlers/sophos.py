import os
import aiohttp
import logging
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

class SophosHandler(BaseHandler):
    """
    A handler for interacting with Sophos Central API using OAuth2 client credentials.
    Provides tools to retrieve endpoint antivirus status, firewall rules, and whitelisting policies.

    Args:
        client_id (str): OAuth2 client ID for Sophos API.
        client_secret (str): OAuth2 client secret.
        token_url (str): URL to retrieve access token from Sophos.
        whoami_url (str): URL to identify the tenant and region.
    """

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        token_url: str | None = None,
        whoami_url: str | None = None
    ):
        """
        Initializes the SophosHandler with client credentials and optional override URLs.
        Fetches values from environment variables if not provided directly.
        Raises:
            ValueError: If client_id or client_secret is not provided.
        """
        super().__init__()

        self.client_id = client_id or os.getenv("SOPHOS_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("SOPHOS_CLIENT_SECRET")
        self.token_url = token_url or os.getenv("SOPHOS_TOKEN_URL") or "https://id.sophos.com/api/v2/oauth2/token"
        self.whoami_url = whoami_url or os.getenv("SOPHOS_WHOAMI_URL") or "https://api.central.sophos.com/whoami/v1"

        if not self.client_id or not self.client_secret:
            raise ValueError("Sophos client_id and client_secret are required.")

        self.access_token = None
        self.tenant_id = None
        self.api_url = None

        self._headers = {
            "Authorization": f"Bearer {self.access_token}",
            "X-Tenant-ID": self.tenant_id
        }

    @tool
    async def get_out_of_date_av(
            self
    ):
        """
        Retrieve a list of endpoint devices with out-of-date antivirus definitions.
        Returns:
            dict: JSON response containing endpoint health status.
        """
        await self.authenticate()
        url = f"{self.api_url}/endpoint/v1/endpoints?health.status=outOfDate"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers) as resp:
                resp.raise_for_status()
                return await resp.json()

    @tool
    async def get_host_firewall_rules(
            self
    ):
        """
        Retrieve all host-based firewall rules configured in Sophos Central.
        Returns:
            dict: JSON response containing firewall rule information.
        """
        await self.authenticate()
        url = f"{self.api_url}/endpoint/v1/firewall-rules"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers) as resp:
                resp.raise_for_status()
                return await resp.json()

    @tool
    async def get_application_whitelisting(
            self
    ):
        """
        Retrieve application control policies that define whitelisted applications.

        Returns:
            dict: JSON response containing application control policies.
        """
        await self.authenticate()
        url = f"{self.api_url}/endpoint/v1/application-control/policies"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def authenticate(
            self
    ):
        """
        Authenticate with the Sophos API using client credentials.
        Retrieves and sets the access token, tenant ID, and region-specific API URL.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    self.access_token = data.get("access_token")

                async with session.get(
                    self.whoami_url,
                    headers={"Authorization": f"Bearer {self.access_token}"}
                ) as whoami_resp:
                    whoami_resp.raise_for_status()
                    whoami_data = await whoami_resp.json()
                    self.tenant_id = whoami_data.get("id")
                    self.api_url = whoami_data.get("apiHosts", {}).get("dataRegion")

                self._headers = {
                    "Authorization": f"Bearer {self.access_token}",
                    "X-Tenant-ID": self.tenant_id
                }

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise
