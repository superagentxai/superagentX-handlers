import os
import logging
import aiohttp

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

class ZohoHIRSHandler(BaseHandler):
    def __init__(self, access_token: str = None):
        super().__init__()
        self.base_url = "https://people.zoho.com/people/api"
        self.access_token = access_token or os.getenv("ZOHO_PEOPLE_ACCESS_TOKEN")
        self.headers = {
            "Authorization": f"Zoho-oauthtoken {self.access_token}",
            "Accept": "application/json"
        }

    async def _get(self, endpoint: str, params=None):
        """
        Internal helper to perform a GET request to a Zoho People API endpoint.

        Args:
            endpoint (str): The relative API endpoint (e.g., 'forms/P_EmployeeView/records').
            params (dict, optional): Optional query parameters to send with the request.

        Returns:
            dict: Parsed JSON response from the API, or an empty dict in case of failure.
        """
        url = f"{self.base_url}/{endpoint}"
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, params=params or {}) as response:
                    if response.status != 200:
                        text = await response.text()
                        logger.error(f"GET {endpoint} failed: {response.status} - {text}")
                        return {}
                    return await response.json()
        except Exception as e:
            logger.error(f"GET {endpoint} exception: {e}")
            return {}

    @tool
    async def list_employees(self):
        """
        Retrieves the list of all employees in the Zoho People organization.

        Returns:
            list: A list of employee records (each a dict).
        """
        logger.info("Fetching employee list...")
        result = await self._get("forms/P_EmployeeView/records")
        return result.get("data", [])

    @tool
    async def list_onboarding_workflows(self):
        """
        Retrieves the list of onboarding workflows configured in Zoho People.

        Returns:
            list: A list of onboarding workflow records (each a dict).
        """
        logger.info("Fetching onboarding workflows...")
        result = await self._get("onboarding/getonboardinglist")
        return result.get("onboarding", [])

    @tool
    async def list_offboarding_workflows(self):
        """
        Retrieves the list of offboarding workflows configured in Zoho People.

        Returns:
            list: A list of offboarding workflow records (each a dict).
        """
        logger.info("Fetching offboarding workflows...")
        result = await self._get("offboarding/getoffboardinglist")
        return result.get("offboarding", [])

    @tool
    async def list_role_change_workflows(self):
        """
        Retrieves the list of role change (or transfer) workflows configured in Zoho People.

        Returns:
            list: A list of transfer workflow records (each a dict).
        """
        logger.info("Fetching role change workflows...")
        result = await self._get("transfer/gettransferlist")
        return result.get("transfer", [])
