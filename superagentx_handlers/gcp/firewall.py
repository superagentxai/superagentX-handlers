import logging
import os

from google.cloud import compute_v1
from google.oauth2 import service_account
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

logger = logging.getLogger(__name__)


class GCPFirewallHandler(BaseHandler):
    def __init__(
            self,
            creds: str | dict | None = None
    ):
        super().__init__()


        # Load credentials from path or dict
        creds = creds or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if isinstance(creds, str):
            credentials: service_account.Credentials = service_account.Credentials.from_service_account_file(
                creds
            )
        elif isinstance(creds, dict):
            credentials: service_account.Credentials = service_account.Credentials.from_service_account_info(
                creds
            )
        else:
            raise ValueError("Invalid credentials: must be a file path or a dictionary.")

        self.credentials = credentials
        self.project_id = credentials.project_id

        self.client = compute_v1.FirewallsClient(credentials=credentials)

    @tool
    async def get_firewall_details(self) -> list:
        """
        Lists all GCP firewall rules and returns a list with all possible values.
        """
        firewalls = []
        try:
            # List all firewall rules
            request = await sync_to_async(compute_v1.ListFirewallsRequest, project=self.project_id)
            firewall_list = self.client.list(request=request)
            async for firewall in iter_to_aiter(firewall_list):
                firewalls.append(firewall)
        except Exception as ex:
            logger.error(f"Error in retrieving firewall details {ex}")

        return firewalls
