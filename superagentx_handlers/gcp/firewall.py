import base64
import json
import logging
import os
from typing import Any, Optional, List, Dict

from superagentx.utils.helper import sync_to_async, iter_to_aiter
from google.cloud import compute_v1
from google.oauth2 import service_account
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class GCPFirewallHandler(BaseHandler):
    def __init__(
            self,
            scope: List[str] | None = None,
            creds: str | dict | None = None
    ):
        super().__init__()
        self.scope = scope or ["https://www.googleapis.com/auth/cloud-platform"]

        creds = creds or os.getenv("GCP_AGENT_CREDENTIALS")
        if isinstance(creds, str):
            credentials = service_account.Credentials.from_service_account_file(
                creds, scopes=self.scope)
        elif isinstance(creds, dict):
            credentials = service_account.Credentials.from_service_account_info(
                creds, scopes=self.scope)
        else:
            raise ValueError("Invalid credentials")

        self.project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
        if not self.project_id:
            credentials_path = os.getenv('GCP_AGENT_CREDENTIALS')
            if credentials_path:
                with open(credentials_path, 'r') as f:
                    creds_info = json.load(f)
                    self.project_id = creds_info.get('project_id')
        if not self.project_id:
            raise ValueError("Project ID not found. Set GOOGLE_CLOUD_PROJECT or provide project_id in service account.")

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
