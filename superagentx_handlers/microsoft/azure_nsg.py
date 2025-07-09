# azure_nsg.py
import os
import logging
from typing import Any

from superagentx.handler.decorators import tool
from superagentx.handler.base import BaseHandler
from azure.identity.aio import ClientSecretCredential
from azure.mgmt.network.aio import NetworkManagementClient

# Custom exceptions
class AzureNSGListFailed(Exception): pass
class AzureNSGClientInitFailed(Exception): pass


logger = logging.getLogger(__name__)


class AzureNSGHandler(BaseHandler):
    """
    A handler class for managing interactions with Azure Network Security Groups (NSGs).
    This class provides a method for retrieving a list of all NSGs within the configured
    Azure subscription, facilitating network security auditing.
    """

    def __init__(
        self,
        *,
        subscription_id: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        **kwargs: Any
    ):
        super().__init__()
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

        try:
            self.credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            self.network_client = NetworkManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        except Exception as e:
            logger.error(f"Error initializing Azure NSG client: {e}", exc_info=True)
            raise AzureNSGClientInitFailed(f"Failed to initialize Azure NSG Handler: {e}")

    @tool
    async def get_network_security_groups(self) -> list[dict]:
        """
        Asynchronously gets or retrieves a list of all accessible Azure Network Security Groups (NSGs)
        within the configured subscription. This method provides an overview of network
        firewall configurations.
        Requires 'Microsoft.Network/networkSecurityGroups/read' (e.g., 'Reader' role)
        Azure RBAC permission for the subscription.
        """
        nsgs = []
        try:
            async for nsg in self.network_client.network_security_groups.list_all():
                # Extract only essential details for brevity, similar to S3 list_bucket
                nsgs.append({
                    "id": nsg.id,
                    "name": nsg.name,
                    "location": nsg.location,
                    "resourceGroup": nsg.id.split('/')[4],
                })
            logger.debug(f"Got {len(nsgs)} Network Security Group records.")
            return nsgs
        except Exception as e:
            logger.error(f"Error getting Network Security Groups: {e}", exc_info=e)
            raise AzureNSGListFailed(f"Failed to list NSGs: {e}")

