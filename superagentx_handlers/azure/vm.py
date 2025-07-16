import logging
import os

from azure.identity.aio import ClientSecretCredential
from azure.mgmt.compute.aio import ComputeManagementClient
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class AzureVMClientInitFailed(Exception):
    pass


logger = logging.getLogger(__name__)


class AzureVMHandler(BaseHandler):
    """
    A handler class for managing interactions with Azure Virtual Machines (VMs).
    This class provides a method for retrieving a list of all VM instances within the
    configured Azure subscription, facilitating server asset detail collection.
    """

    def __init__(
            self,
            *,
            subscription_id: str | None = None,
            tenant_id: str | None = None,
            client_id: str | None = None,
            client_secret: str | None = None
    ):
        super().__init__()
        self.subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        self.tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
        self.client_id = client_id or os.getenv("AZURE_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET")

        try:
            self.credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            self.compute_client = ComputeManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        except Exception as e:
            logger.error(f"Error initializing Azure VM client: {e}", exc_info=True)
            raise AzureVMClientInitFailed(f"Failed to initialize Azure VM Handler: {e}")

    @tool
    async def get_vms(self) -> list[dict]:
        """
        Asynchronously retrieves a list of all accessible Azure Virtual Machine (VM) instances
        within the configured subscription. This method collects essential server asset details.
        Requires 'Microsoft.Compute/virtualMachines/read' (e.g., 'Reader' role) Azure RBAC permission
        for the subscription.
        """
        vms = []
        try:
            vm_data = self.compute_client.virtual_machines.list_all()
            async for vm in vm_data:
                vms.append(vm.as_dict())
            logger.info(vms)
            return vms
        except Exception as e:
            logger.error(f"Error getting Virtual Machines: {e}", exc_info=e)
            return []
