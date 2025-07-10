import os
import logging
from typing import Any

from superagentx.handler.decorators import tool
from superagentx.handler.base import BaseHandler
from azure.identity.aio import ClientSecretCredential
from azure.mgmt.compute.aio import ComputeManagementClient


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
            client_secret: str | None = None,
            **kwargs: Any
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
            # async for vm in self.compute_client.virtual_machines.list_all():
            #     # Extract only essential details for brevity and server asset overview
            #     resource_group_name = vm.id.split('/')[4]  # Extract RG from VM ID
            #
            #     # Attempt to get power state from instance view if available, without expanding explicitly
            #     # This is a common pattern for list_all where full instanceView is not always returned by default.
            #     # For a truly minimal response, we might omit this and rely only on top-level properties.
            #     # However, power state is a critical asset detail, so we include a basic attempt.
            #     power_state = None
            #     if hasattr(vm, 'instance_view') and vm.instance_view and vm.instance_view.statuses:
            #         power_state = next((s.display_status for s in vm.instance_view.statuses if 'PowerState' in s.code),
            #                            None)
            #
            #     vms.append({
            #         "id": vm.id,
            #         "name": vm.name,
            #         "location": vm.location,
            #         "resourceGroup": resource_group_name,
            #         "vmSize": vm.hardware_profile.vm_size if vm.hardware_profile else None,
            #         "osType": str(
            #             vm.storage_profile.os_disk.os_type) if vm.storage_profile and vm.storage_profile.os_disk else None,
            #         "powerState": power_state,
            #         "tags": vm.tags if vm.tags else {}
            #     })
            # logger.debug(f"Got {len(vms)} virtual machine records.")
            vm_data = self.compute_client.virtual_machines.list_all()
            async for vm in vm_data:
                vms.append(vm.as_dict())
            logger.info(vms)
            return vms
        except Exception as e:
            logger.error(f"Error getting Virtual Machines: {e}", exc_info=e)
            return []
