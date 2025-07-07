# azure_vm.py
import os
import logging
from typing import Any, AsyncIterator

from azure.identity.aio import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.compute.aio import ComputeManagementClient
from azure.mgmt.monitor.aio import MonitorManagementClient # For diagnostics settings

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import iter_to_aiter # Assuming this utility exists

logger = logging.getLogger(__name__)


class AzureVMHandler(BaseHandler):
    """
    A handler class for interaction with Azure Virtual Machines and their related resources.
    This class extends BaseHandler and provides methods for retrieving
    VM-related information for Governance, Risk, and Compliance (GRC) purposes.
    This class only implements 'get' operations and does not support create, update, or delete operations.
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
        """
        Initializes the Azure VM Handler with authenticated Azure management clients.

        Args:
            subscription_id (str, optional): Your Azure Subscription ID. Defaults to AZURE_SUBSCRIPTION_ID environment variable.
            tenant_id (str, optional): Your Azure Tenant ID. Defaults to AZURE_TENANT_ID environment variable.
            client_id (str, optional): The Application (client) ID of your registered Azure AD application. Defaults to AZURE_CLIENT_ID environment variable.
            client_secret (str, optional): The client secret of your registered Azure AD application. Defaults to AZURE_CLIENT_SECRET environment variable.
        """
        self.subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
        client_id = client_id or os.getenv("AZURE_CLIENT_ID")
        client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET")

        if not self.subscription_id:
            raise ValueError(
                "Azure Subscription ID must be provided either directly or via AZURE_SUBSCRIPTION_ID environment variable."
            )

        try:
            if all([tenant_id, client_id, client_secret]):
                self.credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
                logger.debug("Azure VM Handler: Authenticating with Client Secret Credential.")
            else:
                self.credential = DefaultAzureCredential()
                logger.debug("Azure VM Handler: Authenticating with DefaultAzureCredential.")

            self.compute_client = ComputeManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            logger.debug("Azure ComputeManagementClient initialized.")

            # MonitorManagementClient is needed for diagnostic settings
            self.monitor_client = MonitorManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            logger.debug("Azure MonitorManagementClient initialized.")

        except Exception as e:
            logger.error(
                f"Error initializing Azure VM clients: {e}", exc_info=True)
            raise ValueError(
                f"Failed to initialize Azure VM Handler. Please ensure "
                f"Azure credentials (subscription_id, tenant_id, client_id, client_secret "
                f"or appropriate environment variables) are valid and that the "
                f"application has necessary RBAC permissions (e.g., 'Reader' on the subscription)."
            )

    @tool
    async def get_vms(self) -> list[dict]:
        """
        Gets for all accessible Azure Virtual Machines within the subscription.
        Includes details like SKU, OS type, size, location, status, and provisioning state.
        Requires 'Microsoft.Compute/virtualMachines/read' (e.g., 'Reader' role) Azure RBAC permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains VM details.
        """
        logger.debug("Getting for Azure Virtual Machines...")
        vms = []
        try:
            async for vm in self.compute_client.virtual_machines.list_all():
                # Get the instance view for detailed status information
                vm_instance_view = await self.compute_client.virtual_machines.instance_view(
                    resource_group_name=vm.id.split('/')[4],
                    vm_name=vm.name
                )

                power_state = next((s.display_status for s in vm_instance_view.statuses if 'PowerState' in s.code), None)
                provisioning_state = next((s.display_status for s in vm_instance_view.statuses if 'ProvisioningState' in s.code), None)

                vms.append({
                    "id": vm.id,
                    "name": vm.name,
                    "location": vm.location,
                    "resourceGroup": vm.id.split('/')[4],
                    "vmId": vm.vm_id,
                    "hardwareProfile": {
                        "vmSize": vm.hardware_profile.vm_size if vm.hardware_profile else None
                    },
                    "osProfile": {
                        "computerName": vm.os_profile.computer_name if vm.os_profile else None,
                        "adminUsername": vm.os_profile.admin_username if vm.os_profile else None,
                        "windowsConfiguration": {
                            "enableAutomaticUpdates": vm.os_profile.windows_configuration.enable_automatic_updates
                        } if vm.os_profile and vm.os_profile.windows_configuration else None,
                        "linuxConfiguration": {
                            "disablePasswordAuthentication": vm.os_profile.linux_configuration.disable_password_authentication
                        } if vm.os_profile and vm.os_profile.linux_configuration else None,
                    },
                    "storageProfile": {
                        "osDisk": {
                            "name": vm.storage_profile.os_disk.name if vm.storage_profile and vm.storage_profile.os_disk else None,
                            "osType": str(vm.storage_profile.os_disk.os_type) if vm.storage_profile and vm.storage_profile.os_disk and vm.storage_profile.os_disk.os_type else None,
                            "diskSizeGb": vm.storage_profile.os_disk.disk_size_gb if vm.storage_profile and vm.storage_profile.os_disk else None,
                            "managedDisk": {
                                "id": vm.storage_profile.os_disk.managed_disk.id
                            } if vm.storage_profile and vm.storage_profile.os_disk and vm.storage_profile.os_disk.managed_disk else None,
                        },
                        "dataDisks": [
                            {
                                "name": disk.name,
                                "diskSizeGb": disk.disk_size_gb,
                                "managedDisk": {"id": disk.managed_disk.id} if disk.managed_disk else None
                            } for disk in vm.storage_profile.data_disks
                        ] if vm.storage_profile and vm.storage_profile.data_disks else [],
                    },
                    "networkProfile": {
                        "networkInterfaces": [
                            {"id": nic_ref.id} for nic_ref in vm.network_profile.network_interfaces
                        ] if vm.network_profile and vm.network_profile.network_interfaces else []
                    },
                    "status": power_state,
                    "provisioningState": provisioning_state,
                    "tags": vm.tags
                })
            logger.debug(f"Got {len(vms)} virtual machine records.")
        except Exception as e:
            logger.error(
                f"An error occurred while getting VM: {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Compute/virtualMachines/read' (e.g., 'Reader' role) RBAC permission for the subscription.")
        return vms

    @tool
    async def get_vm_details(self, vm_name: str, resource_group_name: str) -> dict | None:
        """
        Get comprehensive details for a specific virtual machine.
        Requires 'Microsoft.Compute/virtualMachines/read' (e.g., 'Reader' role) Azure RBAC permission.

        Args:
            vm_name (str): The name of the virtual machine.
            resource_group_name (str): The resource group of the virtual machine.

        Returns:
            dict | None: A dictionary containing comprehensive VM details, or None if not found or an error occurs.
        """
        logger.debug(f"Getting details for VM '{vm_name}' in resource group '{resource_group_name}'...")
        try:
            vm = await self.compute_client.virtual_machines.get(
                resource_group_name=resource_group_name,
                vm_name=vm_name,
                expand='instanceView' # To get detailed status like power state
            )

            power_state = next((s.display_status for s in vm.instance_view.statuses if 'PowerState' in s.code), None)
            provisioning_state = next((s.display_status for s in vm.instance_view.statuses if 'ProvisioningState' in s.code), None)

            return {
                "id": vm.id,
                "name": vm.name,
                "location": vm.location,
                "resourceGroup": resource_group_name,
                "vmId": vm.vm_id,
                "hardwareProfile": {
                    "vmSize": vm.hardware_profile.vm_size
                },
                "osProfile": {
                    "computerName": vm.os_profile.computer_name,
                    "adminUsername": vm.os_profile.admin_username,
                    "windowsConfiguration": {
                        "enableAutomaticUpdates": vm.os_profile.windows_configuration.enable_automatic_updates
                    } if vm.os_profile and vm.os_profile.windows_configuration else None,
                    "linuxConfiguration": {
                        "disablePasswordAuthentication": vm.os_profile.linux_configuration.disable_password_authentication
                    } if vm.os_profile and vm.os_profile.linux_configuration else None,
                },
                "storageProfile": {
                    "osDisk": {
                        "name": vm.storage_profile.os_disk.name,
                        "osType": str(vm.storage_profile.os_disk.os_type),
                        "diskSizeGb": vm.storage_profile.os_disk.disk_size_gb,
                        "managedDisk": {
                            "id": vm.storage_profile.os_disk.managed_disk.id
                        } if vm.storage_profile.os_disk.managed_disk else None,
                    },
                    "dataDisks": [
                        {
                            "name": disk.name,
                            "diskSizeGb": disk.disk_size_gb,
                            "managedDisk": {"id": disk.managed_disk.id} if disk.managed_disk else None
                        } for disk in vm.storage_profile.data_disks
                    ],
                },
                "networkProfile": {
                    "networkInterfaces": [
                        {"id": nic_ref.id} for nic_ref in vm.network_profile.network_interfaces
                    ]
                },
                "diagnosticsProfile": {
                    "bootDiagnostics": {
                        "enabled": vm.diagnostics_profile.boot_diagnostics.enabled,
                        "storageUri": vm.diagnostics_profile.boot_diagnostics.storage_uri
                    }
                } if vm.diagnostics_profile and vm.diagnostics_profile.boot_diagnostics else None,
                "licenseType": vm.license_type,
                "vmAgent": {
                    "vmAgentVersion": vm.instance_view.vm_agent.vm_agent_version,
                    "statuses": [{
                        "code": s.code,
                        "displayStatus": s.display_status,
                        "level": str(s.level)
                    } for s in vm.instance_view.vm_agent.statuses]
                } if vm.instance_view and vm.instance_view.vm_agent else None,
                "disks": [
                    {
                        "name": disk.name,
                        "statuses": [{
                            "code": s.code,
                            "displayStatus": s.display_status,
                            "level": str(s.level)
                        } for s in disk.statuses]
                    } for disk in vm.instance_view.disks
                ] if vm.instance_view and vm.instance_view.disks else None,
                "extensions": [
                    {
                        "name": ext.name,
                        "publisher": ext.publisher,
                        "type": ext.type,
                        "typeHandlerVersion": ext.type_handler_version,
                        "provisioningState": ext.provisioning_state,
                        "statuses": [{
                            "code": s.code,
                            "displayStatus": s.display_status,
                            "level": str(s.level)
                        } for s in ext.instance_view.statuses] if ext.instance_view else None
                    } for ext in vm.instance_view.extensions
                ] if vm.instance_view and vm.instance_view.extensions else None,
                "statuses": [{
                    "code": s.code,
                    "displayStatus": s.display_status,
                    "level": str(s.level)
                } for s in vm.instance_view.statuses] if vm.instance_view else None,
                "powerState": power_state,
                "provisioningState": provisioning_state,
                "tags": vm.tags
            }
        except Exception as e:
            logger.error(
                f"An error occurred while getting details for VM '{vm_name}' (RG: '{resource_group_name}'): {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Compute/virtualMachines/read' RBAC permission for the VM.")
            return None

    @tool
    async def get_vm_tags(self, vm_name: str, resource_group_name: str) -> dict | None:
        """
        Get the tags assigned to a specific VM.
        Requires 'Microsoft.Compute/virtualMachines/read' (e.g., 'Reader' role) Azure RBAC permission.

        Args:
            vm_name (str): The name of the virtual machine.
            resource_group_name (str): The resource group of the virtual machine.

        Returns:
            dict | None: A dictionary of tags, or None if the VM is not found or an error occurs.
        """
        logger.debug(f"Getting tags for VM '{vm_name}' in resource group '{resource_group_name}'...")
        try:
            vm = await self.compute_client.virtual_machines.get(
                resource_group_name=resource_group_name,
                vm_name=vm_name
            )
            return vm.tags
        except Exception as e:
            logger.error(
                f"An error occurred while getting tags for VM '{vm_name}' (RG: '{resource_group_name}'): {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Compute/virtualMachines/read' RBAC permission for the VM.")
            return None

    @tool
    async def get_vm_boot_diagnostics_settings(self, vm_name: str, resource_group_name: str) -> dict | None:
        """
        Gets boot diagnostics settings for a specific VM.
        Requires 'Microsoft.Compute/virtualMachines/read' (e.g., 'Reader' role) Azure RBAC permission.

        Args:
            vm_name (str): The name of the virtual machine.
            resource_group_name (str): The resource group of the virtual machine.

        Returns:
            dict: A dictionary containing boot diagnostics settings, or None if not found or an error occurs.
        """
        logger.debug(f"Getting boot diagnostics settings for VM '{vm_name}' in resource group '{resource_group_name}'...")
        try:
            vm = await self.compute_client.virtual_machines.get(
                resource_group_name=resource_group_name,
                vm_name=vm_name,
                expand='instanceView' # To ensure diagnostics profile is populated
            )
            if vm and vm.diagnostics_profile and vm.diagnostics_profile.boot_diagnostics:
                return {
                    "enabled": vm.diagnostics_profile.boot_diagnostics.enabled,
                    "storageUri": vm.diagnostics_profile.boot_diagnostics.storage_uri
                }
            return None
        except Exception as e:
            logger.error(
                f"An error occurred while getting boot diagnostics settings for VM '{vm_name}' (RG: '{resource_group_name}'): {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Compute/virtualMachines/read' RBAC permission for the VM.")
            return None

    @tool
    async def get_vm_patch_status(self, vm_name: str, resource_group_name: str) -> dict | None:
        """
        Gets patch status for a specific VM.
        This provides a high-level overview of automatic OS updates for Windows VMs
        and password authentication for Linux VMs. More detailed patch status might
        require integration with Azure Update Management.
        Requires 'Microsoft.Compute/virtualMachines/read' (e.g., 'Reader' role) Azure RBAC permission.

        Args:
            vm_name (str): The name of the virtual machine.
            resource_group_name (str): The resource group of the virtual machine.

        Returns:
            dict | None: A dictionary containing patch status details, or None if not available or an error occurs.
        """
        logger.debug(f"Getting patch status for VM '{vm_name}' in resource group '{resource_group_name}'...")
        try:
            vm = await self.compute_client.virtual_machines.get(
                resource_group_name=resource_group_name,
                vm_name=vm_name
            )
            os_profile = vm.os_profile

            patch_status = {}
            if os_profile:
                if os_profile.windows_configuration:
                    patch_status["osType"] = "Windows"
                    patch_status["automaticUpdatesEnabled"] = os_profile.windows_configuration.enable_automatic_updates
                elif os_profile.linux_configuration:
                    patch_status["osType"] = "Linux"
                    patch_status["passwordAuthenticationDisabled"] = os_profile.linux_configuration.disable_password_authentication

            return patch_status if patch_status else None
        except Exception as e:
            logger.error(
                f"An error occurred while getting patch status for VM '{vm_name}' (RG: '{resource_group_name}'): {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Compute/virtualMachines/read' RBAC permission for the VM. "
                "More detailed patch status might require integration with Azure Update Management.")
            return None