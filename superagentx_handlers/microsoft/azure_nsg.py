# azure_nsg.py
import os
import logging
from typing import Any

from azure.identity.aio import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.network.aio import NetworkManagementClient
from azure.mgmt.resource.resources.aio import ResourceManagementClient

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import iter_to_aiter # Assuming this utility exists

logger = logging.getLogger(__name__)


class AzureNSGHandler(BaseHandler):
    """
    A handler class for interaction with Azure Network Security Groups (NSGs).
    This class extends BaseHandler and provides methods for retrieving
    NSG-related information for Governance, Risk, and Compliance (GRC) purposes.
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
        Initializes the Azure NSG Handler with authenticated Azure management clients.

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
                logger.debug("Azure NSG Handler: Authenticating with Client Secret Credential.")
            else:
                self.credential = DefaultAzureCredential()
                logger.debug("Azure NSG Handler: Authenticating with DefaultAzureCredential.")

            self.network_client = NetworkManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            self.resource_client = ResourceManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            logger.debug("Azure NetworkManagementClient initialized.")

        except Exception as e:
            logger.error(
                f"Error initializing Azure NSG clients: {e}", exc_info=True)
            raise ValueError(
                f"Failed to initialize Azure NSG Handler. Please ensure "
                f"Azure credentials (subscription_id, tenant_id, client_id, client_secret "
                f"or appropriate environment variables) are valid and that the "
                f"application has necessary RBAC permissions (e.g., 'Reader' on the subscription)."
            )

    @tool
    async def get_resource_groups(self) -> list[dict]:
        """
        Gets for all accessible Azure Resource Groups within the subscription.
        Requires 'Microsoft.Resources/subscriptions/resourcegroups/read' (e.g., 'Reader' role) Azure RBAC permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains Resource Group details.
        """
        logger.debug("Getting for Azure Resource Groups...")
        resource_groups = []
        try:
            resource_groups = self.resource_client.resource_groups.list()
            # async for rg in self.resource_client.resource_groups.list():
            #     resource_groups.append({
            #         "id": rg.id,
            #         "name": rg.name,
            #         "location": rg.location,
            #         "properties": {
            #             "provisioningState": rg.properties.provisioning_state if rg.properties else None
            #         },
            #         "tags": rg.tags
            #     })
            logger.debug(f"Got {len(resource_groups)} Resource Group records.")
        except Exception as e:
            logger.error(
                f"An error occurred while getting Resource Group: {e}", exc_info=True)
        return resource_groups

    @tool
    async def get_nics(self) -> list[dict]:
        """
        Gets for all accessible Azure Network Interfaces (NICs) within the subscription.
        Requires 'Microsoft.Network/networkInterfaces/read' (e.g., 'Reader' role) Azure RBAC permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains NIC details.
        """
        logger.debug("Getting for Azure Network Interfaces...")
        nics = []
        try:
            async for nic in self.network_client.network_interfaces.list_all():
                # Extract relevant details
                ip_configurations = []
                if nic.ip_configurations:
                    for ip_config in nic.ip_configurations:
                        ip_configurations.append({
                            "name": ip_config.name,
                            "privateIpAddress": ip_config.private_ip_address,
                            "privateIpAllocationMethod": str(ip_config.private_ip_allocation_method),
                            "publicIpAddressId": ip_config.public_ip_address.id if ip_config.public_ip_address else None,
                            "primary": ip_config.primary
                        })

                nsg_id = nic.network_security_group.id if nic.network_security_group else None
                # Get the NSG name from the ID if available
                nsg_name = nsg_id.split('/')[-1] if nsg_id else None

                resource_group_name = nic.id.split('/')[4] # Extract RG from NIC ID

                nics.append({
                    "id": nic.id,
                    "name": nic.name,
                    "location": nic.location,
                    "resourceGroup": resource_group_name,
                    "primary": nic.primary,
                    "enableIpForwarding": nic.enable_ip_forwarding,
                    "enableAcceleratedNetworking": nic.enable_accelerated_networking,
                    "dnsSettings": {
                        "dnsServers": nic.dns_settings.dns_servers,
                        "internalDomainNameSuffix": nic.dns_settings.internal_domain_name_suffix
                    } if nic.dns_settings else None,
                    "ipConfigurations": ip_configurations,
                    "networkSecurityGroupId": nsg_id,
                    "networkSecurityGroupName": nsg_name,
                    "tags": nic.tags
                })
            logger.debug(f"Got {len(nics)} Network Interface records.")
        except Exception as e:
            logger.error(
                f"An error occurred while getting NIC: {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Network/networkInterfaces/read' RBAC permission for the subscription."
            )
        return nics

    @tool
    async def get_network_security_groups(self) -> list[dict]:
        """
        Gets for all accessible Azure Network Security Groups (NSGs) within the subscription.
        Includes details like location, security rules, and applied network interfaces/subnets.
        Requires 'Microsoft.Network/networkSecurityGroups/read' (e.g., 'Reader' role) Azure RBAC permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains NSG details.
        """
        logger.debug("Getting for Azure Network Security Groups...")
        nsgs = []
        try:
            async for nsg in self.network_client.network_security_groups.list_all():
                security_rules = []
                if nsg.security_rules:
                    for rule in nsg.security_rules:
                        security_rules.append({
                            "name": rule.name,
                            "description": rule.description,
                            "protocol": str(rule.protocol) if hasattr(rule, 'protocol') else None,
                            "direction": str(rule.direction) if hasattr(rule, 'direction') else None,
                            "sourceAddressPrefix": rule.source_address_prefix,
                            "destinationAddressPrefix": rule.destination_address_prefix,
                            "sourcePortRange": rule.source_port_range,
                            "destinationPortRange": rule.destination_port_range,
                            "access": str(rule.access) if hasattr(rule, 'access') else None,
                            "priority": rule.priority,
                            "ruleType": str(rule.rule_type) if hasattr(rule, 'rule_type') else None,
                        })

                default_security_rules = []
                if nsg.default_security_rules:
                    for rule in nsg.default_security_rules:
                        default_security_rules.append({
                            "name": rule.name,
                            "protocol": str(rule.protocol) if hasattr(rule, 'protocol') else None,
                            "direction": str(rule.direction) if hasattr(rule, 'direction') else None,
                            "sourceAddressPrefix": rule.source_address_prefix,
                            "destinationAddressPrefix": rule.destination_address_prefix,
                            "sourcePortRange": rule.source_port_range,
                            "destinationPortRange": rule.destination_port_range,
                            "access": str(rule.access) if hasattr(rule, 'access') else None,
                            "priority": rule.priority,
                            "ruleType": str(rule.rule_type) if hasattr(rule, 'rule_type') else None,
                        })

                # Extract associated network interfaces and subnets
                network_interfaces = []
                if nsg.network_interfaces:
                    network_interfaces = [{"id": nic.id, "name": nic.name} for nic in nsg.network_interfaces]

                subnets = []
                if nsg.subnets:
                    subnets = [{"id": subnet.id, "name": subnet.name} for subnet in nsg.subnets]

                nsgs.append({
                    "id": nsg.id,
                    "name": nsg.name,
                    "location": nsg.location,
                    "resourceGroup": nsg.id.split('/')[4],
                    "securityRules": security_rules,
                    "defaultSecurityRules": default_security_rules,
                    "networkInterfaces": network_interfaces,
                    "subnets": subnets,
                    "tags": nsg.tags
                })
            logger.debug(f"Got {len(nsgs)} Network Security Group records.")
        except Exception as e:
            logger.error(
                f"An error occurred while getting NSG: {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Network/networkSecurityGroups/read' RBAC permission for the subscription."
            )
        return nsgs

    @tool
    async def get_network_security_group_rules(self, nsg_name: str, resource_group_name: str) -> list[dict] | None:
        """
        Gets for Network Security Group rules for a specific NSG.
        Requires 'Microsoft.Network/networkSecurityGroups/read' (e.g., 'Reader' role) Azure RBAC permission.

        Args:
            nsg_name (str): The name of the Network Security Group.
            resource_group_name (str): The resource group name of the NSG.

        Returns:
            list: A list of dictionaries, where each dictionary contains NSG rule details.
        """
        logger.debug(f"Getting for Network Security Group rules for NSG '{nsg_name}'...")
        nsg_rules = []
        try:
            nsg = await self.network_client.network_security_groups.get(
                resource_group_name=resource_group_name,
                network_security_group_name=nsg_name
            )
            if nsg and nsg.security_rules:
                for rule in nsg.security_rules:
                    nsg_rules.append({
                        "name": rule.name,
                        "description": rule.description,
                        "protocol": str(rule.protocol) if hasattr(rule, 'protocol') else None,
                        "direction": str(rule.direction) if hasattr(rule, 'direction') else None,
                        "sourceAddressPrefix": rule.source_address_prefix,
                        "destinationAddressPrefix": rule.destination_address_prefix,
                        "sourcePortRange": rule.source_port_range,
                        "destinationPortRange": rule.destination_port_range,
                        "access": str(rule.access) if hasattr(rule, 'access') else None,
                        "priority": rule.priority,
                        "ruleType": str(rule.rule_type) if hasattr(rule, 'rule_type') else None,
                    })
            logger.debug(f"Got {len(nsg_rules)} Network Security Group rule records for NSG '{nsg_name}'.")
            return nsg_rules
        except Exception as e:
            logger.error(
                f"An error occurred while getting NSG rules for NSG '{nsg_name}' (RG: '{resource_group_name}'): {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Network/networkSecurityGroups/read' RBAC permission for the NSG."
            )
            return None

    @tool
    async def get_effective_network_security_rules(self, network_interface_name: str, resource_group_name: str) -> list[dict] | None:
        """
        Gets effective network security rules for a specific network interface.
        These are the actual rules applied, considering all associated NSGs and default rules.
        Requires 'Microsoft.Network/networkInterfaces/read' and 'Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action' RBAC permissions.

        Args:
            network_interface_name (str): The name of the network interface.
            resource_group_name (str): The resource group name of the network interface.

        Returns:
            list: A list of dictionaries, where each dictionary contains effective security rules for the NIC.
        """
        logger.debug(f"Getting effective security rules for NIC '{network_interface_name}'...")
        effective_security_rules = []
        try:
            nic_effective_nsg = await self.network_client.network_interfaces.begin_list_effective_network_security_groups(
                resource_group_name=resource_group_name,
                network_interface_name=network_interface_name
            ).result()

            if nic_effective_nsg and nic_effective_nsg.effective_security_groups:
                for group in nic_effective_nsg.effective_security_groups:
                    if group.effective_security_rules:
                        for rule in group.effective_security_rules:
                            effective_security_rules.append({
                                "name": rule.name,
                                "protocol": str(rule.protocol) if hasattr(rule, 'protocol') else None,
                                "sourceAddressPrefix": rule.source_address_prefix,
                                "destinationAddressPrefix": rule.destination_address_prefix,
                                "expandedSourceAddressPrefix": rule.expanded_source_address_prefix, # List of IPs if prefix is service tag
                                "expandedDestinationAddressPrefix": rule.expanded_destination_address_prefix,
                                "priority": rule.priority,
                                "sourcePortRanges": rule.source_port_ranges,
                                "destinationPortRanges": rule.destination_port_ranges,
                                "accessType": str(rule.access) if hasattr(rule, 'access') else None, # Access can be Allow/Deny
                                "ruleType": str(rule.direction) if hasattr(rule, 'direction') else None, # Direction can be Inbound/Outbound
                            })

            logger.debug(f"Got effective security rules for NIC '{network_interface_name}'.")
            return effective_security_rules
        except Exception as e:
            logger.error(
                f"An error occurred while getting effective network security rules for NIC '{network_interface_name}' (RG: '{resource_group_name}'): {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Network/networkInterfaces/read' and "
                "'Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action' RBAC permissions for the NIC.")
            return None