import asyncio
import logging
import os
from datetime import datetime
from typing import Optional

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.apimanagement.aio import ApiManagementClient
from azure.mgmt.authorization.aio import AuthorizationManagementClient
from azure.mgmt.network.aio import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

logger = logging.getLogger(__name__)


class AzureApplicationGatewayHandler(BaseHandler):
    """
    Azure Application Gateway handler for managing application gateways, listeners, rules, and backend pools.
    """

    def __init__(
            self,
            subscription_id: str | None = None,
            client_id: str | None = None,
            client_secret: str | None = None,
            tenant_id: str | None = None,
            credential: DefaultAzureCredential | None = None
    ):
        super().__init__()
        self.subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        self.tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
        self.client_id = client_id or os.getenv("AZURE_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET")

        # Initialize credential
        if credential:
            self.credential = credential
        elif client_id and client_secret and tenant_id:
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            # Use environment variables or managed identity
            self.credential = DefaultAzureCredential()

        # Initialize clients
        self.network_client = NetworkManagementClient(
            credential=self.credential,  # noqa
            subscription_id=self.subscription_id
        )

        self.resource_client = ResourceManagementClient(
            credential=self.credential,  # noqa
            subscription_id=self.subscription_id
        )

        self.apim_client = ApiManagementClient(
            self.credential,
            self.subscription_id
        )
        self.rbac_client = AuthorizationManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

    @tool
    async def get_resource_groups(self) -> list[dict]:
        """
        Retrieve all resource groups in the subscription.

        Returns:
            list[dict]: List of resource group details
        """
        logger.info("Fetching Azure resource groups...")
        resource_groups_data = []
        try:
            resource_groups = await sync_to_async(self.resource_client.resource_groups.list)
            async for rg in iter_to_aiter(resource_groups):
                rg_info = {
                    'name': rg.name,
                    'location': rg.location,
                    'id': rg.id,
                    'type': rg.type,
                    'tags': rg.tags or {},
                    'properties': {
                        'provisioning_state': rg.properties.provisioning_state if rg.properties else None
                    }
                }
                resource_groups_data.append(rg_info)
            logger.info(f"Retrieved {len(resource_groups_data)} resource groups")
        except AzureError as e:
            logger.error(f"Error fetching resource groups: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching resource groups: {e}")
        return resource_groups_data

    @tool
    async def get_application_gateways(self, resource_group_name: Optional[str] = None) -> list[dict]:
        """
        Retrieve all application gateways in the subscription or specific resource group.

        Args:
            resource_group_name (str, optional): Optional resource group name to filter results

        Returns:
            list[dict]: List of application gateway details
        """
        logger.info(f"Fetching application gateways for resource group: {resource_group_name or 'all'}")
        app_gateways_data = []
        try:
            if resource_group_name:
                app_gateways = self.network_client.application_gateways.list(
                    resource_group_name=resource_group_name
                )
            else:
                app_gateways = self.network_client.application_gateways.list_all()

            async for app_gateway in app_gateways:
                app_gateway_info = {
                    'name': app_gateway.name,
                    'id': app_gateway.id,
                    'location': app_gateway.location,
                    'type': app_gateway.type,
                    'resource_group': app_gateway.id.split('/')[4] if app_gateway.id else None,
                    'tags': app_gateway.tags or {},
                    'provisioning_state': app_gateway.provisioning_state,
                    'operational_state': app_gateway.operational_state,
                    'tier': app_gateway.sku.tier if app_gateway.sku else None,
                    'capacity': app_gateway.sku.capacity if app_gateway.sku else None,
                    'enable_http2': app_gateway.enable_http2,
                    'enable_fips': app_gateway.enable_fips,
                    'zones': app_gateway.zones or [],
                    'frontend_ip_configurations': [
                        {
                            'name': config.name,
                            'private_ip_address': config.private_ip_address,
                            'private_ip_allocation_method': config.private_ip_allocation_method,
                            'subnet_id': config.subnet.id if config.subnet else None,
                            'public_ip_address_id': config.public_ip_address.id if config.public_ip_address else None
                        } for config in (app_gateway.frontend_ip_configurations or [])
                    ],
                    'frontend_ports': [
                        {
                            'name': port.name,
                            'port': port.port
                        } for port in (app_gateway.frontend_ports or [])
                    ],
                    'backend_address_pools': [
                        {
                            'name': pool.name,
                            'backend_addresses': [
                                {
                                    'ip_address': addr.ip_address,
                                    'fqdn': addr.fqdn
                                } for addr in (pool.backend_addresses or [])
                            ]
                        } for pool in (app_gateway.backend_address_pools or [])
                    ],
                    'backend_http_settings_collection': [
                        {
                            'name': setting.name,
                            'port': setting.port,
                            'protocol': setting.protocol,
                            'cookie_based_affinity': setting.cookie_based_affinity,
                            'request_timeout': setting.request_timeout,
                            'connection_draining': {
                                'enabled': setting.connection_draining.enabled,
                                'drain_timeout_in_sec': setting.connection_draining.drain_timeout_in_sec
                            } if setting.connection_draining else None
                        } for setting in (app_gateway.backend_http_settings_collection or [])
                    ],
                    'http_listeners': [
                        {
                            'name': listener.name,
                            'frontend_ip_configuration_name': listener.frontend_ip_configuration.id.split('/')[
                                -1] if listener.frontend_ip_configuration else None,
                            'frontend_port_name': listener.frontend_port.id.split('/')[
                                -1] if listener.frontend_port else None,
                            'protocol': listener.protocol,
                            'host_name': listener.host_name,
                            'host_names': listener.host_names or [],
                            'ssl_certificate_name': listener.ssl_certificate.id.split('/')[
                                -1] if listener.ssl_certificate else None,
                            'require_server_name_indication': listener.require_server_name_indication
                        } for listener in (app_gateway.http_listeners or [])
                    ],
                    'request_routing_rules': [
                        {
                            'name': rule.name,
                            'rule_type': rule.rule_type,
                            'priority': rule.priority,
                            'http_listener_name': rule.http_listener.id.split('/')[-1] if rule.http_listener else None,
                            'backend_address_pool_name': rule.backend_address_pool.id.split('/')[
                                -1] if rule.backend_address_pool else None,
                            'backend_http_settings_name': rule.backend_http_settings.id.split('/')[
                                -1] if rule.backend_http_settings else None,
                            'url_path_map_name': rule.url_path_map.id.split('/')[-1] if rule.url_path_map else None,
                            'redirect_configuration_name': rule.redirect_configuration.id.split('/')[
                                -1] if rule.redirect_configuration else None
                        } for rule in (app_gateway.request_routing_rules or [])
                    ],
                    'url_path_maps': [
                        {
                            'name': url_map.name,
                            'default_backend_address_pool_name': url_map.default_backend_address_pool.id.split('/')[
                                -1] if url_map.default_backend_address_pool else None,
                            'default_backend_http_settings_name': url_map.default_backend_http_settings.id.split('/')[
                                -1] if url_map.default_backend_http_settings else None,
                            'path_rules': [
                                {
                                    'name': rule.name,
                                    'paths': rule.paths or [],
                                    'backend_address_pool_name': rule.backend_address_pool.id.split('/')[
                                        -1] if rule.backend_address_pool else None,
                                    'backend_http_settings_name': rule.backend_http_settings.id.split('/')[
                                        -1] if rule.backend_http_settings else None
                                } for rule in (url_map.path_rules or [])
                            ]
                        } for url_map in (app_gateway.url_path_maps or [])
                    ],
                    'ssl_certificates': [
                        {
                            'name': cert.name,
                            'key_vault_secret_id': cert.key_vault_secret_id
                        } for cert in (app_gateway.ssl_certificates or [])
                    ],
                    'probes': [
                        {
                            'name': probe.name,
                            'protocol': probe.protocol,
                            'host': probe.host,
                            'path': probe.path,
                            'interval': probe.interval,
                            'timeout': probe.timeout,
                            'unhealthy_threshold': probe.unhealthy_threshold,
                            'pick_host_name_from_backend_http_settings': probe.pick_host_name_from_backend_http_settings,
                            'match': {
                                'body': probe.match.body,
                                'status_codes': probe.match.status_codes
                            } if probe.match else None
                        } for probe in (app_gateway.probes or [])
                    ],
                    'waf_configuration': {
                        'enabled': app_gateway.web_application_firewall_configuration.enabled,
                        'firewall_mode': app_gateway.web_application_firewall_configuration.firewall_mode,
                        'rule_set_type': app_gateway.web_application_firewall_configuration.rule_set_type,
                        'rule_set_version': app_gateway.web_application_firewall_configuration.rule_set_version,
                        'request_body_check': app_gateway.web_application_firewall_configuration.request_body_check,
                        'max_request_body_size_in_kb': app_gateway.web_application_firewall_configuration.max_request_body_size_in_kb,
                        'file_upload_limit_in_mb': app_gateway.web_application_firewall_configuration.file_upload_limit_in_mb
                    } if app_gateway.web_application_firewall_configuration else None,
                    'firewall_policy_id': app_gateway.firewall_policy.id if app_gateway.firewall_policy else None,
                    'autoscale_configuration': {
                        'min_capacity': app_gateway.autoscale_configuration.min_capacity,
                        'max_capacity': app_gateway.autoscale_configuration.max_capacity
                    } if app_gateway.autoscale_configuration else None
                }
                app_gateways_data.append(app_gateway_info)
            logger.info(f"Retrieved {len(app_gateways_data)} application gateways")
        except AzureError as e:
            logger.error(f"Error fetching application gateways: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching application gateways: {e}")
        return app_gateways_data

    @tool
    async def get_application_gateway(
            self,
            resource_group_name: str,
            gateway_name: str
    ) -> dict:
        """
        Retrieve details for a specific application gateway.

        Args:
            resource_group_name (str): Resource group name
            gateway_name (str): Application gateway name

        Returns:
            dict: Application gateway details
        """
        logger.info(f"Fetching application gateway {gateway_name} in resource group {resource_group_name}")
        try:
            app_gateway = await self.network_client.application_gateways.get(
                resource_group_name=resource_group_name,
                application_gateway_name=gateway_name
            )

            # Use the same detailed extraction as in get_application_gateways
            app_gateway_info = {
                'name': app_gateway.name,
                'id': app_gateway.id,
                'location': app_gateway.location,
                'type': app_gateway.type,
                'resource_group': resource_group_name,
                'tags': app_gateway.tags or {},
                'provisioning_state': app_gateway.provisioning_state,
                'operational_state': app_gateway.operational_state,
                'tier': app_gateway.sku.tier if app_gateway.sku else None,
                'capacity': app_gateway.sku.capacity if app_gateway.sku else None,
                'enable_http2': app_gateway.enable_http2,
                'enable_fips': app_gateway.enable_fips,
                'zones': app_gateway.zones or []
            }

            logger.info(f"Retrieved application gateway {gateway_name}")
            return app_gateway_info
        except ResourceNotFoundError:
            logger.warning(f"Application gateway {gateway_name} not found in resource group {resource_group_name}")
        except AzureError as e:
            logger.error(f"Error fetching application gateway {gateway_name}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching application gateway {gateway_name}: {e}")
        return {}

    @tool
    async def get_application_gateway_backend_health(
            self,
            resource_group_name: str,
            gateway_name: str
    ) -> dict:
        """
        Retrieve backend health information for an application gateway.

        Args:
            resource_group_name (str): Resource group name
            gateway_name (str): Application gateway name

        Returns:
            dict: Backend health details
        """
        logger.info(f"Fetching backend health for application gateway {gateway_name}")
        try:
            # Start backend health check
            health_operation = await self.network_client.application_gateways.begin_backend_health(
                resource_group_name=resource_group_name,
                application_gateway_name=gateway_name
            )

            # Wait for operation to complete
            health_result = health_operation.result()

            backend_health_info = {
                'backend_address_pools': [
                    {
                        'backend_address_pool': {
                            'id': pool.backend_address_pool.id if pool.backend_address_pool else None
                        },
                        'backend_http_settings_collection': [
                            {
                                'backend_http_settings': {
                                    'id': setting.backend_http_settings.id if setting.backend_http_settings else None
                                },
                                'servers': [
                                    {
                                        'address': server.address,
                                        'ip_configuration': {
                                            'id': server.ip_configuration.id if server.ip_configuration else None
                                        } if server.ip_configuration else None,
                                        'health': server.health
                                    } for server in (setting.servers or [])
                                ]
                            } for setting in (pool.backend_http_settings_collection or [])
                        ]
                    } for pool in (health_result.backend_address_pools or [])
                ]
            }
            logger.info(f"Retrieved backend health for application gateway {gateway_name}")
            return backend_health_info
        except AzureError as e:
            logger.error(f"Error fetching backend health for application gateway {gateway_name}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching backend health for application gateway {gateway_name}: {e}")
        return {}

    @tool
    async def get_application_gateway_waf_policies(
            self,
            resource_group_name: Optional[str] = None
    ) -> list:
        """
        Retrieve Web Application Firewall policies.

        Args:
            resource_group_name (srt, optional): Optional resource group name to filter results

        Returns:
            list[dict]: List of WAF policy details
        """
        logger.info(f"Fetching WAF policies for resource group: {resource_group_name or 'all'}")
        waf_policies_data = []
        try:
            if resource_group_name:
                waf_policies = self.network_client.web_application_firewall_policies.list(
                    resource_group_name=resource_group_name
                )
            else:
                waf_policies = self.network_client.web_application_firewall_policies.list_all()

            async for policy in waf_policies:
                policy_info = {
                    'name': policy.name,
                    'id': policy.id,
                    'location': policy.location,
                    'type': policy.type,
                    'resource_group': policy.id.split('/')[4] if policy.id else None,
                    'tags': policy.tags or {},
                    'provisioning_state': policy.provisioning_state,
                    'resource_state': policy.resource_state,
                    'policy_settings': {
                        'state': policy.policy_settings.state,
                        'mode': policy.policy_settings.mode,
                        'request_body_check': policy.policy_settings.request_body_check,
                        'max_request_body_size_in_kb': policy.policy_settings.max_request_body_size_in_kb,
                        'file_upload_limit_in_mb': policy.policy_settings.file_upload_limit_in_mb
                    } if policy.policy_settings else None,
                    'managed_rules': {
                        'managed_rule_sets': [
                            {
                                'rule_set_type': rule_set.rule_set_type,
                                'rule_set_version': rule_set.rule_set_version,
                                'rule_group_overrides': [
                                    {
                                        'rule_group_name': override.rule_group_name,
                                        'rules': [
                                            {
                                                'rule_id': rule.rule_id,
                                                'state': rule.state,
                                                'action': rule.action
                                            } for rule in (override.rules or [])
                                        ]
                                    } for override in (rule_set.rule_group_overrides or [])
                                ]
                            } for rule_set in (policy.managed_rules.managed_rule_sets or [])
                        ],
                        'exclusions': [
                            {
                                'match_variable': exclusion.match_variable,
                                'selector_match_operator': exclusion.selector_match_operator,
                                'selector': exclusion.selector
                            } for exclusion in (policy.managed_rules.exclusions or [])
                        ]
                    } if policy.managed_rules else None,
                    'custom_rules': [
                        {
                            'name': rule.name,
                            'priority': rule.priority,
                            'rule_type': rule.rule_type,
                            'match_conditions': [
                                {
                                    'match_variables': [
                                        {
                                            'variable_name': var.variable_name,
                                            'selector': var.selector
                                        } for var in (condition.match_variables or [])
                                    ],
                                    'operator': condition.operator,
                                    'negation_condition': condition.negation_condition,
                                    'match_values': condition.match_values or [],
                                    'transforms': condition.transforms or []
                                } for condition in (rule.match_conditions or [])
                            ],
                            'action': rule.action,
                            'state': rule.state
                        } for rule in (policy.custom_rules or [])
                    ]
                }
                waf_policies_data.append(policy_info)

            logger.info(f"Retrieved {len(waf_policies_data)} WAF policies")
        except AzureError as e:
            logger.error(f"Error fetching WAF policies: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching WAF policies: {e}")
        return waf_policies_data

    @tool
    async def get_public_ip_addresses(
            self,
            resource_group_name: Optional[str] = None
    ) -> list:
        """
        Retrieve public IP addresses that can be used with application gateways.

        Args:
            resource_group_name (str, optional): Optional resource group name to filter results

        Returns:
            list[dict]: List of public IP address details
        """
        logger.info(f"Fetching public IP addresses for resource group: {resource_group_name or 'all'}")
        public_ips_data = []
        try:
            if resource_group_name:
                public_ips = self.network_client.public_ip_addresses.list(
                    resource_group_name=resource_group_name
                )
            else:
                public_ips = self.network_client.public_ip_addresses.list_all()

            async for public_ip in public_ips:
                public_ip_info = {
                    'name': public_ip.name,
                    'id': public_ip.id,
                    'location': public_ip.location,
                    'resource_group': public_ip.id.split('/')[4] if public_ip.id else None,
                    'tags': public_ip.tags or {},
                    'provisioning_state': public_ip.provisioning_state,
                    'resource_guid': public_ip.resource_guid,
                    'ip_address': public_ip.ip_address,
                    'public_ip_allocation_method': public_ip.public_ip_allocation_method,
                    'public_ip_address_version': public_ip.public_ip_address_version,
                    'dns_settings': {
                        'domain_name_label': public_ip.dns_settings.domain_name_label,
                        'fqdn': public_ip.dns_settings.fqdn,
                        'reverse_fqdn': public_ip.dns_settings.reverse_fqdn
                    } if public_ip.dns_settings else None,
                    'zones': public_ip.zones or [],
                    'sku': {
                        'name': public_ip.sku.name,
                        'tier': public_ip.sku.tier
                    } if public_ip.sku else None,
                    'ip_configuration': {
                        'id': public_ip.ip_configuration.id,
                        'name': public_ip.ip_configuration.id.split('/')[-1] if public_ip.ip_configuration else None
                    } if public_ip.ip_configuration else None
                }
                public_ips_data.append(public_ip_info)
            logger.info(f"Retrieved {len(public_ips_data)} public IP addresses")
        except AzureError as e:
            logger.error(f"Error fetching public IP addresses: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching public IP addresses: {e}")
        return public_ips_data

    @tool
    async def get_virtual_networks(
            self,
            resource_group_name: Optional[str] = None
    ) -> list:
        """
        Retrieve virtual networks that can be used with application gateways.

        Args:
            resource_group_name (str, optional): Optional resource group name to filter results

        Returns:
            list[dict]: List of virtual network details
        """
        logger.info(f"Fetching virtual networks for resource group: {resource_group_name or 'all'}")
        vnets_data = []
        try:
            if resource_group_name:
                vnets = self.network_client.virtual_networks.list(
                    resource_group_name=resource_group_name
                )
            else:
                vnets = self.network_client.virtual_networks.list_all()

            async for vnet in vnets:
                vnet_info = {
                    'name': vnet.name,
                    'id': vnet.id,
                    'location': vnet.location,
                    'resource_group': vnet.id.split('/')[4] if vnet.id else None,
                    'tags': vnet.tags or {},
                    'provisioning_state': vnet.provisioning_state,
                    'resource_guid': vnet.resource_guid,
                    'address_space': {
                        'address_prefixes': vnet.address_space.address_prefixes or []
                    } if vnet.address_space else None,
                    'subnets': [
                        {
                            'name': subnet.name,
                            'id': subnet.id,
                            'address_prefix': subnet.address_prefix,
                            'address_prefixes': subnet.address_prefixes or [],
                            'provisioning_state': subnet.provisioning_state,
                            'service_endpoints': [
                                {
                                    'service': endpoint.service,
                                    'locations': endpoint.locations or []
                                } for endpoint in (subnet.service_endpoints or [])
                            ]
                        } for subnet in (vnet.subnets or [])
                    ],
                    'dns_servers': vnet.dhcp_options.dns_servers if vnet.dhcp_options else [],
                    'enable_ddos_protection': vnet.enable_ddos_protection,
                    'enable_vm_protection': vnet.enable_vm_protection
                }
                vnets_data.append(vnet_info)
            logger.info(f"Retrieved {len(vnets_data)} virtual networks")
        except AzureError as e:
            logger.error(f"Error fetching virtual networks: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching virtual networks: {e}")
        return vnets_data

    @tool
    async def start_application_gateway(
            self,
            resource_group_name: str,
            gateway_name: str
    ) -> dict:
        """
        Start an application gateway.

        Args:
            resource_group_name (str): Resource group name
            gateway_name (str): Application gateway name

        Returns:
            dict: Operation result
        """
        logger.info(f"Starting application gateway {gateway_name} in resource group {resource_group_name}")
        try:
            start_operation = await self.network_client.application_gateways.begin_start(
                resource_group_name=resource_group_name,
                application_gateway_name=gateway_name
            )

            await start_operation.result()

            logger.info(f"Application gateway {gateway_name} start operation completed")
            return {
                'status': 'completed',
                'operation': 'start',
                'gateway_name': gateway_name,
                'resource_group': resource_group_name
            }
        except AzureError as e:
            logger.error(f"Error starting application gateway {gateway_name}: {e}")
            return {
                'status': 'failed',
                'operation': 'start',
                'gateway_name': gateway_name,
                'resource_group': resource_group_name,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"Unexpected error starting application gateway {gateway_name}: {e}")
            return {
                'status': 'failed',
                'operation': 'start',
                'gateway_name': gateway_name,
                'resource_group': resource_group_name,
                'error': str(e)
            }

    @tool
    async def stop_application_gateway(
            self,
            resource_group_name: str,
            gateway_name: str
    ) -> dict:
        """
        Stop an application gateway.

        Args:
            resource_group_name (str): Resource group name
            gateway_name (str): Application gateway name

        Returns:
            dict: Operation result
        """
        logger.info(f"Stopping application gateway {gateway_name} in resource group {resource_group_name}")
        try:
            stop_operation = await self.network_client.application_gateways.begin_stop(
                resource_group_name=resource_group_name,
                application_gateway_name=gateway_name
            )

            await stop_operation.result()

            logger.info(f"Application gateway {gateway_name} stop operation completed")
            return {
                'status': 'completed',
                'operation': 'stop',
                'gateway_name': gateway_name,
                'resource_group': resource_group_name
            }
        except AzureError as e:
            logger.error(f"Error stopping application gateway {gateway_name}: {e}")
            return {
                'status': 'failed',
                'operation': 'stop',
                'gateway_name': gateway_name,
                'resource_group': resource_group_name,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"Unexpected error stopping application gateway {gateway_name}: {e}")
            return {
                'status': 'failed',
                'operation': 'stop',
                'gateway_name': gateway_name,
                'resource_group': resource_group_name,
                'error': str(e)
            }

    @tool
    async def collect_all_application_gateway_data(
            self,
            resource_group_name: Optional[str] = None
    ) -> dict:
        """
        Collects comprehensive governance, risk, and compliance (GRC) data for Azure Application Gateway
        resources within a specified resource group or across the entire subscription.

        This method asynchronously gathers detailed metadata and configuration for Application Gateways,
        including related components such as WAF policies, public IPs, virtual networks, and backend health status.
        It is useful for compliance audits, security assessments, and infrastructure monitoring.

        Args:
            resource_group_name (str, optional):
                The name of the Azure resource group to filter the data. If not provided, data is collected
                for all resource groups in the subscription.

        Returns:
            dict: A dictionary containing the following keys:
                - subscription_id: Azure subscription identifier
                - resource_group_filter: The resource group used for filtering (if any)
                - resource_groups: List of resource groups (if not filtered)
                - application_gateways: List of Application Gateway instances
                - waf_policies: Associated Web Application Firewall (WAF) policies
                - public_ip_addresses: Public IPs linked to Application Gateways
                - virtual_networks: Related virtual networks and subnets
                - backend_health_data: Health status of backend pools per gateway
                - collection_timestamp: ISO-formatted timestamp of data collection
        """
        logger.info(
            f"Starting comprehensive application gateway data collection for resource group: {resource_group_name or 'all'}")

        try:
            (
                resource_groups,
                application_gateways,
                waf_policies,
                public_ips,
                virtual_networks
            ) = await asyncio.gather(
                self.get_resource_groups() if not resource_group_name else [],
                self.get_application_gateways(resource_group_name),
                self.get_application_gateway_waf_policies(resource_group_name),
                self.get_public_ip_addresses(resource_group_name),
                self.get_virtual_networks(resource_group_name),
                return_exceptions=True
            )

            # Get backend health for each application gateway
            backend_health_data = []
            for app_gateway in (application_gateways if not isinstance(application_gateways, Exception) else []):
                rg_name = app_gateway.get('resource_group')
                gw_name = app_gateway.get('name')
                if rg_name and gw_name:
                    health_data = await self.get_application_gateway_backend_health(rg_name, gw_name)
                    if health_data:
                        backend_health_data.append({
                            'gateway_name': gw_name,
                            'resource_group': rg_name,
                            'health_data': health_data
                        })

            logger.info(f"Finished comprehensive application gateway data collection")

            result = {
                'subscription_id': self.subscription_id,
                'resource_group_filter': resource_group_name,
                'resource_groups': resource_groups if not isinstance(resource_groups, Exception) else [],
                'application_gateways': application_gateways if not isinstance(application_gateways, Exception) else [],
                'waf_policies': waf_policies if not isinstance(waf_policies, Exception) else [],
                'public_ip_addresses': public_ips if not isinstance(public_ips, Exception) else [],
                'virtual_networks': virtual_networks if not isinstance(virtual_networks, Exception) else [],
                'backend_health_data': backend_health_data,
                'collection_timestamp': datetime.now().isoformat()
            }
            logger.info(result)
            return result

        except Exception as e:
            logger.error(f"Error during comprehensive application gateway data collection: {e}")
            return {}

    @tool
    async def collect_authentication_authorization_details(
            self,
            resource_group_name: Optional[str] = None
    ) -> dict:
        """
        Collects authentication and authorization configuration details for Azure API Management resources.

        Args:
            resource_group_name (str, optional): Resource group to filter APIM instances.

        Returns:
            dict: Dictionary with authentication settings, RBAC policies, and managed identities.
        """
        result = {
            "resource_group_filter": resource_group_name,
            "authentication_settings": [],
            "authorization_policies": [],
            "managed_identities": [],
            "collection_timestamp": datetime.utcnow().isoformat()
        }

        try:
            apim_services = []
            if resource_group_name:
                for svc in self.apim_client.api_management_service.list_by_resource_group(resource_group_name):
                    apim_services.append((resource_group_name, svc))
            else:
                # Query all resources of type Microsoft.ApiManagement/service
                for resource in self.resource_client.resources.list(
                        filter="resourceType eq 'Microsoft.ApiManagement/service'"):
                    rg_name = resource.id.split("/")[4]
                    svc_name = resource.name
                    svc = await self.apim_client.api_management_service.get(rg_name, svc_name)
                    apim_services.append((rg_name, svc))

            for rg, service in apim_services:
                name = service.name

                # Managed Identity
                result["managed_identities"].append({
                    "name": name,
                    "resource_group": rg,
                    "identity": service.identity.as_dict() if service.identity else {}
                })

                # RBAC role assignments
                rbac_scope = f"/subscriptions/{self.subscription_id}/resourceGroups/{rg}/providers/Microsoft.ApiManagement/service/{name}"
                for role in self.rbac_client.role_assignments.list_for_scope(rbac_scope):
                    result["authorization_policies"].append({
                        "name": name,
                        "resource_group": rg,
                        "principal_id": role.principal_id,
                        "role_definition_id": role.role_definition_id,
                        "scope": role.scope
                    })

                # Identity Providers (OAuth2, AAD, etc.)
                for idp in self.apim_client.identity_provider.list_by_service(rg, name):
                    result["authentication_settings"].append({
                        "name": name,
                        "resource_group": rg,
                        "identity_provider": idp.type,
                        "client_id": idp.client_id,
                        "allowed_tenants": getattr(idp, 'allowed_tenants', []),
                        "authority": getattr(idp, 'authority', None)
                    })

            logger.info("Successfully collected API Management auth and RBAC details.")
        except Exception as e:
            logger.error(f"Error collecting auth and RBAC details: {e}")
        return result  # Return partial data
