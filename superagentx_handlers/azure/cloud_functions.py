import logging
import os

from azure.core.exceptions import AzureError
from azure.identity.aio import ClientSecretCredential
from azure.mgmt.web.aio import WebSiteManagementClient
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


def _extract_resource_group_from_id(resource_id: str) -> str:
    """Extract resource group name from Azure resource ID."""
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        rg_index = parts.index("resourceGroups")
        return parts[rg_index + 1] if rg_index + 1 < len(parts) else ""
    except (ValueError, IndexError):
        return ""


def _extract_site_config(function_app) -> dict:
    """Extract site configuration properties."""
    if not hasattr(function_app, "site_config") or not function_app.site_config:
        return {}

    site_config = function_app.site_config
    return {
        "number_of_workers": getattr(site_config, "number_of_workers", None),
        "default_documents": getattr(site_config, "default_documents", []),
        "net_framework_version": getattr(site_config, "net_framework_version", None),
        "php_version": getattr(site_config, "php_version", None),
        "python_version": getattr(site_config, "python_version", None),
        "node_version": getattr(site_config, "node_version", None),
        "power_shell_version": getattr(site_config, "power_shell_version", None),
        "linux_fx_version": getattr(site_config, "linux_fx_version", None),
        "windows_fx_version": getattr(site_config, "windows_fx_version", None),
        "request_tracing_enabled": getattr(site_config, "request_tracing_enabled", None),
        "request_tracing_expiration_time": getattr(site_config, "request_tracing_expiration_time", None),
        "remote_debugging_enabled": getattr(site_config, "remote_debugging_enabled", None),
        "remote_debugging_version": getattr(site_config, "remote_debugging_version", None),
        "http_logging_enabled": getattr(site_config, "http_logging_enabled", None),
        "acr_use_managed_identity_creds": getattr(site_config, "acr_use_managed_identity_creds", None),
        "acr_user_managed_identity_id": getattr(site_config, "acr_user_managed_identity_id", None),
        "logs_directory_size_limit": getattr(site_config, "logs_directory_size_limit", None),
        "detailed_error_logging_enabled": getattr(site_config, "detailed_error_logging_enabled", None),
        "publishing_username": getattr(site_config, "publishing_username", None),
        "use32_bit_worker_process": getattr(site_config, "use32_bit_worker_process", None),
        "web_sockets_enabled": getattr(site_config, "web_sockets_enabled", None),
        "always_on": getattr(site_config, "always_on", None),
        "managed_pipeline_mode": getattr(site_config, "managed_pipeline_mode", None),
        "virtual_applications": getattr(site_config, "virtual_applications", []),
        "load_balancing": getattr(site_config, "load_balancing", None),
        "experiments": getattr(site_config, "experiments", None),
        "limits": getattr(site_config, "limits", None),
        "auto_heal_enabled": getattr(site_config, "auto_heal_enabled", None),
        "auto_heal_rules": getattr(site_config, "auto_heal_rules", None),
        "tracing_options": getattr(site_config, "tracing_options", None),
        "vnet_name": getattr(site_config, "vnet_name", None),
        "vnet_route_all_enabled": getattr(site_config, "vnet_route_all_enabled", None),
        "vnet_private_ports_count": getattr(site_config, "vnet_private_ports_count", None),
        "cors": getattr(site_config, "cors", None),
        "push": getattr(site_config, "push", None),
        "api_definition": getattr(site_config, "api_definition", None),
        "api_management_config": getattr(site_config, "api_management_config", None),
        "auto_swap_slot_name": getattr(site_config, "auto_swap_slot_name", None),
        "local_my_sql_enabled": getattr(site_config, "local_my_sql_enabled", None),
        "managed_service_identity_id": getattr(site_config, "managed_service_identity_id", None),
        "x_managed_service_identity_id": getattr(site_config, "x_managed_service_identity_id", None),
        "ip_security_restrictions": getattr(site_config, "ip_security_restrictions", []),
        "scm_ip_security_restrictions": getattr(site_config, "scm_ip_security_restrictions", []),
        "scm_ip_security_restrictions_use_main": getattr(site_config, "scm_ip_security_restrictions_use_main",
                                                         None),
        "http20_enabled": getattr(site_config, "http20_enabled", None),
        "min_tls_version": getattr(site_config, "min_tls_version", None),
        "scm_min_tls_version": getattr(site_config, "scm_min_tls_version", None),
        "ftps_state": getattr(site_config, "ftps_state", None),
        "pre_warmed_instance_count": getattr(site_config, "pre_warmed_instance_count", None),
        "function_app_scale_limit": getattr(site_config, "function_app_scale_limit", None),
        "health_check_path": getattr(site_config, "health_check_path", None),
        "functions_runtime_scale_monitoring_enabled": getattr(site_config,
                                                              "functions_runtime_scale_monitoring_enabled", None),
        "website_time_zone": getattr(site_config, "website_time_zone", None),
        "minimum_elastic_instance_count": getattr(site_config, "minimum_elastic_instance_count", None),
        "azure_storage_accounts": getattr(site_config, "azure_storage_accounts", {}),
        "public_network_access": getattr(site_config, "public_network_access", None),
    }


def _function_to_dict(function_app) -> dict:
    """
    Convert Azure Function App object to dictionary with all properties.

    Args:
        function_app: Azure Function App object

    Returns:
        Dict containing all function app properties
    """
    function_dict = {
        # Basic Properties
        "id": getattr(function_app, "id", None),
        "name": getattr(function_app, "name", None),
        "type": getattr(function_app, "type", None),
        "kind": getattr(function_app, "kind", None),
        "location": getattr(function_app, "location", None),
        "tags": getattr(function_app, "tags", {}),

        # Identity Properties
        "identity": {
            "type": getattr(function_app.identity, "type", None) if hasattr(
                function_app, "identity"
            ) and function_app.identity else None,
            "principal_id": getattr(function_app.identity, "principal_id", None) if hasattr(
                function_app, "identity"
            ) and function_app.identity else None,
            "tenant_id": getattr(function_app.identity, "tenant_id", None) if hasattr(
                function_app, "identity"
            ) and function_app.identity else None,
            "user_assigned_identities": getattr(function_app.identity, "user_assigned_identities", {}) if hasattr(
                function_app, "identity"
            ) and function_app.identity else {}
        },

        # Site Properties
        "state": getattr(function_app, "state", None),
        "host_names": getattr(function_app, "host_names", []),
        "repository_site_name": getattr(function_app, "repository_site_name", None),
        "usage_state": getattr(function_app, "usage_state", None),
        "enabled": getattr(function_app, "enabled", None),
        "enabled_host_names": getattr(function_app, "enabled_host_names", []),
        "availability_state": getattr(function_app, "availability_state", None),
        "server_farm_id": getattr(function_app, "server_farm_id", None),
        "reserved": getattr(function_app, "reserved", None),
        "is_xenon": getattr(function_app, "is_xenon", None),
        "hyper_v": getattr(function_app, "hyper_v", None),
        "last_modified_time_utc": getattr(function_app, "last_modified_time_utc", None),
        "storage_recovery_default_state": getattr(function_app, "storage_recovery_default_state", None),
        "content_availability_state": getattr(function_app, "content_availability_state", None),
        "runtime_availability_state": getattr(function_app, "runtime_availability_state", None),
        "secret_store_id": getattr(function_app, "secret_store_id", None),
        "https_only": getattr(function_app, "https_only", None),
        "redundancy_mode": getattr(function_app, "redundancy_mode", None),
        "in_progress_operation_id": getattr(function_app, "in_progress_operation_id", None),
        "public_network_access": getattr(function_app, "public_network_access", None),
        "key_vault_reference_identity": getattr(function_app, "key_vault_reference_identity", None),
        "default_host_name": getattr(function_app, "default_host_name", None),
        "custom_domain_verification_id": getattr(function_app, "custom_domain_verification_id", None),
        "outbound_ip_addresses": getattr(function_app, "outbound_ip_addresses", None),
        "possible_outbound_ip_addresses": getattr(function_app, "possible_outbound_ip_addresses", None),
        "container_size": getattr(function_app, "container_size", None),
        "daily_memory_time_quota": getattr(function_app, "daily_memory_time_quota", None),
        "suspended_till": getattr(function_app, "suspended_till", None),
        "max_number_of_workers": getattr(function_app, "max_number_of_workers", None),
        "client_affinity_enabled": getattr(function_app, "client_affinity_enabled", None),
        "client_cert_enabled": getattr(function_app, "client_cert_enabled", None),
        "client_cert_mode": getattr(function_app, "client_cert_mode", None),
        "client_cert_exclusion_paths": getattr(function_app, "client_cert_exclusion_paths", None),
        "host_names_disabled": getattr(function_app, "host_names_disabled", None),
        "vnet_name": getattr(function_app, "vnet_name", None),
        "vnet_route_all_enabled": getattr(function_app, "vnet_route_all_enabled", None),
        "vnet_image_pull_enabled": getattr(function_app, "vnet_image_pull_enabled", None),
        "vnet_content_share_enabled": getattr(function_app, "vnet_content_share_enabled", None),

        # Site Configuration
        "site_config": _extract_site_config(function_app=function_app),

        # Host Name SSL States
        "host_name_ssl_states": [
            {
                "name": ssl_state.name,
                "ssl_state": ssl_state.ssl_state,
                "virtual_ip": ssl_state.virtual_ip,
                "thumbprint": ssl_state.thumbprint,
                "to_update": ssl_state.to_update,
                "host_type": ssl_state.host_type
            }
            for ssl_state in getattr(function_app, "host_name_ssl_states", [])
        ],

        # Resource Group
        "resource_group": _extract_resource_group_from_id(resource_id=getattr(function_app, "id", "")),

        # Extended Properties
        "extended_location": getattr(function_app, "extended_location", None),
        "management_hostname": getattr(function_app, "management_hostname", None),
        "virtual_network_subnet_id": getattr(function_app, "virtual_network_subnet_id", None),
        "storage_account_required": getattr(function_app, "storage_account_required", None),
        "scm_site_also_stopped": getattr(function_app, "scm_site_also_stopped", None),
        "target_swap_slot": getattr(function_app, "target_swap_slot", None),
        "hosting_environment_profile": getattr(function_app, "hosting_environment_profile", None),
        "slot_swap_status": getattr(function_app, "slot_swap_status", None),
    }

    logger.debug(f"Converted function app '{function_app.name}' to dictionary with {len(function_dict)} properties")
    return function_dict


class AzureFunctionHandler(BaseHandler):
    """
    A handler class for managing Azure Cloud Functions management class for retrieving and managing function apps
    within the configured Azure subscription, facilitating serverless asset detail collection.
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

        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        self.web_client = WebSiteManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

    @tool
    async def get_all_function_apps_in_subscription(self) -> list:
        """
        Get all function apps in the subscription

        Returns:
            List[Dict]: List of function app properties as dictionaries
        """
        function_apps = []
        try:
            async for app in self.web_client.web_apps.list():
                # Filter only function apps (kind contains 'functionapp')
                if hasattr(app, 'kind') and app.kind and 'functionapp' in app.kind.lower():
                    function_apps.append(_function_to_dict(function_app=app))
                    logger.debug(f"Added function app: {app.name}")

            logger.info(f"Successfully retrieved {len(function_apps)} function apps from subscription")
            return function_apps
        except AzureError as e:
            logger.error(f"Azure error retrieving function apps from subscription {self.subscription_id}: {str(e)}")
        except Exception as e:
            logger.error(
                f"Unexpected error retrieving function apps from subscription {self.subscription_id}: {str(e)}")
        finally:
            await self.close()
        return function_apps

    @tool
    async def get_function_apps_by_resource_group(self, resource_group_name: str) -> list:
        """
        Get all function apps in a specific resource group

        Args:
            resource_group_name (str): Name of the resource group

        Returns:
            List[Dict]: List of function app properties as dictionaries
        """
        function_apps = []
        try:
            async for app in self.web_client.web_apps.list_by_resource_group(resource_group_name=resource_group_name):
                # Filter only function apps (kind contains 'functionapp')
                if hasattr(app, 'kind') and app.kind and 'functionapp' in app.kind.lower():
                    function_apps.append(_function_to_dict(function_app=app))
                    logger.debug(f"Added function app: {app.name} from resource group: {resource_group_name}")

            logger.info(
                f"Successfully retrieved {len(function_apps)} function apps from resource group: {resource_group_name}"
            )
            return function_apps
        except AzureError as e:
            logger.error(f"Azure error retrieving function apps from resource group {resource_group_name}: {str(e)}")
        except Exception as e:
            logger.error(
                f"Unexpected error retrieving function apps from resource group {resource_group_name}: {str(e)}"
            )
        finally:
            await self.close()
        return function_apps

    @tool
    async def get_function_app_by_name(
            self,
            resource_group_name: str,
            function_app_name: str
    ) -> dict:
        """
        Get a specific function app by name

        Args:
            resource_group_name (str): Name of the resource group
            function_app_name (str): Name of the function app

        Returns:
            Dict: Function app properties as dictionary
        """
        try:
            app = await self.web_client.web_apps.get(
                resource_group_name=resource_group_name,
                name=function_app_name
            )

            # Verify it's a function app
            if not (hasattr(app, 'kind') and app.kind and 'functionapp' in app.kind.lower()):
                raise ValueError(f"App {function_app_name} is not a function app")

            function_app_dict = _function_to_dict(function_app=app)
            logger.info(
                f"Successfully retrieved function app: {function_app_name} from resource group: {resource_group_name}"
            )
            return function_app_dict
        except AzureError as e:
            logger.error(
                f"Azure error retrieving function app {function_app_name} from resource group"
                f" {resource_group_name}: {str(e)}"
            )
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error retrieving function app {function_app_name} from resource group"
                f" {resource_group_name}: {str(e)}"
            )
        finally:
            await self.close()
        return {}

    @tool
    async def get_function_app_configuration(
            self,
            resource_group_name: str,
            function_app_name: str
    ) -> dict:
        """
        Get function app configuration including app settings

        Args:
            resource_group_name (str): Name of the resource group
            function_app_name (str): Name of the function app

        Returns:
            Dict: Function app configuration as dictionary
        """
        try:
            # Get site config
            site_config = await self.web_client.web_apps.get_configuration(
                resource_group_name=resource_group_name,
                name=function_app_name
            )

            # Get application settings
            app_settings = await self.web_client.web_apps.list_application_settings(
                resource_group_name=resource_group_name,
                name=function_app_name
            )

            # Get connection strings
            connection_strings = await self.web_client.web_apps.list_connection_strings(
                resource_group_name=resource_group_name,
                name=function_app_name
            )

            config_dict = {
                "site_config": _function_to_dict(function_app=site_config),
                "app_settings": getattr(app_settings, "properties", {}),
                "connection_strings": getattr(connection_strings, "properties", {})
            }

            logger.info(f"Successfully retrieved configuration for function app: {function_app_name}")
            return config_dict
        except AzureError as e:
            logger.error(f"Azure error retrieving configuration for function app {function_app_name}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving configuration for function app {function_app_name}: {str(e)}")
        finally:
            await self.close()
        return {}

    async def close(self):
        """Close the Azure clients and credentials."""
        try:
            if self.web_client:
                await self.web_client.close()
            if self.credential:
                await self.credential.close()
            logger.debug("Closed Azure Function manager connections")
        except Exception as e:
            logger.error(f"Error closing Azure Function manager connections: {str(e)}")
