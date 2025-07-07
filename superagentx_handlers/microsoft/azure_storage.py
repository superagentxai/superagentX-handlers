# azure_storage.py
import asyncio
import os
import logging
from typing import Any, AsyncIterator

from azure.identity.aio import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.storage.aio import StorageManagementClient
from azure.storage.blob.aio import BlobServiceClient
from azure.storage.filedatalake.aio import FileSystemClient, DataLakeServiceClient
from azure.storage.queue.aio import QueueServiceClient
from azure.data.tables.aio import TableServiceClient

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import iter_to_aiter # Assuming this utility exists

logger = logging.getLogger(__name__)


class AzureStorageHandler(BaseHandler):
    """
    A handler class for interaction with Azure Storage accounts and their resources.
    This class extends BaseHandler and provides methods for retrieving
    storage-related information for Governance, Risk, and Compliance (GRC) purposes.
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
        Initializes the Azure Storage Handler with authenticated Azure management and data plane clients.

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
            # Authenticate using Client Secret Credential for explicit credentials,
            # or DefaultAzureCredential for managed identities/VS Code login etc.
            if all([tenant_id, client_id, client_secret]):
                self.credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
                logger.debug("Azure Storage Handler: Authenticating with Client Secret Credential.")
            else:
                self.credential = DefaultAzureCredential()
                logger.debug("Azure Storage Handler: Authenticating with DefaultAzureCredential.")

            # Initialize Azure Storage Management Client for control plane operations (e.g., listing storage accounts)
            self.storage_mgmt_client = StorageManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            logger.debug("Azure Storage Management Client initialized.")

        except Exception as e:
            logger.error(
                f"Error initializing Azure Storage clients: {e}", exc_info=True)
            raise ValueError(
                f"Failed to initialize Azure Storage Handler. Please ensure "
                f"Azure credentials (subscription_id, tenant_id, client_id, client_secret "
                f"or appropriate environment variables) are valid and that the "
                f"application has necessary RBAC permissions (e.g., 'Storage Account Contributor' or 'Reader')."
            )

    async def _get_resource_group_from_account_id(self, account_id: str) -> str:
        """Helper to extract resource group name from a storage account ID."""
        parts = account_id.split('/')
        # Expected format: /subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Storage/storageAccounts/{accountName}
        if len(parts) >= 5 and parts[3].lower() == 'resourcegroups':
            return parts[4]
        raise ValueError(f"Could not extract resource group from account ID: {account_id}")

    async def _get_blob_service_client(self, storage_account_name: str, resource_group_name: str) -> BlobServiceClient | None:
        """Helper to get an authenticated BlobServiceClient for a specific storage account."""
        try:
            # Fetch storage account keys for data plane authentication
            keys = await self.storage_mgmt_client.storage_accounts.list_keys(
                resource_group_name=resource_group_name,
                account_name=storage_account_name
            )
            key = keys.keys[0].value # Assuming first key is available

            return BlobServiceClient(
                account_url=f"https://{storage_account_name}.blob.core.windows.net",
                credential=key
            )
        except Exception as e:
            logger.error(f"Error getting BlobServiceClient for {storage_account_name}: {e}", exc_info=True)
            return None

    async def _get_file_service_client(self, storage_account_name: str, resource_group_name: str) -> DataLakeServiceClient | None:
        """Helper to get an authenticated DataLakeServiceClient for a specific storage account (ADLS Gen2)."""
        try:
            keys = await self.storage_mgmt_client.storage_accounts.list_keys(
                resource_group_name=resource_group_name,
                account_name=storage_account_name
            )
            key = keys.keys[0].value

            return DataLakeServiceClient(
                account_url=f"https://{storage_account_name}.dfs.core.windows.net", # For ADLS Gen2 endpoint
                credential=key
            )
        except Exception as e:
            logger.error(f"Error getting DataLakeServiceClient for {storage_account_name}: {e}", exc_info=True)
            return None

    async def _get_filesystem_client(self, storage_account_name: str, resource_group_name: str, share_name: str) -> FileSystemClient | None:
        """Helper to get an authenticated FileSystemClient for a specific file share (filesystem in ADLS Gen2 context)."""
        try:
            dl_service_client = await self._get_file_service_client(storage_account_name, resource_group_name)
            if not dl_service_client:
                return None
            return dl_service_client.get_file_system_client(share_name)
        except Exception as e:
            logger.error(f"Error getting FileSystemClient for share '{share_name}' in account '{storage_account_name}': {e}", exc_info=True)
            return None

    async def _get_queue_service_client(self, storage_account_name: str, resource_group_name: str) -> QueueServiceClient | None:
        """Helper to get an authenticated QueueServiceClient for a specific storage account."""
        try:
            keys = await self.storage_mgmt_client.storage_accounts.list_keys(
                resource_group_name=resource_group_name,
                account_name=storage_account_name
            )
            key = keys.keys[0].value

            return QueueServiceClient(
                account_url=f"https://{storage_account_name}.queue.core.windows.net",
                credential=key
            )
        except Exception as e:
            logger.error(f"Error getting QueueServiceClient for {storage_account_name}: {e}", exc_info=True)
            return None

    async def _get_table_service_client(self, storage_account_name: str, resource_group_name: str) -> TableServiceClient | None:
        """Helper to get an authenticated TableServiceClient for a specific storage account."""
        try:
            keys = await self.storage_mgmt_client.storage_accounts.list_keys(
                resource_group_name=resource_group_name,
                account_name=storage_account_name
            )
            key = keys.keys[0].value

            return TableServiceClient(
                account_url=f"https://{storage_account_name}.table.core.windows.net",
                credential=key
            )
        except Exception as e:
            logger.error(f"Error getting TableServiceClient for {storage_account_name}: {e}", exc_info=True)
            return None

    @tool
    async def get_storage_accounts(self) -> list[dict]:
        """
        Gets IAM related for all accessible Azure Storage Accounts within the subscription.
        This includes basic details, SKU, kind, location, access tiers, encryption status, and public access settings.
        Requires 'Microsoft.Storage/storageAccounts/read' (e.g., 'Reader' role) Azure RBAC permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains storage account details.
        """
        logger.debug("Getting for Azure Storage Accounts...")
        storage_accounts = []
        try:
            # The list() method returns an AsyncItemPaged, which is an async iterator
            async for account in self.storage_mgmt_client.storage_accounts.list():
                resource_group_name = await self._get_resource_group_from_account_id(account.id)
                account_details = await self.storage_mgmt_client.storage_accounts.get_properties(
                    resource_group_name=resource_group_name,
                    account_name=account.name
                )
                network_rule_set = account_details.network_rule_set
                encryption = account_details.encryption
                azure_files_identity_based_auth = account_details.azure_files_identity_based_authentication
                storage_accounts.append({
                    "id": account_details.id,
                    "name": account_details.name,
                    "location": account_details.location,
                    "resourceGroup": resource_group_name,
                    "sku": account_details.sku.name if account_details.sku else None,
                    "kind": account_details.kind,
                    "accessTier": account_details.access_tier,
                    "primaryLocation": account_details.primary_location,
                    "statusOfPrimary": account_details.status_of_primary,
                    "encryptionStatus": {
                        "services": {s.key: {"enabled": s.enabled, "lastEnabledTime": s.last_enabled_time.isoformat() if s.last_enabled_time else None} for s in encryption.services.as_dict().values()} if encryption and encryption.services else None,
                        "keySource": str(encryption.key_source) if encryption else None,
                        "keyVaultProperties": {
                            "keyName": encryption.key_vault_properties.key_name,
                            "keyVaultUri": encryption.key_vault_properties.key_vault_uri,
                            "keyVersion": encryption.key_vault_properties.key_version,
                            "lastRotationTime": encryption.key_vault_properties.last_rotation_time.isoformat() if encryption.key_vault_properties.last_rotation_time else None,
                        } if encryption and encryption.key_vault_properties else None,
                        "requireInfrastructureEncryption": encryption.require_infrastructure_encryption
                    },
                    "networkRuleSet": {
                        "defaultAction": str(network_rule_set.default_action) if network_rule_set else None,
                        "ipRules": [{"value": ip_rule.value, "action": str(ip_rule.action)} for ip_rule in network_rule_set.ip_rules] if network_rule_set and network_rule_set.ip_rules else [],
                        "virtualNetworkRules": [{"id": vnet_rule.id, "action": str(vnet_rule.action)} for vnet_rule in network_rule_set.virtual_network_rules] if network_rule_set and network_rule_set.virtual_network_rules else [],
                        "bypass": [str(b) for b in network_rule_set.bypass] if network_rule_set and network_rule_set.bypass else [],
                    },
                    "publicNetworkAccess": str(account_details.public_network_access) if hasattr(account_details, 'public_network_access') else None,
                    "minimumTlsVersion": str(account_details.minimum_tls_version) if hasattr(account_details, 'minimum_tls_version') else None,
                    "allowBlobPublicAccess": account_details.allow_blob_public_access,
                    "azureFilesIdentityBasedAuthentication": {
                        "directoryServiceOptions": str(azure_files_identity_based_auth.directory_service_options) if azure_files_identity_based_auth else None,
                        "activeDirectoryProperties": {
                            "domainName": azure_files_identity_based_auth.active_directory_properties.domain_name,
                            "domainGuid": azure_files_identity_based_auth.active_directory_properties.domain_guid,
                            "azureStorageSid": azure_files_identity_based_auth.active_directory_properties.azure_storage_sid,
                            "netBiosDomainName": azure_files_identity_based_auth.active_directory_properties.net_bios_domain_name,
                            "forestAction": str(azure_files_identity_based_auth.active_directory_properties.forest_action) if azure_files_identity_based_auth.active_directory_properties else None,
                        } if azure_files_identity_based_auth and azure_files_identity_based_auth.active_directory_properties else None,
                    } if azure_files_identity_based_auth else None,
                    "isHnsEnabled": account_details.is_hns_enabled, # For ADLS Gen2
                    "defaultToOAuthAuthentication": account_details.default_to_oauth_authentication,
                    "routingPreference": {
                        "routingChoice": str(account_details.routing_preference.routing_choice) if account_details.routing_preference else None,
                        "publishMicrosoftEndpoints": account_details.routing_preference.publish_microsoft_endpoints if account_details.routing_preference else None,
                        "publishInternetEndpoints": account_details.routing_preference.publish_internet_endpoints if account_details.routing_preference else None,
                    } if account_details.routing_preference else None,
                })
            logger.debug(f"Got {len(storage_accounts)} Storage Account records.")
        except Exception as e:
            logger.error(
                f"An error occurred while getting Storage Account: {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Storage/storageAccounts/read' (e.g., 'Reader' role) RBAC permission for the subscription.")
        return storage_accounts

    @tool
    async def get_blob_containers(self, storage_account_name: str, resource_group_name: str) -> list[dict] | None:
        """
        Gets for all accessible Blob Containers within a specific storage account.
        Includes details like public access level, immutability policy, and legal hold status.
        Requires 'Storage Blob Data Reader' or 'Reader' role on the storage account.

        Args:
            storage_account_name (str): The name of the storage account.
            resource_group_name (str): The resource group of the storage account.

        Returns:
            list: A list of dictionaries, where each dictionary contains blob container details.
        """
        logger.debug(f"Getting for Blob Containers in storage account '{storage_account_name}' (RG: '{resource_group_name}')...")
        containers = []
        blob_service_client = None
        try:
            blob_service_client = await self._get_blob_service_client(storage_account_name, resource_group_name)
            if not blob_service_client:
                return None

            async for container in blob_service_client.list_containers(include_metadata=True):
                containers.append({
                    "name": container.name,
                    "lastModified": container.last_modified.isoformat() if container.last_modified else None,
                    "etag": container.etag,
                    "publicAccess": str(container.public_access) if container.public_access else "Off",
                    "hasImmutabilityPolicy": container.has_immutability_policy,
                    "hasLegalHold": container.has_legal_hold,
                    "leaseStatus": str(container.lease_status) if container.lease_status else None,
                    "leaseState": str(container.lease_state) if container.lease_state else None,
                    "leaseDuration": str(container.lease_duration) if container.lease_duration else None,
                    "defaultEncryptionScope": container.default_encryption_scope,
                    "denyEncryptionScopeOverride": container.deny_encryption_scope_override,
                })
            logger.debug(f"Got {len(containers)} Blob Container records for account '{storage_account_name}'.")
            return containers
        except Exception as e:
            logger.error(f"An error occurred while getting Blob Container for storage account '{storage_account_name}' (RG: '{resource_group_name}'): {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Storage Blob Data Reader' or 'Reader' role on the storage account."
            )
            return None
        finally:
            if blob_service_client:
                await blob_service_client.close()

    @tool
    async def get_blobs(self, storage_account_name: str, resource_group_name: str, container_name: str) -> list[dict] | None:
        """
        Gets for all accessible Blobs within a specific container.
        Includes details like size, type, encryption status, and last modified time.
        Requires 'Storage Blob Data Reader' role on the container or storage account.

        Args:
            storage_account_name (str): The name of the storage account.
            resource_group_name (str): The resource group of the storage account.
            container_name (str): The name of the blob container.

        Returns:
            list: A list of dictionaries, where each dictionary contains blob details.
        """
        logger.debug(f"Getting for Blobs in container '{container_name}' (Account: '{storage_account_name}')...")
        blobs = []
        blob_service_client = None
        try:
            blob_service_client = await self._get_blob_service_client(storage_account_name, resource_group_name)
            if not blob_service_client:
                return None

            container_client = blob_service_client.get_container_client(container_name)
            async for blob in container_client.list_blobs(include=['metadata', 'snapshots', 'versions', 'deleted', 'tags', 'encryption_scope']):
                blobs.append({
                    "name": blob.name,
                    "containerName": container_name,
                    "size": blob.size,
                    "blobType": str(blob.blob_type),
                    "creationTime": blob.creation_time.isoformat() if blob.creation_time else None,
                    "lastModified": blob.last_modified.isoformat() if blob.last_modified else None,
                    "etag": blob.etag,
                    "isEncrypted": blob.is_encrypted,
                    "encryptionScope": blob.encryption_scope,
                    "accessTier": str(blob.blob_tier) if blob.blob_tier else None,
                    "leaseStatus": str(blob.lease.status) if blob.lease else None,
                    "leaseState": str(blob.lease.state) if blob.lease else None,
                    "leaseDuration": str(blob.lease.duration) if blob.lease else None,
                    "hasLegalHold": blob.legal_hold,
                    "hasImmutabilityPolicy": blob.immutability_policy,
                    "isDeleted": blob.deleted,
                    "deletedTime": blob.deleted_time.isoformat() if blob.deleted_time else None,
                    "versionId": blob.version_id,
                    "isLatestVersion": blob.is_current_version,
                    "metadata": blob.metadata,
                    "tags": blob.tags,
                })
            logger.debug(f"Got {len(blobs)} Blob records for container '{container_name}'.")
            return blobs
        except Exception as e:
            logger.error(f"An error occurred while getting Blobs for container '{container_name}' in account '{storage_account_name}': {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Storage Blob Data Reader' role on the container or storage account."
            )
            return None
        finally:
            if blob_service_client:
                await blob_service_client.close()

    @tool
    async def get_file_shares(self, storage_account_name: str, resource_group_name: str) -> list[dict] | None:
        """
        Gets for all accessible File Shares within a specific storage account.
        Includes details like share size, protocol, and root squashing settings.
        Requires 'Storage File Data Reader' or 'Reader' role on the storage account.

        Args:
            storage_account_name (str): The name of the storage account.
            resource_group_name (str): The resource group of the storage account.

        Returns:
            list: A list of dictionaries, where each dictionary contains file share details.
        """
        logger.debug(f"Getting for File Shares in storage account '{storage_account_name}' (RG: '{resource_group_name}')...")
        file_shares = []
        dl_service_client = None
        try:
            dl_service_client = await self._get_file_service_client(storage_account_name, resource_group_name)
            if not dl_service_client:
                return None

            async for file_system in dl_service_client.list_file_systems():
                file_shares.append({
                    "name": file_system.name,
                    "lastModified": file_system.last_modified.isoformat() if file_system.last_modified else None,
                    "etag": file_system.etag,
                    "isDeleted": file_system.deleted,
                    "deletedTime": file_system.deleted_time.isoformat() if file_system.deleted_time else None,
                    "versionId": file_system.version_id,
                    "isLatestVersion": file_system.is_current_version,
                    "metadata": file_system.metadata,
                })
            logger.debug(f"Got {len(file_shares)} File Share records for account '{storage_account_name}'.")
            return file_shares
        except Exception as e:
            logger.error(f"An error occurred while getting File Share for storage account '{storage_account_name}' (RG: '{resource_group_name}'): {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Storage File Data Reader' or 'Reader' role on the storage account."
            )
            return None
        finally:
            if dl_service_client:
                await dl_service_client.close()

    @tool
    async def get_files_in_share(self, storage_account_name: str, resource_group_name: str, share_name: str) -> list[dict] | None:
        """
        Gets for all accessible Files within a specific file share.
        Includes details like size, creation time, and last modified time.
        Requires 'Storage File Data Reader' role on the file share or storage account.

        Args:
            storage_account_name (str): The name of the storage account.
            resource_group_name (str): The resource group of the storage account.
            share_name (str): The name of the file share.

        Returns:
            list: A list of dictionaries, where each dictionary contains file details.
        """
        logger.debug(f"Getting for Files in share '{share_name}' (Account: '{storage_account_name}')...")
        files_in_share = []
        filesystem_client = None
        try:
            filesystem_client = await self._get_filesystem_client(storage_account_name, resource_group_name, share_name)
            if not filesystem_client:
                return None

            async for path in filesystem_client.get_paths():
                if not path.is_directory:
                    files_in_share.append({
                        "name": path.name,
                        "size": path.content_length,
                        "creationTime": path.creation_time.isoformat() if path.creation_time else None,
                        "lastModified": path.last_modified.isoformat() if path.last_modified else None,
                        "etag": path.etag,
                    })
            logger.debug(f"Got {len(files_in_share)} File records for share '{share_name}'.")
            return files_in_share
        except Exception as e:
            logger.error(f"An error occurred while getting Files for share '{share_name}' in account '{storage_account_name}': {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Storage File Data Reader' role on the file share or storage account."
            )
            return None
        finally:
            if filesystem_client:
                await filesystem_client.close()

    @tool
    async def get_all_azure_storage(self) -> dict:
        """
        Gets all available GRC for Azure Storage Accounts and their related resources within the subscription.
        This includes storage account properties, blob containers, blobs, file shares, and files within shares.

        Returns:
            dict: A dictionary containing all collected Azure Storage for GRC purposes.
        """
        logger.debug("Starting to get all Azure Storage...")
        all_data = {
            "storageAccounts": [],
            "blobContainers": {},
            "blobs": {},
            "fileShares": {},
            "filesInShares": {},
            "encryptionStatus": [],
            "accessKeysStatus": [],
            "networkRules": [],
        }

        # Step 1: Get all storage accounts and then their child resources
        storage_accounts_list = await self.get_storage_accounts()
        all_data["storageAccounts"] = storage_accounts_list

        for account in storage_accounts_list:
            account_name = account["name"]
            resource_group = account["resourceGroup"]

            # Get blob containers and blobs
            all_data["blobContainers"][account_name] = await self.get_blob_containers(
                storage_account_name=account_name,
                resource_group_name=resource_group
            )
            all_data["blobs"][account_name] = {}
            for container in all_data["blobContainers"][account_name]:
                container_name = container["name"]
                all_data["blobs"][account_name][container_name] = await self.get_blobs(
                    storage_account_name=account_name,
                    resource_group_name=resource_group,
                    container_name=container_name
                )

            # Get file shares and files within them
            all_data["fileShares"][account_name] = await self.get_file_shares(
                storage_account_name=account_name,
                resource_group_name=resource_group
            )
            all_data["filesInShares"][account_name] = {}
            for share in all_data["fileShares"][account_name]:
                share_name = share["name"]
                all_data["filesInShares"][account_name][share_name] = await self.get_files_in_share(
                    storage_account_name=account_name,
                    resource_group_name=resource_group,
                    share_name=share_name
                )

        # Step 2: Get other account-level 
        all_data["encryptionStatus"] = await self.get_storage_account_encryption_status()
        all_data["accessKeysStatus"] = await self.get_storage_account_access_keys_status()
        all_data["networkRules"] = await self.get_storage_account_network_rules()

        logger.debug(
            "\nFinished getting all Azure Storage.")
        return all_data

    @tool
    async def get_storage_account_encryption_status(self) -> list[dict]:
        """
        Gets encryption status and scope details for all accessible storage accounts.
        Requires 'Microsoft.Storage/storageAccounts/read' (e.g., 'Reader' role) Azure RBAC permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains encryption details for a storage account.
        """
        logger.debug("Getting encryption status for Azure Storage Accounts...")
        encryption_status_list = []
        try:
            async for account in self.storage_mgmt_client.storage_accounts.list():
                resource_group_name = await self._get_resource_group_from_account_id(account.id)
                account_details = await self.storage_mgmt_client.storage_accounts.get_properties(
                    resource_group_name=resource_group_name,
                    account_name=account.name
                )
                encryption = account_details.encryption
                encryption_status_list.append({
                    "id": account_details.id,
                    "name": account_details.name,
                    "resourceGroup": resource_group_name,
                    "keySource": str(encryption.key_source) if encryption else None,
                    "services": {s.key: {"enabled": s.enabled, "lastEnabledTime": s.last_enabled_time.isoformat() if s.last_enabled_time else None} for s in encryption.services.as_dict().values()} if encryption and encryption.services else None,
                    "keyVaultProperties": {
                        "keyName": encryption.key_vault_properties.key_name,
                        "keyVaultUri": encryption.key_vault_properties.key_vault_uri,
                        "keyVersion": encryption.key_vault_properties.key_version,
                        "lastRotationTime": encryption.key_vault_properties.last_rotation_time.isoformat() if encryption.key_vault_properties.last_rotation_time else None,
                    } if encryption and encryption.key_vault_properties else None,
                    "requireInfrastructureEncryption": encryption.require_infrastructure_encryption if hasattr(encryption, 'require_infrastructure_encryption') else None
                })
            logger.debug(f"Got {len(encryption_status_list)} encryption status records.")
        except Exception as e:
            logger.error(
                f"An error occurred while getting encryption status for Storage Accounts: {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Storage/storageAccounts/read' RBAC permission for the subscription.")
        return encryption_status_list

    @tool
    async def get_storage_account_access_keys_status(self) -> list[dict]:
        """
        Gets the status related to storage account access keys, including last rotation time if available.
        Note: This operation DOES NOT expose the actual keys. It only checks for existence or properties.
        Requires 'Microsoft.Storage/storageAccounts/listkeys/action' RBAC permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains access key status for a storage account.
        """
        logger.debug("Getting access key status for Azure Storage Accounts...")
        access_keys_status_list = []
        try:
            async for account in self.storage_mgmt_client.storage_accounts.list():
                resource_group_name = await self._get_resource_group_from_account_id(account.id)
                # list_keys requires resource_group_name and account_name
                keys = await self.storage_mgmt_client.storage_accounts.list_keys(
                    resource_group_name=resource_group_name,
                    account_name=account.name
                )
                access_keys_status_list.append({
                    "id": account.id,
                    "name": account.name,
                    "resourceGroup": resource_group_name,
                    "key1Exists": bool(keys.keys and keys.keys[0].value),
                    "key2Exists": bool(len(keys.keys) > 1 and keys.keys[1].value),
                    # The last rotation time is not directly exposed for individual keys via this API.
                    # It would typically be derived from auditing logs or custom tracking.
                    # This example provides placeholders for illustrative purposes.
                    "key1LastRotationTime": None, # Placeholder: Requires custom logic/monitoring
                    "key2LastRotationTime": None, # Placeholder: Requires custom logic/monitoring
                    "message": "Actual key values are not exposed. This status indicates key existence."
                })
            logger.debug(f"Got {len(access_keys_status_list)} access key status records.")
        except Exception as e:
            logger.error(
                f"An error occurred while getting access key status for Storage Accounts: {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Storage/storageAccounts/listkeys/action' RBAC permission for the subscription.")
        return access_keys_status_list

    @tool
    async def get_storage_account_network_rules(self) -> list[dict]:
        """
        Gets network rule set (firewall) configurations for all accessible Azure Storage Accounts.
        Requires 'Microsoft.Storage/storageAccounts/read' (e.g., 'Reader' role) Azure RBAC permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains network rule set details for a storage account.
        """
        logger.debug("Getting network rules for Azure Storage Accounts...")
        network_rules_list = []
        try:
            async for account in self.storage_mgmt_client.storage_accounts.list():
                resource_group_name = await self._get_resource_group_from_account_id(account.id)
                account_details = await self.storage_mgmt_client.storage_accounts.get_properties(
                    resource_group_name=resource_group_name,
                    account_name=account.name
                )
                network_rule_set = account_details.network_rule_set
                network_rules_list.append({
                    "id": account_details.id,
                    "name": account_details.name,
                    "resourceGroup": resource_group_name,
                    "defaultAction": str(network_rule_set.default_action) if network_rule_set else None,
                    "ipRules": [{"value": ip_rule.value, "action": str(ip_rule.action)} for ip_rule in network_rule_set.ip_rules] if network_rule_set and network_rule_set.ip_rules else [],
                    "virtualNetworkRules": [{"id": vnet_rule.id, "action": str(vnet_rule.action)} for vnet_rule in network_rule_set.virtual_network_rules] if network_rule_set and network_rule_set.virtual_network_rules else [],
                    "bypass": [str(b) for b in network_rule_set.bypass] if network_rule_set and network_rule_set.bypass else [],
                })
            logger.debug(f"Got {len(network_rules_list)} network rule set records.")
        except Exception as e:
            logger.error(
                f"An error occurred while getting network rules for Storage Accounts: {e}", exc_info=True)
            logger.error(
                "Ensure the Azure application has 'Microsoft.Storage/storageAccounts/read' RBAC permission for the subscription.")
        return network_rules_list
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Asynchronous exit to close clients."""
        if hasattr(self, 'storage_mgmt_client') and self.storage_mgmt_client:
            await self.storage_mgmt_client.close()
            logger.debug("Azure Storage Management Client closed.")
        if hasattr(self, 'credential') and self.credential:
            await self.credential.close()
            logger.debug("Azure Credential client closed.")
        # Data plane clients (BlobServiceClient etc.) are created per method and closed in finally blocks.
        super().__aexit__(exc_type, exc_val, exc_tb)
