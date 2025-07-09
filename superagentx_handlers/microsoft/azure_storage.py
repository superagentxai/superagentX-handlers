# azure_storage.py
import asyncio
import os
import logging
from typing import Any

from superagentx.handler.decorators import tool
from superagentx.handler.base import BaseHandler 
from azure.identity.aio import ClientSecretCredential
from azure.mgmt.storage.aio import StorageManagementClient
from azure.storage.blob.aio import BlobServiceClient
from azure.storage.filedatalake.aio import FileSystemClient, DataLakeServiceClient

# Custom exceptions
class AzureStorageListBlobsFailed(Exception): pass
class AzureStorageGetBlobFailed(Exception): pass
class AzureStorageListFilesFailed(Exception): pass
class AzureStorageGetFileFailed(Exception): pass
class AzureStorageClientInitFailed(Exception): pass
class AzureStorageGetEncryptionStatusFailed(Exception): pass # New exception for encryption status


logger = logging.getLogger(__name__)


class AzureStorageHandler(BaseHandler):
    """
    A handler class for managing interactions with a specific Azure Storage Account.
    This class provides methods for getting information about blob containers, blobs,
    file shares, and files within that designated storage account and resource group,
    facilitating efficient data retrieval for auditing and compliance.
    """

    def __init__(
        self,
        *,
        subscription_id: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        storage_account_name: str | None = None,
        resource_group_name: str | None = None,
        **kwargs: Any
    ):

        super().__init__()
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.storage_account_name = storage_account_name
        self.resource_group_name = resource_group_name

        try:
            self.credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            self.storage_mgmt_client = StorageManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        except Exception as e:
            logger.error(f"Error initializing Azure Storage clients: {e}", exc_info=True)
            raise AzureStorageClientInitFailed(f"Failed to initialize Azure Storage Handler: {e}")

    async def _get_blob_service_client(self) -> BlobServiceClient | None:
        """Helper to get an authenticated BlobServiceClient for the handler's storage account."""
        try:
            keys = await self.storage_mgmt_client.storage_accounts.list_keys(
                resource_group_name=self.resource_group_name,
                account_name=self.storage_account_name
            )
            key = keys.keys[0].value
            return BlobServiceClient(account_url=f"https://{self.storage_account_name}.blob.core.windows.net", credential=key)
        except Exception as e:
            logger.error(f"Error getting BlobServiceClient for {self.storage_account_name}: {e}", exc_info=True)
            return None

    async def _get_file_service_client(self) -> DataLakeServiceClient | None:
        """Helper to get an authenticated DataLakeServiceClient for the handler's storage account (ADLS Gen2)."""
        try:
            keys = await self.storage_mgmt_client.storage_accounts.list_keys(
                resource_group_name=self.resource_group_name,
                account_name=self.storage_account_name
            )
            key = keys.keys[0].value
            return DataLakeServiceClient(account_url=f"https://{self.storage_account_name}.dfs.core.windows.net", credential=key)
        except Exception as e:
            logger.error(f"Error getting DataLakeServiceClient for {self.storage_account_name}: {e}", exc_info=True)
            return None

    async def _get_filesystem_client(self, share_name: str) -> FileSystemClient | None:
        """Helper to get an authenticated FileSystemClient for a specific file share."""
        try:
            dl_service_client = await self._get_file_service_client()
            if not dl_service_client: return None
            return dl_service_client.get_file_system_client(share_name)
        except Exception as e:
            logger.error(f"Error getting FileSystemClient for share '{share_name}': {e}", exc_info=True)
            return None

    @tool
    async def get_blob_containers(self) -> list[dict] | None:
        """
        Asynchronously retrieves a list of all blob containers within the configured Azure Storage account.
        This method provides an overview of the top-level storage units for blobs.
        Requires 'Storage Blob Data Reader' or 'Reader' role on the storage account.
        """
        containers = []
        blob_service_client = None
        try:
            blob_service_client = await self._get_blob_service_client()
            if not blob_service_client: return None
            async for container in blob_service_client.list_containers(include_metadata=True):
                containers.append({"name": container.name, "lastModified": container.last_modified.isoformat() if container.last_modified else None})
            return containers
        except Exception as e:
            logger.error(f"Error getting Blob Containers: {e}", exc_info=e)
            raise AzureStorageListBlobsFailed(f"Failed to list blob containers: {e}")
        finally:
            if blob_service_client: await blob_service_client.close()

    @tool
    async def get_blobs(self, container_name: str) -> list[dict] | None:
        """
        Asynchronously retrieves a list of all blobs within a specified container in the configured storage account.
        This method helps in managing and auditing the contents of a blob container.

        Parameter:
           container_name (str): The name of the blob container to list blobs from.
        """
        blobs = []
        blob_service_client = None
        try:
            blob_service_client = await self._get_blob_service_client()
            if not blob_service_client: return None
            container_client = blob_service_client.get_container_client(container_name)
            async for blob in container_client.list_blobs():
                blobs.append({"name": blob.name, "size": blob.size, "lastModified": blob.last_modified.isoformat() if blob.last_modified else None})
            return blobs
        except Exception as e:
            logger.error(f"Error getting Blobs in container '{container_name}': {e}", exc_info=e)
            raise AzureStorageListBlobsFailed(f"Failed to list blobs: {e}")
        finally:
            if blob_service_client: await blob_service_client.close()

    @tool
    async def get_file_share_file_properties(self, share_name: str, file_path: str) -> dict | None:
        """
        Asynchronously retrieves detailed properties of a specific file within an Azure file share.
        This method facilitates auditing and inspection of individual file attributes.

        Parameter:
           share_name (str): The name of the file share containing the file.
           file_path (str): The full path to the file within the share (e.g., 'directory/filename.txt').
        """
        file_properties = None
        fs_client = None
        try:
            fs_client = await self._get_filesystem_client(share_name)
            if not fs_client: return None
            file_client = fs_client.get_file_client(file_path)
            properties = await file_client.get_file_properties()
            file_properties = {
                "name": properties.name,
                "size": properties.content_length,
                "lastModified": properties.last_modified.isoformat() if properties.last_modified else None,
            }
            return file_properties
        except Exception as e:
            logger.error(f"Error getting properties for file '{file_path}' in share '{share_name}': {e}", exc_info=e)
            raise AzureStorageGetFileFailed(f"Failed to get file properties: {e}")
        finally:
            if fs_client: await fs_client.close()

    @tool
    async def get_storage_account_encryption_status(self) -> dict | None:
        """
        Asynchronously retrieves the encryption status and key management details for the configured Azure Storage account.
        This method provides crucial information for auditing data at rest encryption.
        Requires 'Microsoft.Storage/storageAccounts/read' (e.g., 'Reader' role) Azure RBAC permission.
        """
        try:
            account_details = await self.storage_mgmt_client.storage_accounts.get_properties(
                resource_group_name=self.resource_group_name,
                account_name=self.storage_account_name
            )
            encryption = account_details.encryption
            
            encryption_status = {
                "id": account_details.id,
                "name": account_details.name,
                "resourceGroup": self.resource_group_name,
                "keySource": str(encryption.key_source) if encryption else None,
                "services": {s.key: {"enabled": s.enabled, "lastEnabledTime": s.last_enabled_time.isoformat() if s.last_enabled_time else None} for s in encryption.services.as_dict().values()} if encryption and encryption.services else None,
                "keyVaultProperties": {
                    "keyName": encryption.key_vault_properties.key_name,
                    "keyVaultUri": encryption.key_vault_properties.key_vault_uri,
                    "keyVersion": encryption.key_vault_properties.key_version,
                    "lastRotationTime": encryption.key_vault_properties.last_rotation_time.isoformat() if encryption.key_vault_properties.last_rotation_time else None,
                } if encryption and encryption.key_vault_properties else None,
                "requireInfrastructureEncryption": encryption.require_infrastructure_encryption if hasattr(encryption, 'require_infrastructure_encryption') else None
            }
            logger.debug(f"Successfully got encryption status for storage account '{self.storage_account_name}'.")
            return encryption_status
        except Exception as e:
            logger.error(f"Error getting encryption status for storage account '{self.storage_account_name}': {e}", exc_info=e)
            raise AzureStorageGetEncryptionStatusFailed(f"Failed to get encryption status: {e}")

