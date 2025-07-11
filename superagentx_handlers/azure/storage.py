import logging
import os
from typing import Any

from azure.identity.aio import ClientSecretCredential
from azure.mgmt.storage.aio import StorageManagementClient
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class AzureStorageClientInitFailed(Exception):
    """Exception raised when the Azure Storage client fails to initialize."""
    pass


class AzureStorageHandler(BaseHandler):
    """
    A handler class for managing interactions with Azure Storage Accounts (often referred to as buckets).
    This class provides methods for retrieving a list of all storage accounts within a subscription,
    along with their associated policy (network rules), encryption settings, and public access status.
    It also includes methods for listing files (blobs) within a specific container and retrieving
    the content of a specific file.
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
        """
        Initializes the AzureStorageHandler.

        Args:
            subscription_id (str | None): The Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID environment variable.
            tenant_id (str | None): The Azure tenant ID. Defaults to AZURE_TENANT_ID environment variable.
            client_id (str | None): The Azure client ID (application ID). Defaults to AZURE_CLIENT_ID environment variable.
            client_secret (str | None): The Azure client secret. Defaults to AZURE_CLIENT_SECRET environment variable.
            **kwargs (Any): Additional keyword arguments.

        Raises:
            AzureStorageClientInitFailed: If there's an error initializing the Azure Storage client.
        """
        super().__init__()
        # Retrieve credentials from arguments or environment variables
        self.subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        self.tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
        self.client_id = client_id or os.getenv("AZURE_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET")

        try:
            # Authenticate using client secret credentials
            self.credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            # Initialize the Azure Storage Management Client (for management plane operations)
            self.storage_client = StorageManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
        except Exception as e:
            logger.error(f"Error initializing Azure Storage client: {e}", exc_info=True)
            raise AzureStorageClientInitFailed(f"Failed to initialize Azure Storage Handler: {e}")

    @tool
    async def list_storage_accounts(self) -> list[dict]:
        """
        Asynchronously retrieves a list of all accessible Azure Storage Accounts (buckets)
        within the configured subscription. For each account, it extracts essential details
        including its ID, name, location, resource group, encryption settings, network policy
        (firewall rules), and a clear indicator of whether public blob access is allowed.

        This method requires the 'Microsoft.Storage/storageAccounts/read' Azure RBAC permission
        (e.g., 'Reader' role) for the subscription to function correctly.

        Returns:
            list[dict]: A list of dictionaries, where each dictionary represents a storage account
                        with its details.

        Raises:
            AzureStorageListFailed: If there's an error while listing the storage accounts.
        """
        storage_accounts_info = []
        try:
            # Asynchronously iterate through all storage accounts in the subscription
            async for account in self.storage_client.storage_accounts.list():
                # Append the collected information for the current storage account
                storage_accounts_info.append(account.as_dict())
            logger.debug(f"Successfully retrieved {len(storage_accounts_info)} storage account records.")
            return storage_accounts_info
        except Exception as e:
            logger.error(f"Error listing Azure Storage Accounts: {e}", exc_info=True)
            return []
