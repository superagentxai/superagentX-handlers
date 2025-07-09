# test_azure_storage.py
import os
import pytest
import pytest_asyncio

# Import your AzureStorageHandler and custom exceptions
from azure_storage import AzureStorageHandler, AzureStorageClientInitFailed, \
    AzureStorageListBlobsFailed, AzureStorageGetBlobFailed, AzureStorageListFilesFailed, AzureStorageGetFileFailed, \
    AzureStorageGetEncryptionStatusFailed

'''
 Run Pytest for Azure Storage:

   1. pytest --log-cli-level=INFO test_azure_storage.py::TestAzureStorage::test_get_blob_containers
   2. pytest --log-cli-level=INFO test_azure_storage.py::TestAzureStorage::test_get_blobs
   3. pytest --log-cli-level=INFO test_azure_storage.py::TestAzureStorage::test_get_file_share_file_properties
   4. pytest --log-cli-level=INFO test_azure_storage.py::TestAzureStorage::test_get_storage_account_encryption_status

 Remember to set your Azure environment variables and the specific test resource names before running:
 export AZURE_SUBSCRIPTION_ID="your_test_subscription_id"
 export AZURE_TENANT_ID="your_test_tenant_id"
 export AZURE_CLIENT_ID="your_test_client_id"
 export AZURE_CLIENT_SECRET="your_test_client_secret"
 export TEST_STORAGE_ACCOUNT_NAME="yourteststorageaccount" # e.g., "grctestsa"
 export TEST_RESOURCE_GROUP_NAME="your-test-resource-group" # e.g., "my-grc-test-rg"
 export TEST_BLOB_CONTAINER_NAME="yourtestblobcontainer" # e.g., "grctestcontainer"
 export TEST_BLOB_NAME="yourtestblob.txt" # e.g., "sampleblob.txt"
 export TEST_FILE_SHARE_NAME="yourtestfileshare" # e.g., "grctestshare"
 export TEST_FILE_NAME="yourtestfile.txt" # e.g., "samplefile.txt"
'''

@pytest_asyncio.fixture
async def azure_storage_client_init() -> AzureStorageHandler: # type: ignore
    handler = AzureStorageHandler(
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET"),
        storage_account_name=os.getenv("TEST_STORAGE_ACCOUNT_NAME"),
        resource_group_name=os.getenv("TEST_RESOURCE_GROUP_NAME")
    )
    return handler


class TestAzureStorage:

    async def test_get_blob_containers(self, azure_storage_client_init: AzureStorageHandler):
        containers = await azure_storage_client_init.get_blob_containers()
        assert isinstance(containers, list)

    async def test_get_blobs(self, azure_storage_client_init: AzureStorageHandler):
        container_name = os.getenv("TEST_BLOB_CONTAINER_NAME")
        if not container_name: pytest.skip("TEST_BLOB_CONTAINER_NAME not set.")
        blobs = await azure_storage_client_init.get_blobs(container_name=container_name)
        assert isinstance(blobs, list)

    async def test_get_file_share_file_properties(self, azure_storage_client_init: AzureStorageHandler):
        share_name = os.getenv("TEST_FILE_SHARE_NAME")
        file_name = os.getenv("TEST_FILE_NAME")
        if not share_name or not file_name: pytest.skip("TEST_FILE_SHARE_NAME or TEST_FILE_NAME not set.")
        file_properties = await azure_storage_client_init.get_file_share_file_properties(
            share_name=share_name, file_path=file_name
        )
        assert isinstance(file_properties, dict)

    async def test_get_storage_account_encryption_status(self, azure_storage_client_init: AzureStorageHandler):
        encryption_status = await azure_storage_client_init.get_storage_account_encryption_status()
        assert isinstance(encryption_status, dict)

