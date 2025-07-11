import os
import pytest
import logging
import pytest_asyncio

from superagentx_handlers import AzureStorageHandler

logger = logging.getLogger(__name__)
'''
 Run Pytest for Azure Stroage:
   1. pytest --log-cli-level=INFO tests/handlers/azure/test_azure_storage.py::TestAzureStorage::test_list_storage_accounts
'''

@pytest_asyncio.fixture
async def azure_vm_client_init() -> AzureStorageHandler: # type: ignore
    handler = AzureStorageHandler()
    return handler


class TestAzureStorage:

    async def test_list_storage_accounts(self, azure_vm_client_init: AzureStorageHandler):
        accounts = await azure_vm_client_init.list_storage_accounts()
        logger.info(accounts)
        # assert isinstance(vms, list)