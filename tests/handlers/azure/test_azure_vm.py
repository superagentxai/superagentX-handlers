import os
import pytest
import logging
import pytest_asyncio

from superagentx_handlers import AzureVMHandler

logger = logging.getLogger(__name__)
'''
 Run Pytest for Azure VM:
   1. pytest --log-cli-level=INFO tests/handlers/azure/test_azure_vm.py::TestAzureVM::test_get_vms
'''

@pytest_asyncio.fixture
async def azure_vm_client_init() -> AzureVMHandler: # type: ignore
    handler = AzureVMHandler()
    return handler


class TestAzureVM:

    async def test_get_vms(self, azure_vm_client_init: AzureVMHandler):
        vms = await azure_vm_client_init.get_vms()
        logger.info(vms)
        # assert isinstance(vms, list)