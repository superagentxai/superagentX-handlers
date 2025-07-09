# test_azure_vm.py
import os
import pytest
import pytest_asyncio

# Import your AzureVMHandler and custom exceptions
from azure_vm import AzureVMHandler, AzureVMClientInitFailed, AzureVMListFailed

'''
 Run Pytest for Azure VM:

   1. pytest --log-cli-level=INFO test_azure_vm.py::TestAzureVM::test_get_vms

 Remember to set your Azure environment variables for a TEST/DEVELOPMENT subscription/tenant (NOT production) before running:
 export AZURE_SUBSCRIPTION_ID="your_test_subscription_id"
 export AZURE_TENANT_ID="your_test_tenant_id"
 export AZURE_CLIENT_ID="your_test_client_id"
 export AZURE_CLIENT_SECRET="your_test_client_secret"
'''

@pytest_asyncio.fixture
async def azure_vm_client_init() -> AzureVMHandler: # type: ignore
    handler = AzureVMHandler(
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    return handler


class TestAzureVM:

    async def test_get_vms(self, azure_vm_client_init: AzureVMHandler):
        vms = await azure_vm_client_init.get_vms()
        assert isinstance(vms, list)

