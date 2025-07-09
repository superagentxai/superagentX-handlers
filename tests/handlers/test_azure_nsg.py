# test_azure_nsg.py
import os
import pytest
import pytest_asyncio

# Import your AzureNSGHandler and custom exceptions
from azure_nsg import AzureNSGHandler, AzureNSGClientInitFailed, AzureNSGListFailed

'''
 Run Pytest for Azure NSG:

   1. pytest --log-cli-level=INFO test_azure_nsg.py::TestAzureNSG::test_get_network_security_groups

 Remember to set your Azure environment variables for a TEST/DEVELOPMENT subscription/tenant (NOT production) before running:
 export AZURE_SUBSCRIPTION_ID="your_test_subscription_id"
 export AZURE_TENANT_ID="your_test_tenant_id"
 export AZURE_CLIENT_ID="your_test_client_id"
 export AZURE_CLIENT_SECRET="your_test_client_secret"
'''

@pytest_asyncio.fixture
async def azure_nsg_client_init() -> AzureNSGHandler: # type: ignore
    handler = AzureNSGHandler(
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    return handler


class TestAzureNSG:

    async def test_get_network_security_groups(self, azure_nsg_client_init: AzureNSGHandler):
        nsgs = await azure_nsg_client_init.get_network_security_groups()
        assert isinstance(nsgs, list)

