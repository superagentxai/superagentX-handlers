# test_azure_nsg.py
import pytest_asyncio
import logging

logger = logging.getLogger(__name__)

from superagentx_handlers import AzureNSGHandler
'''
 Run Pytest for Azure NSG:
   1. pytest --log-cli-level=INFO tests/handlers/azure/test_azure_nsg.py::TestAzureNSG::test_get_network_security_groups
'''

@pytest_asyncio.fixture
async def azure_nsg_client_init() -> AzureNSGHandler: # type: ignore
    handler = AzureNSGHandler()
    return handler


class TestAzureNSG:

    async def test_get_network_security_groups(self, azure_nsg_client_init: AzureNSGHandler):
        nsgs = await azure_nsg_client_init.get_network_security_groups()
        logger.info(nsgs)
        # assert isinstance(nsgs, list)