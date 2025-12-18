import os
import pytest
import logging
import pytest_asyncio

from superagentx_handlers.azure.cloud_functions import AzureFunctionHandler

logger = logging.getLogger(__name__)
'''
 Run Pytest for Azure VM:
   1. pytest --log-cli-level=INFO tests/handlers/azure/test_azure_cloud_functions.py::TestAzureFunctionHandler::test_get_functions
'''


@pytest_asyncio.fixture
async def azure_functions_client_init() -> AzureFunctionHandler:  # type: ignore
    handler = AzureFunctionHandler()
    return handler


class TestAzureFunctionHandler:

    async def test_get_functions(self, azure_functions_client_init: AzureFunctionHandler):
        cloud_functions = await azure_functions_client_init.get_all_function_apps_in_subscription()
        logger.info(cloud_functions)
        assert isinstance(cloud_functions, list)
