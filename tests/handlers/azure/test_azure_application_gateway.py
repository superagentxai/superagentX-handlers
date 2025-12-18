import os
import pytest
import logging
import pytest_asyncio

from superagentx_handlers import AzureApplicationGatewayHandler

logger = logging.getLogger(__name__)
'''
 Run Pytest for Azure LoadBalancer:
   1. pytest --log-cli-level=INFO tests/handlers/azure/test_azure_application_gateway.py::TestAzureApplicationGatewayHandler::test_get_load_balancers
'''


@pytest_asyncio.fixture
async def azure_api_gateway_client_init() -> AzureApplicationGatewayHandler:  # type: ignore
    handler = AzureApplicationGatewayHandler()
    return handler


class TestAzureApplicationGatewayHandler:

    async def test_get_load_balancers(self, azure_api_gateway_client_init: AzureApplicationGatewayHandler):
        api_gateways = await azure_api_gateway_client_init.collect_all_application_gateway_data()
        logger.info(api_gateways)
        assert isinstance(api_gateways, dict)
