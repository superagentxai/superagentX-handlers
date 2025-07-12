import os
import pytest
import logging
import pytest_asyncio

from superagentx_handlers.azure.loadbalancer import AzureLoadBalancerHandler

logger = logging.getLogger(__name__)
'''
 Run Pytest for Azure LoadBalancer:
   1. pytest --log-cli-level=INFO tests/handlers/azure/test_azure_lb.py::TestAzureLoadBalancer::test_get_load_balancers
'''


@pytest_asyncio.fixture
async def azure_lb_client_init() -> AzureLoadBalancerHandler:  # type: ignore
    handler = AzureLoadBalancerHandler()
    return handler


class TestAzureLoadBalancer:

    async def test_get_load_balancers(self, azure_lb_client_init: AzureLoadBalancerHandler):
        load_balancers = await azure_lb_client_init.get_all_load_balancers_in_subscription()
        logger.info(load_balancers)
        assert isinstance(load_balancers, list)
