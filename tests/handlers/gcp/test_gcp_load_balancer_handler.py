import logging
import pytest

from superagentx_handlers.gcp.loadbalancer import GCPLoadBalancerHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/gcp/test_gcp_load_balancer_handler.py::TestGCPLoadBalancerHandler::test_load_balancer_info

'''


@pytest.fixture
def load_balancer_handler_init() -> GCPLoadBalancerHandler:
    return GCPLoadBalancerHandler()


class TestGCPLoadBalancerHandler:

    async def test_load_balancer_info(self, load_balancer_handler_init: GCPLoadBalancerHandler):
        result = await load_balancer_handler_init.list_all_load_balancer_components()
        logger.info(f"Load Balancer Results: {result}")
        assert isinstance(result, dict)
