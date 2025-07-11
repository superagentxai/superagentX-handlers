import logging
import pytest

from superagentx_handlers.gcp.firewall import GCPFirewallHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/gcp/test_gcp_firewall_handler.py::TestGCPFirewallHandler::test_get_gcp_firewall_info

'''


@pytest.fixture
def gcp_firewall_handler_init() -> GCPFirewallHandler:
    return GCPFirewallHandler()


class TestGCPFirewallHandler:

    async def test_get_gcp_firewall_info(self, gcp_firewall_handler_init: GCPFirewallHandler):
        result = await gcp_firewall_handler_init.get_firewall_details()
        logger.info(f"GCP Firewall Results: {result}")
        assert isinstance(result, list)
