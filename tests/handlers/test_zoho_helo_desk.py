import os
import logging
import pytest

from superagentx_handlers.zoho_help_desk import ZohoHelpDeskHandler

logger = logging.getLogger(__name__)

"""
Run:
pytest --log-cli-level=INFO tests/handlers/test_zoho_helpdesk.py
"""


@pytest.fixture
def zoho_handler():
    """Initialize Zoho Help Desk handler with environment variables."""
    org_id = os.getenv("ZOHO_ORG_ID")
    token = os.getenv("ZOHO_ACCESS_TOKEN")
    base_url = os.getenv("ZOHO_DESK_BASE_URL", "https://desk.zoho.com/api/v1")

    handler = ZohoHelpDeskHandler(
        org_id=org_id,
        auth_token=token,
        base_url=base_url
    )

    return handler


@pytest.mark.asyncio
class TestZohoHelpDesk:

    async def test_get_ticket(self, zoho_handler: ZohoHelpDeskHandler):
        """Get an existing ticket."""
        sample_ticket_id = os.getenv("ZOHO_TEST_TICKET_ID")

        result = zoho_handler.get_ticket(sample_ticket_id)
        logger.info(f"Ticket Result: {result}")

        assert isinstance(result, dict)
        assert "id" in result
        assert result["id"] == sample_ticket_id
