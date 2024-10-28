import logging
import os

import pytest

from superagentx_handlers.crm.hubspot_crm import HubSpotHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_create_contact
   2. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_get_contacts
   3. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_create_company
   4. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_get_companies
   5. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_get_deals
   6. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_get_tickets
   7. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_get_ticket_status
   8. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_create_ticket
   9. pytest --log-cli-level=INFO tests/handlers/test_hub_spot_handler.py::TestHubSpot::test_search_ticket

'''


@pytest.fixture
def hs_client_init() -> HubSpotHandler:
    hs_handler = HubSpotHandler(
        token=os.getenv("HUBSPOT_TOKEN")
    )
    return hs_handler


class TestHubSpot:

    async def test_create_contact(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.create_contact(
            email='',
            first_name="",
            last_name=""
        )
        logger.info(f"Contact Info: {res}")
        assert isinstance(res, list)
        assert len(res) > 0

    async def test_get_contacts(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.get_all_contact()
        logger.info(f"Contact Info: {res}")
        assert isinstance(res, list)
        assert len(res) > 0

    async def test_create_company(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.create_company(
            name='',
            domain=""
        )
        logger.info(f"Company Info: {res}")
        assert isinstance(res, list)
        assert len(res) > 0

    async def test_get_companies(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.get_all_company()
        logger.info(f"Company Info: {res}")
        assert isinstance(res, list)
        assert len(res) > 0

    async def test_get_deals(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.get_all_deals()
        logger.info(f"Deals Info: {res}")
        assert isinstance(res, list)
        assert len(res) > 0

    async def test_get_tickets(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.get_all_tickets()
        logger.info(f"Tickets Info: {res}")
        assert isinstance(res, list)
        assert len(res) > 0

    async def test_get_ticket_status(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.get_ticket_status(
            ticket_id="112344"
        )
        logger.info(f"Tickets Info: {res}")
        assert isinstance(res, dict)

    async def test_create_ticket(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.create_ticket(
            subject="",
            content=""
        )
        logger.info(f"Tickets Created Successfully {res}")
        assert isinstance(res, dict)

    async def test_search_ticket(
            self,
            hs_client_init: HubSpotHandler
    ):
        res = await hs_client_init.get_ticket_status(
            policy_number=""
        )
        logger.info(f"Tickets Info {res}")
        assert isinstance(res, dict)

