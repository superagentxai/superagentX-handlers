import logging
import pytest
from superagentx_handlers import SalesforceERPHandler

logger = logging.getLogger(__name__)


'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/handlers/test_salesforce.py::TestSalesforceERPHandler::test_create_order
   2. pytest --log-cli-level=INFO tests/handlers/test_salesforce.py::TestSalesforceERPHandler::test_create_invoice

'''


@pytest.fixture
async def salesforce_handler_init():
    return SalesforceERPHandler()


class TestSalesforceERPHandler:

    async def test_create_order(self, salesforce_handler_init):

        res = await salesforce_handler_init.create_order(
            order_data={
                "AccountId": "9298t72hjwhg8w4",
                "EffectiveDate": "2026-04-09",
                "Status": "Draft",
                "Name": "purchase"
            }
        )

        logger.info(f"Result: {res}")
