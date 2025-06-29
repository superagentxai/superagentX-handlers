import logging

import pytest

from gcphandler import GcpIAMHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO CustomHandlers/test_gcp_handler.py::TestGCPIAMHandler::test_gcp_iam_handler

'''

@pytest.fixture
def gcp_iam_handler_init() -> GcpIAMHandler:
    gcp_handler = GcpIAMHandler()
    return gcp_handler

class TestGCPIAMHandler:

    @pytest.mark.asyncio
    async def test_gcp_iam_handler(self,gcp_iam_handler_init: GcpIAMHandler):
        result = await gcp_iam_handler_init.collect_project_iam_evidence()
        logger.info(f"Response {result}")