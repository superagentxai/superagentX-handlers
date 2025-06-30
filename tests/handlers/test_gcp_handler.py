import logging

import pytest

from gcp.gcp_iam import GCPIAMHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO CustomHandlers/test_gcp_handler.py::TestGCPIAMHandler::test_gcp_iam_handler

'''

@pytest.fixture
def gcp_iam_handler_init() -> GCPIAMHandler:
    gcp_handler = GCPIAMHandler()
    return gcp_handler

class TestGCPIAMHandler:

    @pytest.mark.asyncio
    async def test_gcp_iam_handler(self,gcp_iam_handler_init: GCPIAMHandler):
        result = await gcp_iam_handler_init.collect_project_iam_evidence()
        logger.info(f"Response {result}")