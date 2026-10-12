



import logging
import pytest
import asyncio
from ci_pr_handler import CIPRHandler

logger = logging.getLogger(__name__)

'''
Run Pytest for CI PR Handler:

1. pytest --log-cli-level=INFO test_ci_pr_handler.py::TestCIPRHandler::test_handle_pr_dummy
2. pytest --log-cli-level=INFO test_ci_pr_handler.py::TestCIPRHandler::test_format_failure
'''

@pytest.fixture
def ci_pr_handler_init() -> CIPRHandler:
    handler = CIPRHandler()
    return handler

@pytest.mark.asyncio
class TestCIPRHandler:

    async def test_handle_pr_dummy(self, ci_pr_handler_init: CIPRHandler):
        await ci_pr_handler_init.handle_pr(
            repo_url = "https://github.com/YOUR_USERNAME/repo.git",  # Example public repo
            branch = "branch",
            pr_id = 1
        )
        logger.info(" PR handling test completed successfully")        #



    async def test_format_failure(self, ci_pr_handler_init: CIPRHandler):
        result = {
            "project_type": "python",
            "stderr": "Test failed due to some error"
        }
        message = await ci_pr_handler_init._format_failure(result)
        logger.info(f"Formatted message:\n{message}")  #

