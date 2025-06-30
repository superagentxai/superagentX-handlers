import logging

import pytest

from gitlab_details import GitlabHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO CustomHandlers/test_gitlab_handler.py::TestGitLabHandler::test_gitlab_handler

'''

@pytest.fixture
def gitlab_handler_init() -> GitlabHandler:
    gitlab_handler = GitlabHandler()
    return gitlab_handler

class TestGitLabHandler:

    @pytest.mark.asyncio
    async def test_gitlab_handler(self,gitlab_handler_init: GitlabHandler):
        result = await gitlab_handler_init.get_projects()
        logger.info(f"Response {result}")