import logging

import pytest

from superagentx.llm import LLMClient
from superagentx_handlers.websitecrawler import AmazonWebHandler

logger = logging.getLogger(__name__)

'''
Run Pytest:

    1.pytest --log-cli-level=INFO tests/handlers/test_amazon_web_crawler.py::TestAWSCrawler::test_aws_handler

'''

@pytest.fixture
def aws_client_init() -> AmazonWebHandler:
    aws_crawler_handler = AmazonWebHandler()
    return aws_crawler_handler


class TestAWSCrawler:
    async def test_aws_handler(self, aws_client_init: AmazonWebHandler):
        query = "Television"
        res = await aws_client_init.search(query)
        logger.info(f'Result => {res}')
        assert isinstance(res, object)