import logging

import pytest

from superagentx_handlers.scrape import ScrapeHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

    1.pytest --log-cli-level=INFO tests/handlers/test_scrape_handler.py::TestScrap::test_scrap_content    

'''


@pytest.fixture
def scrap_content_init() -> ScrapeHandler:
    scrap_handler = ScrapeHandler()
    return scrap_handler


class TestScrap:

    async def test_scrap_content(self, scrap_content_init: ScrapeHandler):
        res = await scrap_content_init.scrap_content(
            domain_urls=[]
        )
        logger.info(f'Scrap Content Results =>\n{res}')
        assert isinstance(res, list)
