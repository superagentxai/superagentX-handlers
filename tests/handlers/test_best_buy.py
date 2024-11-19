import logging
import pytest
from superagentx_handlers.best_buy import BestbuyHandler

logger = logging.getLogger(__name__)
'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/handlers/test_best_buy.py::TestBestBuy::test_get_best_buy_info

'''


@pytest.fixture
async def best_buy_handler() -> BestbuyHandler:
    return BestbuyHandler(api_key="dmx8sagAYsaH0ghrgAA7OhkR")


class TestBestBuy:

    async def test_get_best_buy_info(self, best_buy_handler: BestbuyHandler):
        res = await best_buy_handler.get_best_buy_info(keyword="search=iphone")
        logger.info(f'Lat Lang => {res}')
        assert res
