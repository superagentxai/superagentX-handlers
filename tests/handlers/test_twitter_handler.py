import pytest
import logging

from superagentx_handlers.twitter import TwitterHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:

   1. pytest -s --log-cli-level=INFO tests/handlers/test_twitter_handler.py::TestTwitter::test_post_tweet

'''


@pytest.fixture
def twitter_client_init() -> TwitterHandler:
    twitter = TwitterHandler()
    return twitter


class TestTwitter:
    async def test_post_tweet(self, twitter_client_init: TwitterHandler):
        res = await twitter_client_init.post_tweet(
            text=""
        )
        logger.info(res)
