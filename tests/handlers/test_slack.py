import logging

import pytest

from superagentx_handlers.slack import SlackHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1.pytest --log-cli-level=INFO tests/handlers/test_slack.py::TestSlackHandler::test_send_slack_message
    2.pytest --log-cli-level=INFO tests/handlers/test_slack.py::TestSlackHandler::test_get_messages_from_channel
    3.pytest --log-cli-level=INFO tests/handlers/test_slack.py::TestSlackHandler::test_get_channel_id

'''


@pytest.fixture
def slack_handler_init() -> SlackHandler:
    slack_handler = SlackHandler()
    return slack_handler


class TestSlackHandler:

    async def test_send_slack_message(self, slack_handler_init: SlackHandler):
        res = await slack_handler_init.send_slack_message(
            text="Hello, Slack!",
            channel_id="<CHANNEL_ID>"
        )
        logger.info(f"Result: {res}")

    async def test_get_messages_from_channel(self, slack_handler_init: SlackHandler):
        res = await slack_handler_init.get_messages_from_channel(
            channel_id="<CHANNEL_ID>"
        )
        logger.info(f"Result: {res}")

    async def test_get_channel_id(self, slack_handler_init: SlackHandler):
        res = await slack_handler_init.get_channel_id(
            channel_name="testslack"
        )
        logger.info(f"Result: {res}")