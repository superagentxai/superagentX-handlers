import logging
import os

from slack_sdk.errors import SlackApiError
from slack_sdk.web.async_client import AsyncWebClient
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class SlackHandler(BaseHandler):
    def __init__(
            self,
            bot_token: str | None = None
    ):
        super().__init__()
        bot_token = bot_token or os.getenv("SLACK_BOT_TOKEN")

        self.client = AsyncWebClient(token=bot_token)

    @tool
    async def send_slack_message(
            self,
            text: str,
            channel_id: str
    ):
        """
            Sends a message to a Slack channel.

            Args:
                channel_id (str): The Slack channel ID (e.g., 'C1234567890') where the message should be sent.
                text (str): The plain text message to send.

            Returns:
                dict: The JSON response from Slack API. Contains metadata such as 'ok', 'ts', 'channel', etc.
        """
        try:
            response = await self.client.chat_postMessage(channel=channel_id, text=text)
            logger.debug(f"Message sent: {response['ts']}")
            return response
        except SlackApiError as e:
            logger.error(f"Error sending message: {e.response['error']}")

    @tool
    async def get_messages_from_channel(self, channel_id: str, limit: int = 5):

        """
            Retrieves messages from a specified Slack channel.

            Args:
                channel_id (str): The Slack channel ID (e.g., 'C1234567890') to fetch messages from.
                limit (int, optional): The maximum number of messages to retrieve. Defaults to 100.

            Returns:
                list: A list of message objects retrieved from the channel.
        """
        try:
            response = await self.client.conversations_history(channel=channel_id, limit=limit)
            messages = response.get("messages", [])
            if not messages:
                logger.info(f"No messages found in channel {channel_id}.")
                return

            logger.debug(f"Messages from channel {channel_id}:")
            for msg in messages:
                user = msg.get("user", "bot")
                text = msg.get("text", "")
                print(f"{user} said: {text}")
            return messages
        except SlackApiError as e:
            logger.error(f"Error fetching messages from channel {channel_id}: {e.response['error']}")

    @tool
    async def get_channel_id(self, channel_name: str):
        """
           Retrieves the Slack channel ID for a given channel name.

           Args:
               channel_name (str): The name of the Slack channel (e.g., 'general').

           Returns:
               str: The corresponding Slack channel ID (e.g., 'C1234567890').
        """

        """Fetch channel ID using channel name."""
        response = await self.client.conversations_list()
        if response:
            for channel in response.get("channels", []):
                if channel["name"] == channel_name:
                    return channel.get("id")
