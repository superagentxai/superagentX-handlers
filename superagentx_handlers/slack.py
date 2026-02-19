# import logging
# import os
#
# from slack_sdk.errors import SlackApiError
# from slack_sdk.web.async_client import AsyncWebClient
# from superagentx.handler.base import BaseHandler
# from superagentx.handler.decorators import tool
#
# logger = logging.getLogger(__name__)
#
#
# class SlackHandler(BaseHandler):
#     def __init__(
#             self,
#             bot_token: str | None = None
#     ):
#         super().__init__()
#         bot_token = bot_token or os.getenv("SLACK_BOT_TOKEN")
#
#         self.client = AsyncWebClient(token=bot_token)
#
#     @tool
#     async def send_slack_message(
#             self,
#             text: str,
#             channel_id: str
#     ):
#         """
#             Sends a message to a Slack channel.
#
#             Args:
#                 channel_id (str): The Slack channel ID (e.g., 'C1234567890') where the message should be sent.
#                 text (str): The plain text message to send.
#
#             Returns:
#                 dict: The JSON response from Slack API. Contains metadata such as 'ok', 'ts', 'channel', etc.
#         """
#         try:
#             response = await self.client.chat_postMessage(channel=channel_id, text=text)
#             logger.debug(f"Message sent: {response['ts']}")
#             return response
#         except SlackApiError as e:
#             logger.error(f"Error sending message: {e.response['error']}")
#
#     @tool
#     async def get_messages_from_channel(
#             self,
#             channel_id: str,
#             limit: int = 5
#     ):
#
#         """
#             Retrieves messages from a specified Slack channel.
#
#             Args:
#                 channel_id (str): The Slack channel ID (e.g., 'C1234567890') to fetch messages from.
#                 limit (int, optional): The maximum number of messages to retrieve. Defaults to 100.
#
#             Returns:
#                 list: A list of message objects retrieved from the channel.
#         """
#         try:
#             response = await self.client.conversations_history(channel=channel_id, limit=limit)
#             messages = response.get("messages", [])
#             if not messages:
#                 logger.info(f"No messages found in channel {channel_id}.")
#                 return
#
#             logger.debug(f"Messages from channel {channel_id}:")
#             for msg in messages:
#                 user = msg.get("user", "bot")
#                 text = msg.get("text", "")
#                 print(f"{user} said: {text}")
#             return messages
#         except SlackApiError as e:
#             logger.error(f"Error fetching messages from channel {channel_id}: {e.response['error']}")
#
#     @tool
#     async def get_channel_id(self, channel_name: str):
#         """
#            Retrieves the Slack channel ID for a given channel name.
#
#            Args:
#                channel_name (str): The name of the Slack channel (e.g., 'general').
#
#            Returns:
#                str: The corresponding Slack channel ID (e.g., 'C1234567890').
#         """
#
#         """Fetch channel ID using channel name."""
#         response = await self.client.conversations_list()
#         if response:
#             for channel in response.get("channels", []):
#                 if channel["name"] == channel_name:
#                     return channel.get("id")
import asyncio
import json
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
        bot_token: str | None = None,
        channel_id: str | None = None
    ):
        super().__init__()

        self.bot_token = bot_token or os.getenv("SLACK_BOT_TOKEN")
        self.channel_id = channel_id or os.getenv("SLACK_CHANNEL_ID")

        if not self.bot_token:
            raise ValueError("Slack bot token is required")

        if not self.channel_id:
            raise ValueError("Slack channel ID is required")

        self.client = AsyncWebClient(token=self.bot_token)

    @tool
    async def send_slack_message(self, text: str):
        """
        Sends a message to the configured Slack channel.

        Args:
            text (str): The plain text message to send.

        Returns:
            dict: Slack API response
        """
        try:
            response = await self.client.chat_postMessage(
                channel=self.channel_id,
                text=text
            )
            logger.debug(f"Message sent: {response['ts']}")
            return response.data  # ✅ THIS FIXES IT
        except SlackApiError as e:
            logger.error(f"Error sending message: {e.response['error']}")
            raise

    @tool
    async def get_messages_from_channel(self, limit: int = 5):
        """
        Retrieves messages from the configured Slack channel.

        Args:testing
            limit (int, optional): Number of messages to retrieve. Defaults to 5.

        Returns:
            list: List of message objects
        """
        try:
            response = await self.client.conversations_history(
                channel=self.channel_id,
                limit=limit
            )
            messages = response.get("messages", [])

            if not messages:
                logger.info(f"No messages found in channel {self.channel_id}.")
                return []

            logger.debug(f"Messages from channel {self.channel_id}:")
            for msg in messages:
                user = msg.get("user", "bot")
                text = msg.get("text", "")
                logger.debug(f"{user} said: {text}")

            return messages
        except SlackApiError as e:
            logger.error(
                f"Error fetching messages from channel {self.channel_id}: {e.response['error']}"
            )
            raise

    @tool
    async def get_channel_id(self, channel_name: str):
        """
        Retrieves the Slack channel ID for a given channel name.

        Args:
            channel_name (str): Slack channel name (e.g., 'general')

        Returns:
            str: Slack channel ID
        """
        try:
            response = await self.client.conversations_list()
            for channel in response.get("channels", []):
                if channel.get("name") == channel_name:
                    return channel.get("id")
        except SlackApiError as e:
            logger.error(f"Error fetching channel list: {e.response['error']}")
            raise

    @tool
    async def send_message_by_channel_name(
            self,
            channel_name: str,
            text: str
    ):
        """
        Sends a Slack message using a channel name instead of channel ID.

        Args:
            channel_name (str): Slack channel name (e.g. 'general')
            text (str): Message text

        Returns:
            dict: Slack API response (JSON-serializable)
        """
        try:
            channel_id = await self.get_channel_id(channel_name)

            if not channel_id:
                raise ValueError(f"Channel '{channel_name}' not found")

            response = await self.client.chat_postMessage(
                channel=channel_id,
                text=text
            )

            logger.debug(
                f"Message sent to #{channel_name} ({channel_id}): {response['ts']}"
            )

            return response.data

        except SlackApiError as e:
            logger.error(
                f"Slack API error while sending to #{channel_name}: "
                f"{e.response['error']}"
            )
            raise

if __name__ == "__main__":
    handler = SlackHandler()


    async def main():
        res = await handler.send_slack_message(text="hi")
        print(json.dumps(res, indent=2))


    asyncio.run(main())