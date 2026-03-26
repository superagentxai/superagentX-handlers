import asyncio
import json
import logging
import os
from typing import Optional

import aio_pika
from slack_sdk.errors import SlackApiError
from slack_sdk.web.async_client import AsyncWebClient
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class SlackHandler(BaseHandler):
    def __init__(
            self,
            bot_token: Optional[str] = None,
            channel_id: Optional[str] = None,
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
    async def send_slack_message(self, text: Optional[str] = None):
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
    async def get_messages_from_channel(self, limit: Optional[int]= None):
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
    async def get_channel_id(self, channel_name: Optional[str]= None):
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
            channel_name: Optional[str]= None,
            text: Optional[str]= None
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


    @tool
    async def consume_and_forward_to_slack(
            self,
            amqp_url: Optional[str]= None,
            queue_name: Optional[str]= None
    ):
        """
        Connects to RabbitMQ using given amqp_url,
        consumes messages from the specified queue,
        and forwards them to the configured Slack channel.
        """

        try:
            logger.info(f"Connecting to RabbitMQ → {amqp_url}")

            connection = await aio_pika.connect_robust(amqp_url)
            channel = await connection.channel()

            queue = await channel.declare_queue(queue_name, durable=True)

            logger.info(f"Listening to queue: {queue_name}")

            async with queue.iterator() as queue_iter:
                async for message in queue_iter:
                    async with message.process():
                        try:
                            body = message.body.decode()

                            # Try JSON formatting
                            try:
                                data = json.loads(body)
                                formatted_text = json.dumps(data, indent=2)
                            except json.JSONDecodeError:
                                formatted_text = body

                            slack_message = (
                                "🚨 *Alert Received:*\n"
                                f"```{formatted_text}```"
                            )

                            await self.send_slack_message(slack_message)

                            logger.info("Alert forwarded to Slack successfully.")

                        except Exception as e:
                            logger.error(f"Error processing message: {e}")

        except Exception as e:
            logger.error(f"RabbitMQ connection error: {e}")
            raise
