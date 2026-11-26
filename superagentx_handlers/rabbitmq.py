import asyncio
import json
import logging
import os
from typing import Any, Optional

import aio_pika
from aio_pika import DeliveryMode, Message
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class RabbitMQHandler(BaseHandler):

    def __init__(
            self,
            host: Optional[str] = None,
            port: Optional[int] = None,
            username: Optional[str] = None,
            password: Optional[str] = None,
            virtual_host: Optional[str] = None,
            heartbeat: Optional[int] = None,
            **kwargs
    ):
        super().__init__(**kwargs)

        self.host = host or os.getenv("RABBITMQ_HOST", "localhost")
        self.port = port or int(os.getenv("RABBITMQ_PORT", "5672"))
        self.username = username or os.getenv("RABBITMQ_USERNAME", "guest")
        self.password = password or os.getenv("RABBITMQ_PASSWORD", "guest")
        self.virtual_host = (
            virtual_host
            if virtual_host is not None
            else os.getenv("RABBITMQ_VIRTUAL_HOST", "/")
        )
        self.heartbeat = (
            heartbeat
            if heartbeat is not None
            else int(os.getenv("RABBITMQ_HEARTBEAT", "60"))
        )

        self.connection = None
        self.channel = None
        self._connection_lock = asyncio.Lock()

    async def _get_channel(self):
        """
        Establishes a RabbitMQ connection and returns an active channel.
        Reuses the existing connection whenever possible.
        """

        async with self._connection_lock:
            try:
                if (
                        self.connection is None
                        or self.connection.is_closed
                ):
                    logger.info(
                        "Connecting to RabbitMQ at %s:%s",
                        self.host,
                        self.port
                    )

                    self.connection = await aio_pika.connect_robust(
                        host=self.host,
                        port=self.port,
                        login=self.username,
                        password=self.password,
                        virtualhost=self.virtual_host,
                        heartbeat=self.heartbeat
                    )

                    self.channel = None

                    logger.info("RabbitMQ connection established.")

                if (
                        self.channel is None
                        or self.channel.is_closed
                ):
                    self.channel = await self.connection.channel()

                    logger.info("RabbitMQ channel initialized.")

                return self.channel

            except Exception as e:
                logger.error(
                    "Error establishing RabbitMQ connection: %s",
                    e
                )
                raise

    @tool
    async def publish_message(
            self,
            queue_name: str,
            message: Any,
            **kwargs
    ):
        """
        Publishes a text or JSON message to the specified RabbitMQ queue.

        Args:
            queue_name (str): RabbitMQ queue name.
            message (Any): Plain-text or JSON-serializable message.

        Returns:
            dict: Publishing status and queue information.
        """

        try:
            previous_agent_result = kwargs.get("previous_agent_result")

            if previous_agent_result is not None:
                message = previous_agent_result

            if not queue_name or not queue_name.strip():
                raise ValueError("RabbitMQ queue name is required")

            if isinstance(message, str):
                message_body = message.encode("utf-8")
                content_type = "text/plain"

            else:
                message_body = json.dumps(
                    message,
                    ensure_ascii=False,
                    default=str
                ).encode("utf-8")
                content_type = "application/json"

            channel = await self._get_channel()

            queue = await channel.declare_queue(
                queue_name,
                durable=True
            )

            await channel.default_exchange.publish(
                Message(
                    body=message_body,
                    content_type=content_type,
                    delivery_mode=DeliveryMode.PERSISTENT
                ),
                routing_key=queue.name,
                mandatory=True
            )

            logger.info(
                "Message published successfully to queue: %s",
                queue_name
            )

            return {
                "status": "success",
                "queue_name": queue_name,
                "content_type": content_type,
                "message": "Message published successfully"
            }

        except Exception as e:
            logger.error(
                "Error publishing message to RabbitMQ queue %s: %s",
                queue_name,
                e
            )
            raise

    async def close(self):
        """
        Closes the RabbitMQ channel and connection.
        """

        try:
            async with self._connection_lock:

                if self.channel and not self.channel.is_closed:
                    await self.channel.close()
                    logger.info("RabbitMQ channel closed.")

                if self.connection and not self.connection.is_closed:
                    await self.connection.close()
                    logger.info("RabbitMQ connection closed.")

                self.channel = None
                self.connection = None

        except Exception as e:
            logger.error(
                "Error closing RabbitMQ connection: %s",
                e
            )
            raise
