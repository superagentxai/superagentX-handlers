import os
import httpx
from os import getenv
from typing import Any, Dict

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class WhatsappHandler(BaseHandler):
    """
        Asynchronous handler for sending messages via the WhatsApp Cloud API.

        This handler manages authentication and communication with the
        WhatsApp Cloud API, enabling agents or tools to send WhatsApp text
        messages programmatically.

        Supported Tool Methods:
            - send_whatsapp_message(to_number, message_text)
    """
    def __init__(
        self,
        whatsapp_api_url: str,
        phone_number_id: str,
        access_token: str
    ):
        """
            Initialize the WhatsappHandler with API configuration and credentials.

            Args:
                whatsapp_api_url (str): Base URL for the WhatsApp Cloud API.
                    Example: "https://graph.facebook.com/v18.0"
                phone_number_id (str): WhatsApp phone number ID used to send messages.
                access_token (str): WhatsApp Cloud API access token.

            Raises:
                ValueError: If any required configuration value is missing,
                    either from parameters or environment variables.
        """
        super().__init__()
        self.whatsapp_api = whatsapp_api_url or os.getenv("WHATSAPP_API_URL")
        self.phone_number_id = phone_number_id or os.getenv("WHATSAPP_PHONE_NUMBER_ID")
        self.access_token = access_token or getenv("WHATSAPP_ACCESS_TOKEN")

        if not all([self.whatsapp_api, self.phone_number_id, self.access_token]):
            raise ValueError("Missing required WhatsApp environment variables")

    @tool
    async def send_whatsapp_message(
            self,
            to_number: str,
            message_text: str,
    ) -> Dict[str, Any]:
        """
            Send a WhatsApp text message using the WhatsApp Cloud API.

            This method sends a plain text message to a specified WhatsApp
            phone number. It is exposed as a tool and can be invoked by
            agents or automated workflows.

            Args:
                to_number (str): Recipient phone number in international
                    format (E.164), without spaces or symbols.
                    Example: "919876543210"
                message_text (str): Text content of the WhatsApp message.

        """

        url = f"{self.whatsapp_api}/{self.phone_number_id}/messages"

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "messaging_product": "whatsapp",
            "to": to_number,
            "type": "text",
            "text": {
                "body": message_text
            }
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(url, headers=headers, json=payload)

        if response.status_code in (200, 201):
            print(" Message sent successfully")
            return response.json()

        raise RuntimeError(
            f" Failed to send message: {response.status_code} - {response.text}"
        )
