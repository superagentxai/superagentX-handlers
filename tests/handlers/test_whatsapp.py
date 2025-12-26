import logging

import pytest

from superagentx_handlers.whatsapp import WhatsappHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

    1.pytest --log-cli-level=INFO tests/handlers/test_whatsapp.py::TestWhatsappHandler::test_send_message    

'''

@pytest.fixture
def whatsapp_init() -> WhatsappHandler:
    handler = WhatsappHandler(
        whatsapp_api_url = "https://graph.facebook.com/v22.0",
        phone_number_id = "<PHONE_NUMBER_ID>",
        access_token = "<ACCESS_TOKEN>"
    )
    return handler


class TestWhatsappHandler:

    async def test_send_message(self, whatsapp_init: WhatsappHandler):
        res = await whatsapp_init.send_whatsapp_message(
            to_number = "917648762349",
            message_text = "Hello."
        )
        logger.info(f'whatsapp Content Results =>\n{res}')