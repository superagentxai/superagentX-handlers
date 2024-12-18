import os

import pytest
import logging

from superagentx_handlers.extract_gpt_handler import GptHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:

   1. pytest -s --log-cli-level=INFO tests/handlers/test_gpt_handler.py::TestGpt::test_extract

'''


@pytest.fixture
def gpt_client_init() -> GptHandler:
    gpt = GptHandler(
        openai_api_key=os.getenv("OPENAI_API_KEY")
    )
    return gpt


class TestGpt:
    async def test_extract(self, gpt_client_init: GptHandler):
        res = await gpt_client_init.extract(
            prompt="""
            you are the auditor.
            Extract the KW Number from the given input.
                    """,
            file_path=os.getenv("EX_File_Path")
        )
        logger.info(res)
