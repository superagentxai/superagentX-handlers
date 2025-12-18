import os

import pytest
import logging

from superagentx_handlers.extract.ai import ExtractAIHandler

logger=logging.getLogger(__name__)

'''
    1. pytest --log-cli-level=INFO tests/handlers/extract/test_ai.py::TestExtractAI::test_extract_api

'''

@pytest.fixture
def extract_init() -> ExtractAIHandler:
    extract_handler = ExtractAIHandler(
        api_token= "" or os.getenv('API_TOKEN'),
        prompt_name="<PROMPT_NAME>",
        base_url = "<BASE_URL>",
    )
    return extract_handler

class TestExtractAI:

    async def test_extract_api(self, extract_init: ExtractAIHandler):
        data = await extract_init.get_file_base64_data("")
        result = await extract_init.extract_api(
            project_id="<PROJECT_ID>",
            file_data= data,
            file_path="<FILE_PATH>",
            poll_interval=7
        )
        logger.info(result)
