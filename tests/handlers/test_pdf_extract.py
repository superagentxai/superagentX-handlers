import pytest
import logging
from superagentx_handlers.extract.extract import ExtractHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:

   1. pytest --log-cli-level=INFO tests/handlers/test_pdf_extract.py::TestExtract::test_extract_pdf   
   1. pytest --log-cli-level=INFO tests/handlers/test_pdf_extract.py::TestExtract::test_extract_image  

'''


@pytest.fixture
async def extract_handler() -> ExtractHandler:
    return ExtractHandler(file_path="/home/jeya/Downloads/estimate_bill EB.pdf")


class TestExtract:

    async def test_extract_pdf(self, extract_handler: ExtractHandler):
        res = await extract_handler.extract_pdf_text()
        logger.info(f'Lat Lang => {res}')
        assert res

    async def test_extract_image(self, extract_handler: ExtractHandler):
        res = await extract_handler.extract_image_text()
        logger.info(f'Lat Lang => {res}')
        assert res
