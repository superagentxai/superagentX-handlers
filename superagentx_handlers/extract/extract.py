from abc import ABC
from urllib.request import BaseHandler
import logging
from superagentx.handler.decorators import tool
from PIL import Image
import pytesseract
import pdfplumber

logger = logging.getLogger(__name__)

class ExtractHandler(BaseHandler):
    """
        ExtractHandler is responsible for processing and extracting data
        from various sources such as PDFs, images, or other supported formats.

        This class inherits from BaseHandler and extends its functionality
        to include specific extraction-related operations.
    """


    @tool
    async def extract_pdf_text(self, file_path:str):
        """
            Extracts text content from the specified PDF file.

            This method processes the PDF file provided during the initialization
            of the handler and extracts its textual content asynchronously. The
            extracted text can be used for further analysis or processing.
        """
        try:
            with pdfplumber.open(file_path) as pdf:
                text = "".join(page.extract_text() for page in pdf.pages)
            return text
        except Exception as ex:
            logger.error(f"Error while extracting file: {file_path}! ERROR: {ex}")
            raise

    @tool
    async def extract_image_text(self, file_path:str):
        """
            Extracts text content from an image file.

            This method processes an image file provided during the initialization
            of the handler and extracts any text content from it asynchronously using
            OCR (Optical Character Recognition) techniques.
        """
        try:
            image = Image.open(file_path)
            text = pytesseract.image_to_string(image)
            return text

        except Exception as ex:
            logger.error(f"Error while extracting file: {file_path}! ERROR: {ex}")
            raise

