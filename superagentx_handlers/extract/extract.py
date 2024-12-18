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

    def __init__(
            self,
            *,
            file_path:str
    ):
        """
            Initializes the ExtractHandler with the specified file path.

            Args:
                file_path (str): The path to the file that will be processed
                    for extraction. This should be a valid file path to a
                    supported file format (e.g., PDF, image).
        """
        super().__init__()
        self.file_path = file_path

    @tool
    async def extract_pdf_text(self):
        """
            Extracts text content from the specified PDF file.

            This method processes the PDF file provided during the initialization
            of the handler and extracts its textual content asynchronously. The
            extracted text can be used for further analysis or processing.
        """
        try:
            with pdfplumber.open(self.file_path) as pdf:
                text = "".join(page.extract_text() for page in pdf.pages)
            return text
        except Exception as ex:
            logger.error(f"Error while extracting file: {self.file_path}! ERROR: {ex}")
            raise

    @tool
    async def extract_image_text(self):
        """
            Extracts text content from an image file.

            This method processes an image file provided during the initialization
            of the handler and extracts any text content from it asynchronously using
            OCR (Optical Character Recognition) techniques.
        """
        try:
            image = Image.open(self.file_path)
            text = pytesseract.image_to_string(image)
            return text

        except Exception as ex:
            logger.error(f"Error while extracting file: {self.file_path}! ERROR: {ex}")
            raise

