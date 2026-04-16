import json
import base64
import logging
import aiofiles
import os
from io import BytesIO
from pathlib import Path
from typing import Dict, Any, List, Optional

from pdf2image import convert_from_bytes
from PIL import Image

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.llm import LLMClient
from superagentx.llm.models import ChatCompletionParams, Message

logger = logging.getLogger(__name__)

# Supported file types
PDF_EXTENSIONS = {".pdf"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}


class ExtractHandler(BaseHandler):
    """
     Handler responsible for extracting structured data from PDF or image inputs
     using an LLM. Supports file-based and base64-encoded inputs.
     """

    def __init__(self, llm_config: Dict):
        """
            Initialize the ExtractHandler.

            Args:
                llm_config (Dict): Configuration dictionary used to initialize
                    the LLM client.
        """
        super().__init__()
        self.llm_client = LLMClient(llm_config=llm_config)

    async def _pdf_to_images(self, pdf_bytes: bytes) -> list:
        """
               Convert a PDF file (in bytes) into a list of PIL Image objects.

               Args:
                   pdf_bytes (bytes): Raw PDF file content.

               Returns:
                   list: List of PIL Image objects, one per page.
       """
        return convert_from_bytes(pdf_bytes)

    async def _load_images(self, file_path: str) -> tuple[list, str]:
        """
                Load images from a file path. Supports PDFs and image files.

                Args:
                    file_path (str): Path to the input file.

                Returns:
                    tuple:
                        - list: List of PIL Image objects.
                        - str: File type ("pdf" or "image").

                Raises:
                    ValueError: If the file extension is not supported.
        """
        path = Path(file_path)
        ext = path.suffix.lower()

        if ext in PDF_EXTENSIONS:
            async with aiofiles.open(file_path, "rb") as f:
                pdf_bytes = await f.read()
            images = await self._pdf_to_images(pdf_bytes)
            return images, "pdf"

        elif ext in IMAGE_EXTENSIONS:
            async with aiofiles.open(file_path, "rb") as f:
                img_bytes = await f.read()
            image = Image.open(BytesIO(img_bytes))
            return [image], "image"

        else:
            raise ValueError(
                f"Unsupported file type '{ext}'. "
                f"Supported: PDF {PDF_EXTENSIONS}, Image {IMAGE_EXTENSIONS}"
            )

    async def _load_images_from_base64(self, b64_data: str) -> tuple[list, str]:
        """
                Decode base64 input and load it as images.

                Automatically detects whether the input is a PDF or an image.

                Args:
                    b64_data (str): Base64-encoded file content.

                Returns:
                    tuple:
                        - list: List of PIL Image objects.
                        - str: File type ("pdf" or "image").
        """
        raw = base64.b64decode(b64_data)

        if raw[:4] == b"%PDF":
            images = await self._pdf_to_images(raw)
            return images, "pdf"

        image = Image.open(BytesIO(raw))
        return [image], "image"

    def _image_to_base64(self, image) -> str:
        """
                Convert a PIL Image object into a base64-encoded JPEG string.

                Ensures compatibility by converting images with alpha channels
                or palette modes into RGB.

                Args:
                    image (PIL.Image.Image): Input image.

                Returns:
                    str: Base64-encoded JPEG string.
        """

        buffer = BytesIO()
        if image.mode in ("RGBA", "P", "LA"):
            image = image.convert("RGB")
        image.save(buffer, format="JPEG")
        return base64.b64encode(buffer.getvalue()).decode()

    def _parse_json(self, text_output: str) -> Any:
        """
                Attempt to parse JSON output from the LLM response.

                Handles cases where JSON is wrapped in markdown code blocks
                or partially malformed.

                Args:
                    text_output (str): Raw text output from the LLM.

                Returns:
                    Any: Parsed JSON object if successful, otherwise a dictionary
                        containing the raw text under the key "raw_text".
        """
        try:
            return json.loads(text_output)
        except (json.JSONDecodeError, TypeError):
            if text_output:
                clean = (
                    text_output.strip()
                    .removeprefix("```json")
                    .removeprefix("```")
                    .removesuffix("```")
                    .strip()
                )
                try:
                    return json.loads(clean)
                except Exception:
                    return {"raw_text": text_output}
            return {"raw_text": text_output}

    @tool
    async def extract_data(
            self,
            prompt: str | None = None,
            file_path: str | None = None,
            base64_data: str | None = None,
    ) -> Dict[str, Any]:

        """
                Extract structured data from a PDF or image using an LLM.

                The input can be provided either as a file path or as base64-encoded data.
                The file is converted into images and sent to the LLM along with the prompt.

                Args:
                    prompt (str): Instruction or query describing what data to extract.
                    file_path (Optional[str]): Path to the input file.
                    base64_data (Optional[str]): Base64-encoded file content.

                Returns:
                    Dict[str, Any]: Result dictionary containing:
                        - success (bool): Whether extraction succeeded.
                        - error (str | None): Error message if failed.
                        - pages_processed (int): Number of images/pages processed.
                        - file_type (str | None): Type of input ("pdf" or "image").
                        - data (Any): Parsed JSON output or raw text.
        """
        try:

            if file_path:
                images, file_type = await self._load_images(file_path)

            elif base64_data:
                images, file_type = await self._load_images_from_base64(base64_data)

            else:
                return {
                    "success": False,
                    "error": "Either file_path or base64_data must be provided.",
                    "pages_processed": 0,
                    "file_type": None,
                    "data": None
                }

            content: List[Any] = [{"type": "text", "text": prompt}]

            for img in images:
                img_b64 = self._image_to_base64(img)
                content.append({
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/jpeg;base64,{img_b64}"
                    }
                })

            response = await self.llm_client.achat_completion(
                chat_completion_params=ChatCompletionParams(
                    messages=[Message(role="user", content=content)]
                )
            )

            text_output = response.choices[0].message.content

            return {
                "success": True,
                "pages_processed": len(images),
                "file_type": file_type,
                "data": self._parse_json(text_output)
            }

        except Exception as e:
            logger.exception("Extraction failed")
            return {
                "success": False,
                "error": str(e),
                "pages_processed": 0,
                "file_type": None,
                "data": None
            }
