import json
import litellm
import base64
import logging
from io import BytesIO
from typing import Dict, Any, List

from pdf2image import convert_from_bytes
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class ExtractHandler(BaseHandler):

    def __init__(self, config: Dict[str, Any]):
        """
        Config Example:
        {
            "model": "gpt-4o",
            "api_key": "OPENAI_KEY"
        }

        OR

        {
            "model": "gemini/gemini-2.0-flash",
            "api_key": "GEMINI_KEY"
        }

        OR

        {
            "model": "anthropic/claude-3-5-sonnet",
            "api_key": "CLAUDE_KEY"
        }
        """

        super().__init__()
        self.model = config.get("model")
        self.api_key = config.get("api_key")

        if self.api_key:
            litellm.api_key = self.api_key

    async def _pdf_to_images(self, pdf_bytes: bytes):

        return convert_from_bytes(pdf_bytes)

    def _image_to_base64(self, image):

        buffer = BytesIO()
        image.save(buffer, format="JPEG")

        return base64.b64encode(buffer.getvalue()).decode()

    @tool
    async def extract_data(
            self,
            prompt: str,
            pdf_path: str | None = None,
            base64_pdf: str | None = None
    ) -> Dict[str, Any]:
        """
        Extract information from a PDF using the configured LLM model.

        The PDF can be provided either as a file path or as a base64 encoded string.
        The document is converted into images and sent to the model along with the
        prompt for extraction.

        Args:
            prompt: Instruction describing what data to extract.
            pdf_path: Path to the PDF file (optional).
            base64_pdf: Base64 encoded PDF content (optional).

        Returns:
            A dictionary containing:
                - success: Whether extraction was successful.
                - pages_processed: Number of pages processed.
                - data: Extracted JSON data (or raw text if parsing fails).
                - error: Error message if extraction failed.
        """

        try:

            pdf_bytes = None

            if pdf_path:
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()

            elif base64_pdf:
                pdf_bytes = base64.b64decode(base64_pdf)

            else:
                return {
                    "success": False,
                    "error": "Either pdf_path or base64_pdf must be provided",
                    "pages_processed": 0,
                    "data": None
                }

            images = await self._pdf_to_images(pdf_bytes)

            content: List[Dict] = [{"type": "text", "text": prompt}]

            for img in images:
                img_b64 = self._image_to_base64(img)

                content.append(
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{img_b64}"
                        }
                    }
                )

            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": content
                    }
                ]
            )

            text_output = response["choices"][0]["message"]["content"]

            try:
                json_output = json.loads(text_output)
            except Exception:
                json_output = {"raw_text": text_output}

            return {
                "success": True,
                "pages_processed": len(images),
                "data": json_output
            }

        except Exception as e:

            logger.exception("Extraction failed")

            return {
                "success": False,
                "error": str(e),
                "pages_processed": 0,
                "data": None
            }
