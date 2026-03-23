import asyncio
import json
import base64
import logging

import aiofiles
from io import BytesIO
from typing import Dict, Any, List, Optional

from pdf2image import convert_from_bytes

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.llm import LLMClient
from superagentx.llm.models import ChatCompletionParams, Message

logger = logging.getLogger(__name__)


class ExtractHandler(BaseHandler):

    def __init__(
            self,
            model: str,
            api_key: str,
            base_url: Optional[str] = None,
            llm_type: Optional[str] = None,
            api_version: Optional[str] = None
    ):
        super().__init__()

        self.llm_client = LLMClient(
            llm_config={
                "model": model,
                "llm_type": llm_type,
                "api_key": api_key,
                "base_url": base_url,
                "api_version": api_version,
            }
        )

    async def _pdf_to_images(self, pdf_bytes: bytes):
        return convert_from_bytes(pdf_bytes)

    def _image_to_base64(self, image) -> str:
        buffer = BytesIO()
        image.save(buffer, format="JPEG")
        return base64.b64encode(buffer.getvalue()).decode()

    def _parse_json(self, text_output: str) -> Any:
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
            prompt: str,
            pdf_path: Optional[str] = None,
            base64_pdf: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extract information from a PDF using the configured LLM via SuperAgentX LLMClient.
        """
        try:
            pdf_bytes = None

            if pdf_path:
                async with aiofiles.open(pdf_path, "rb") as f:
                    pdf_bytes = await f.read()
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

            content: List[Any] = [{"type": "text", "text": prompt}]
            for img in images:
                img_b64 = self._image_to_base64(img)
                content.append({
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{img_b64}"}
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
                "data": self._parse_json(text_output)
            }

        except Exception as e:
            logger.exception("Extraction failed")
            return {
                "success": False,
                "error": str(e),
                "pages_processed": 0,
                "data": None
            }
