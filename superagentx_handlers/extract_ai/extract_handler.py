import json
import base64
import logging
import aiofiles
import os
import asyncio
import re
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

PDF_EXTENSIONS = {".pdf"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}

MAX_PAGES = 10
MAX_BASE64_SIZE = 10 * 1024 * 1024  # 10MB
SAFE_DELETE_DIR = "/tmp"


def _parse_json(text_output: str) -> Any:
    try:
        return json.loads(text_output)
    except Exception:
        match = re.search(r"```json\s*(.*?)\s*```", text_output or "", re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass
        return {"raw_text": text_output}


class ExtractHandler(BaseHandler):

    def __init__(self, llm_config: Dict):
        super().__init__()
        self.llm_client = LLMClient(llm_config=llm_config)

    async def _pdf_to_images(self, pdf_bytes: bytes) -> list:
        return await asyncio.to_thread(convert_from_bytes, pdf_bytes)

    async def _load_images(self, file_path: str) -> tuple[list, str]:
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
            image = await asyncio.to_thread(Image.open, BytesIO(img_bytes))
            return [image], "image"

        else:
            raise ValueError(f"Unsupported file type '{ext}'")

    async def _load_images_from_base64(self, b64_data: str) -> tuple[list, str]:
        if len(b64_data) > MAX_BASE64_SIZE:
            raise ValueError("Base64 input too large")

        raw = base64.b64decode(b64_data)

        if raw[:4] == b"%PDF":
            images = await self._pdf_to_images(raw)
            return images, "pdf"

        image = await asyncio.to_thread(Image.open, BytesIO(raw))
        return [image], "image"

    async def _image_to_base64(self, image) -> str:
        def process():
            buffer = BytesIO()
            if image.mode in ("RGBA", "P", "LA"):
                img = image.convert("RGB")
            else:
                img = image
            img.thumbnail((1024, 1024))
            img.save(buffer, format="JPEG", quality=70)
            return base64.b64encode(buffer.getvalue()).decode()

        return await asyncio.to_thread(process)

    async def _call_llm_with_retry(self, content, retries=3):
        for attempt in range(retries):
            try:
                response = await self.llm_client.achat_completion(
                    chat_completion_params=ChatCompletionParams(
                        messages=[Message(role="user", content=content)]
                    )
                )

                if not response or not response.choices:
                    raise ValueError("Empty LLM response")

                message = response.choices[0].message
                if not message or not message.content:
                    raise ValueError("No content in LLM response")

                return message.content

            except Exception as e:
                logger.warning(f"LLM attempt {attempt + 1} failed: {e}")
                if attempt == retries - 1:
                    raise
        return None

    @tool
    async def extract_data(
        self,
        prompt: str,
        file_path: Optional[str] = None,
        base64_data: Optional[str] = None,
    ) -> Dict[str, Any]:

        try:
            if not file_path and not base64_data:
                return {
                    "success": False,
                    "error": "Either file_path or base64_data must be provided.",
                    "pages_processed": 0,
                    "file_type": None,
                    "data": None
                }

            if file_path:
                images, file_type = await self._load_images(file_path)
            else:
                images, file_type = await self._load_images_from_base64(base64_data)

            if len(images) > MAX_PAGES:
                images = images[:MAX_PAGES]
                logger.warning("Truncated pages to MAX_PAGES limit")

            results = []

            for i in range(0, len(images), 5):
                chunk = images[i:i + 5]

                content: List[Any] = [{"type": "text", "text": prompt}]

                for img in chunk:
                    img_b64 = await self._image_to_base64(img)
                    content.append({
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{img_b64}"
                        }
                    })

                text_output = await self._call_llm_with_retry(content)
                results.append(_parse_json(text_output))

            return {
                "success": True,
                "pages_processed": len(images),
                "file_type": file_type,
                "data": results
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

        finally:
            if file_path and file_path.startswith(SAFE_DELETE_DIR):
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.info(f"Deleted input file: {file_path}")
                except Exception as cleanup_error:
                    logger.warning(f"Failed to delete file: {cleanup_error}")
