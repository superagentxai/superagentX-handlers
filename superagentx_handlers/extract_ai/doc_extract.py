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

    def __init__(self, llm_config: Dict):
        super().__init__()
        self.llm_client = LLMClient(llm_config=llm_config)

    async def _pdf_to_images(self, pdf_bytes: bytes) -> list:
        return convert_from_bytes(pdf_bytes)

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
            image = Image.open(BytesIO(img_bytes))
            return [image], "image"

        else:
            raise ValueError(
                f"Unsupported file type '{ext}'. "
                f"Supported: PDF {PDF_EXTENSIONS}, Image {IMAGE_EXTENSIONS}"
            )

    async def _load_images_from_base64(self, b64_data: str) -> tuple[list, str]:
        raw = base64.b64decode(b64_data)

        if raw[:4] == b"%PDF":
            images = await self._pdf_to_images(raw)
            return images, "pdf"

        image = Image.open(BytesIO(raw))
        return [image], "image"

    def _image_to_base64(self, image) -> str:
        buffer = BytesIO()
        if image.mode in ("RGBA", "P", "LA"):
            image = image.convert("RGB")
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
        file_path: Optional[str] = None,
        base64_data: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            images = []
            file_type = None

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
        finally:
            # delete input file if provided
            if file_path:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.info(f"Deleted input file: {file_path}")
                except Exception as cleanup_error:
                    logger.warning(f"Failed to delete file: {cleanup_error}")

 
