import base64
import logging
import os
from io import BytesIO
from pdf2image import convert_from_path
import openai

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx_handlers.google.exceptions import AuthException

logger = logging.getLogger(__name__)


class GptHandler(BaseHandler):
    """
    A handler class for extracting texts with OpenAI.
    This class extends BaseHandler and provides methods for performing text extraction operations using OpenAI.
    """

    def __init__(self, *, openai_api_key: str | None = None):
        super().__init__()
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        if not self.openai_api_key:
            raise AuthException("OpenAI API key not provided.")

    @tool
    async def extract(
            self,
            prompt: str,
            file_path: str
    ):
        """
        Extracts information from a prompt, optionally including file content.
        """
        content = [
            {
                "type": "text",
                "text": prompt
            }
        ]

        if file_path:
            try:
                if file_path.lower().endswith(".pdf"):
                    images = convert_from_path(file_path)
                    for image in images:
                        buffered = BytesIO()
                        image.save(buffered, format="JPEG")
                        base64_image = base64.b64encode(buffered.getvalue()).decode('utf-8')
                        content.append({
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}
                        })
                else:
                    with open(file_path, 'rb') as f:
                        encoded_string = base64.b64encode(f.read()).decode('utf-8')
                        content.append({"type": "text", "text": f"File content: {encoded_string}"})

            except FileNotFoundError:
                logger.warning(f"File {file_path} not found, continuing without it.")
            except Exception as ex:
                message = f"Error reading file {file_path}: {ex}"
                logger.error(message, exc_info=ex)
                raise AuthException(message)

        try:
            response = openai.chat.completions.create(
                model="chatgpt-4o-latest",
                messages=[
                    {
                        "role": "user",
                        "content": content
                    }
                ],
                max_tokens=16384,
                temperature=0,
            )

            response_text = response.choices[0].message.content.strip()
            logger.debug("Extraction completed successfully.")
            return response_text

        except Exception as ex:
            message = f"OpenAI API extraction failed: {ex}"
            logger.error(message, exc_info=ex)
            raise AuthException(message)
