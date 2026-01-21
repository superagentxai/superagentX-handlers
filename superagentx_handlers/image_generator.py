import os
import time
import logging
import uuid

import requests
from superagentx.utils.helper import sync_to_async
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class ClipDropClient(BaseHandler):

    def __init__(self, api_key: str, end_point: str):
        super().__init__()
        self.api_key = api_key or os.getenv("CLIPDROP_API_KEY")
        self.endpoint = "https://clipdrop-api.co/text-to-image/v1"

    async def text_to_image(
            self,
            prompt: str,
            output_path: str = "generated_images"
    ):
        """
        Action: Convert text prompt to image using ClipDrop API.

        Args:
            prompt (str): Text prompt describing the image.
            output_path (str): Directory path where image will be saved.

        Returns:
            dict: Generation result.
        """

        logger.debug(f"Generating image for prompt: {prompt}")

        def generate_filename() -> str:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            return f"clipdrop_{timestamp}_{uuid.uuid4().hex[:8]}.png"

        def _generate():
            if not self.api_key:
                raise EnvironmentError("CLIPDROP_API_KEY is not set.")

            headers = {"x-api-key": self.api_key}
            files = {"prompt": (None, prompt)}

            response = requests.post(
                self.endpoint,
                headers=headers,
                files=files,
                timeout=60
            )

            if response.status_code != 200:
                raise RuntimeError(
                    f"ClipDrop API error {response.status_code}: {response.text}"
                )

            # output_path is treated as DIRECTORY
            os.makedirs(output_path, exist_ok=True)

            filename = generate_filename()
            final_output_path = os.path.join(output_path, filename)

            with open(final_output_path, "wb") as f:
                f.write(response.content)

            return {
                "status": "success",
                "output_path": final_output_path
            }

        return await sync_to_async(_generate)

    @tool
    async def remove_background_from_image(
            self,
            image_path: str,
            output_path: str
    ):
        """
        Action: Remove background from an image using Clipdrop API.

        Args:
            image_path (str): Path to the input image.

        Returns:
            dict: Processed image metadata and file path.
            :param image_path:
            :param output_path:
        """

        if not image_path:
            raise ValueError("image_path is required.")

        if not output_path:
            raise ValueError("output_path is required.")

        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")

        def get_unique_path(path: str) -> str:
            """
            Prevent overwriting existing files.
            Adds (1), (2), etc. if file already exists.
            """
            if not os.path.exists(path):
                return path

            base, ext = os.path.splitext(path)
            counter = 1

            while True:
                new_path = f"{base} ({counter}){ext}"
                if not os.path.exists(new_path):
                    return new_path
                counter += 1

        def _remove_bg():
            api_key = self.api_key or os.environ.get("CLIPDROP_API_KEY")
            if not api_key:
                raise EnvironmentError("CLIPDROP_API_KEY is not set.")

            url = "https://clipdrop-api.co/remove-background/v1"
            headers = {
                "x-api-key": api_key
            }

            with open(image_path, "rb") as f:
                response = requests.post(
                    url,
                    headers=headers,
                    files={"image_file": f}
                )

            if response.status_code != 200:
                raise RuntimeError(
                    f"Clipdrop API error {response.status_code}: {response.text}"
                )

            # Save output image
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

            final_output_path = get_unique_path(output_path)

            with open(final_output_path, "wb") as out:
                out.write(response.content)

            return {
                "image_id": str(uuid.uuid4()),
                "original_image": image_path,
                "processed_image": output_path,
                "provider": "clipdrop",
                "action": "remove_background"
            }

        return await sync_to_async(_remove_bg)

    @tool
    async def replace_background_from_image(
            self,
            image_path: str,
            background_prompt: str,
            output_path: str
    ):
        """
        Action: Replace background of an image using ClipDrop API.

        Args:
            image_path (str): Path to the input image.
            background_prompt (str): Text describing the new background.
            output_path (str): Directory where the processed image will be saved.

        Returns:
            dict: Processed image metadata and file path.
        """

        if not image_path:
            raise ValueError("image_path is required.")

        if not background_prompt:
            raise ValueError("background_prompt is required.")

        if not output_path:
            raise ValueError("output_path is required.")

        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")

        def generate_filename() -> str:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            return f"clipdrop_replace_bg_{timestamp}_{uuid.uuid4().hex[:8]}.png"

        def _replace_bg():
            if not self.api_key:
                raise EnvironmentError("CLIPDROP_API_KEY is not set.")

            url = "https://clipdrop-api.co/replace-background/v1"
            headers = {
                "x-api-key": self.api_key
            }

            with open(image_path, "rb") as f:
                response = requests.post(
                    url,
                    headers=headers,
                    files={
                        "image_file": f,
                        "prompt": (None, background_prompt)
                    },
                    timeout=60
                )

            if response.status_code != 200:
                raise RuntimeError(
                    f"ClipDrop API error {response.status_code}: {response.text}"
                )

            # output_path is treated as DIRECTORY
            os.makedirs(output_path, exist_ok=True)

            filename = generate_filename()
            final_output_path = os.path.join(output_path, filename)

            with open(final_output_path, "wb") as out:
                out.write(response.content)

            return {
                "image_id": str(uuid.uuid4()),
                "original_image": image_path,
                "processed_image": final_output_path,
                "provider": "clipdrop",
                "action": "replace_background"
            }

        return await sync_to_async(_replace_bg)
