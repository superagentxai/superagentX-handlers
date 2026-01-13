import asyncio
import os
import json
from typing import Dict, List
from openai import OpenAI
import logging

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)



class ExtractHandler(BaseHandler):
    """"
    Handler for extracting structured information from files using an OpenAI model.

    This handler accepts a single file or a directory of files, uploads each file
    to the OpenAI API, prompts the model to extract information, and saves the
    extracted results as JSON files.

    Supported features:
    - Accepts either a single file path or a directory of files
    - Normalizes file extensions (e.g., `.PDF` → `.pdf`)
    - Uploads files to the OpenAI Files API
    - Sends each file to a model with a user-defined extraction prompt
    - Attempts to parse the model output as JSON, falling back to raw text if parsing fails
    - Writes one JSON output file per input file

    Attributes:
        client (OpenAI): OpenAI client initialized with the provided API key.
        model (str): The OpenAI model used for extraction (default: "gpt-4.1-mini").
"""

    def __init__(self, api_key: str, model: str = "gpt-4.1-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    # -----------------------------
    # Normalize extension (.PDF -> .pdf)
    # -----------------------------
    @staticmethod
    def normalize_extension(path: str) -> str:
        base, ext = os.path.splitext(path)
        if ext and ext != ext.lower():
            new_path = base + ext.lower()
            os.rename(path, new_path)
            return new_path
        return path

    # -----------------------------
    # Resolve files from path
    # -----------------------------
    @staticmethod
    def resolve_files(path: str) -> List[str]:
        if os.path.isfile(path):
            return [path]

        if os.path.isdir(path):
            return [
                os.path.join(path, f)
                for f in os.listdir(path)
                if os.path.isfile(os.path.join(path, f))
            ]

        raise FileNotFoundError(f"Invalid path: {path}")

    @tool
    async def extract(
            self,
            file_path: str,
            prompt: str,
            output_path: str,
    ) -> Dict[str, dict]:
        files = self.resolve_files(file_path)
        results = {}

        # Ensure output directory exists
        os.makedirs(output_path, exist_ok=True)

        for file in files:
            file = self.normalize_extension(file)
            file_name = os.path.basename(file)

            logger.info("Processing file: %s", file_name)

            # Upload file
            with open(file, "rb") as f:
                uploaded = self.client.files.create(
                    file=f,
                    purpose="assistants"
                )

            # Ask model to extract
            response = self.client.responses.create(
                model=self.model,
                input=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "input_file", "file_id": uploaded.id},
                            {"type": "input_text", "text": prompt},
                        ],
                    }
                ],
            )

            # Extract text safely
            output_text = response.output_text

            # Try JSON parse
            try:
                parsed_output = json.loads(output_text)
            except Exception:
                parsed_output = {"raw_output": output_text}

            results[file_name] = parsed_output


            name, _ = os.path.splitext(file_name)
            output_file = os.path.join(output_path, f"{name}.json")

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(parsed_output, f, indent=2, ensure_ascii=False)

            logger.info("Saved output to %s", output_file)

        return results


