import base64
import json
import logging
import os
import time
import requests
from typing import Optional

import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from functools import lru_cache

logger = logging.getLogger(__name__)


class ExtractAIHandler(BaseHandler):
    API_EXTRACT_ENDPOINT: str = '/extutil/api/v1/do'
    API_STATUS_ENDPOINT: str = '/extutil/api/v1/status'

    def __init__(
            self,
            api_token: str,
            prompt_name: str,
            base_url: str | None = None,
            project_id: str | None = None
    ):
        super().__init__()
        self.api_token = api_token or os.getenv("EXTRACT_API_TOKEN")
        self.base_url = base_url or os.getenv("BASE_URL")
        self.prompt_name = prompt_name
        self.project_id = project_id

    @lru_cache(maxsize=1)
    def get_header(self):
        return {
            'api-token': self.api_token,
            'Content-Type': 'application/json'
        }

    @tool
    async def get_file_base64_data(self, file_path):
        """
        Read a file from the given path and return its Base64-encoded content.

        Args:
            file_path (str): The path to the file that needs to be read.
        """
        try:
            logger.info(f"Reading file {file_path}")
            # Open the PDF file in binary mode
            with open(file_path, "rb") as pdf_file:
                # Read the PDF content and encode it to Base64
                base64_data = base64.b64encode(pdf_file.read()).decode('utf-8')
            return base64_data
        except FileNotFoundError:
            logger.info(f"File {file_path} not found...")
            # print("File not found. Please provide a valid file path.")
            return None

    async def get_invoice_json_data(self, reference_id: str):
        logger.info(f"Getting invoice json data for {reference_id}")
        get_url = f"{self.base_url}/{self.API_STATUS_ENDPOINT}/{reference_id}"
        response = requests.request("GET", get_url, headers=self.get_header())
        return json.loads(response.text)

    async def process_request(self, post_url, project_id, file_path, file_data):
        storage_file_path = file_path
        payload = {
            "project_id": project_id,
            "file_name_or_path": storage_file_path,
            "file_data": file_data,
            "instruction_type": self.prompt_name
        }
        response = requests.post(post_url, headers=self.get_header(), data=json.dumps(payload))

        if response.status_code == 200:
            return response.json()  # Directly parse JSON response
        else:
            logger.info(f"Request to {post_url} failed with status code {response.status_code}...")
            raise Exception(f"Request failed with status code {response.status_code}: {response.text}")

    @tool
    async def extract_api(self, file_path: str, file_data, poll_interval: int, project_id: Optional[str] = None):
        """
        Unified extract method for both DF and SAgentX responses.
        Returns extracted data or None on failure.
        """
        if not self.project_id and not project_id:
            raise ValueError(f"Project Id invalid: {project_id}")
        if self.project_id:
            project_id = project_id
        if not project_id:
            project_id = self.project_id

        j_res = await self.process_request(f"{self.base_url}{self.API_EXTRACT_ENDPOINT}", project_id=project_id,
                                           file_path=file_path, file_data=file_data)  # Detect response type
        if j_res.get('statusCode') == '200':  # DF style
            job_id = j_res['jobId']
            ref_id = j_res['referenceId']
            return_key = 'DF'
        elif str(j_res.get('status', '')).upper() == 'SUCCESS':  # SAgentX style
            job_info = j_res.get('extractJobInfo', {})
            job_id = job_info.get('jobId')
            ref_id = job_info.get('requestId')
            return_key = 'SAGENTX'
        else:
            logger.info('Extracting FAILED: Invalid response')
            return None

        logger.info(f'Extracting file JobId: {job_id}')

        while True:
            res = await self.get_invoice_json_data(ref_id)
            if res.get("status") == "FAILED":
                logger.error(f"Extract FAILED for job: {job_id}, Ref: {ref_id}")
                return None
            if res.get("status") == "SUCCESS":
                logger.info(f"Extract SUCCESS for job: {job_id}, Ref: {ref_id}")
                return res.get("extractJobInfo", {})

            time.sleep(poll_interval)

            logger.info(f'Extracting SUCCESS for JobId: {job_id}')
            return res if return_key == 'DF' else res.get('extractJobInfo')

