import asyncio
import base64
import json
import logging
import os
import time
from typing import Optional

import aiofiles
import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class ExtractAIHandler(BaseHandler):

    API_EXTRACT_ENDPOINT: str = '/extutil/api/v1/do'
    API_STATUS_ENDPOINT: str = '/extutil/api/v1/status'

    def __init__(
            self,
            prompt_name: str,
            api_token: str | None = None,
            base_url: str | None = None,
            project_id: str | None = None
    ):
        super().__init__()
        self.prompt_name = prompt_name
        self.api_token = api_token or os.getenv("EXTRACT_API_TOKEN")
        self.base_url = base_url or os.getenv("BASE_URL")
        self.project_id = project_id
        self.__headers = {
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
            async with aiofiles.open(file_path, "rb") as pdf_file:
                # Read the PDF content and encode it to Base64
                return base64.b64encode(await pdf_file.read()).decode('utf-8')
        except FileNotFoundError:
            logger.info(f"File {file_path} not found...")

    async def get_invoice_json_data(self, reference_id: str):
        logger.info(f"Getting invoice json data for {reference_id}")
        get_url = f"{self.base_url}/{self.API_STATUS_ENDPOINT}/{reference_id}"

        async with aiohttp.ClientSession() as session:
            async with session.request("GET", get_url, headers=self.__headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"Failed to fetch invoice data. Status: {response.status}, Response: {error_text}")
                    raise Exception(f"Error fetching invoice data: {response.status}")

                data = await response.json()
                logger.debug(f"Invoice JSON Data: {data}")
                return data


    async def process_request(
            self,
            post_url,
            project_id,
            file_path,
            file_data
    ):
        payload = {
            "project_id": project_id,
            "file_name_or_path": file_path,
            "file_data": file_data,
            "instruction_type": self.prompt_name
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(post_url, headers=self.__headers, data=json.dumps(payload)) as response:
                if response.status == 200:
                    return await response.json()  # Directly parse JSON response
                else:
                    logger.info(f"Request to {post_url} failed with status code {response.status}...")
                    raise Exception(f"Request failed with status code {response.status}: {response.text}")

    @tool
    async def extract_api(
            self,
            file_path: str,
            file_data,
            poll_interval: int,
            project_id: Optional[str] = None
    ):
        """
        Unified extract method for both DF and SAgentX responses.
        Returns extracted data or None on failure.
        """
        if not self.project_id and not project_id:
            raise ValueError(f"Project Id invalid: {project_id}")
        if self.project_id:
            project_id = self.project_id
        if not project_id:
            project_id = self.project_id

        j_res = await self.process_request(
            post_url=f"{self.base_url}{self.API_EXTRACT_ENDPOINT}",
            project_id=project_id,
            file_path=file_path,
            file_data=file_data
        )  # Detect response type
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

        while True:
            res = await self.get_invoice_json_data(ref_id)

            if res.get("status") == "FAILED":
                logger.error(f"Extract FAILED for job: {job_id}, Ref: {ref_id}")
                return None

            if res.get("status") == "SUCCESS":
                logger.info(f"Extract SUCCESS for job: {job_id}, Ref: {ref_id}")
                return res.get("extractJobInfo", {})

            await asyncio.sleep(poll_interval)

            logger.info(f'Extracting SUCCESS for JobId: {job_id}, Ref: {ref_id}')
            return res if return_key == 'DF' else res.get('extractJobInfo')
