import base64
import json
import logging
import os
import time

from pathlib import Path
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

import requests

logger = logging.getLogger(__name__)


class ExtractAIHandler(BaseHandler):

    def __init__(
            self,
            api_token: str,
            prompt_name: str,
            extract_status_url: str | None = None,
            extract_url: str | None = None,
            project_id: str | None = None
    ):
        super().__init__()
        self.api_token = api_token or os.getenv("API_TOKEN")
        self.extract_status_url = extract_status_url or os.getenv("EXTRACT_STATUS_URL")
        self.extract_url = extract_url or os.getenv("EXTRACT_URL")
        self.prompt_name = prompt_name
        self.project_id = project_id

    def get_header(self):
        return {
            'api-token': self.api_token,
            'Content-Type': 'application/json'
        }

    @tool
    async def get_file_base64_data(self, file_path):
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

    def get_invoice_json_data(self, reference_id: str):
        logger.info(f"Getting invoice json data for {reference_id}")
        get_url = f"{self.extract_status_url}/{reference_id}"
        response = requests.request("GET", get_url, headers=self.get_header())
        return json.loads(response.text)

    def get_payload(self, project_id, file_path, file_data):
        return {
            "project_id": project_id,
            "file_name_or_path": str(file_path),
            "file_data": file_data,
            "instruction_type": self.prompt_name
        }

    def process_request(self, post_url, project_id, file_path, file_data):
        payload = self.get_payload(project_id=project_id, file_data=file_data, file_path=file_path)
        response = requests.post(post_url, headers=self.get_header(), data=json.dumps(payload))

        if response.status_code == 200:
            return response.json()  # Directly parse JSON response
        else:
            logger.info(f"Request to {post_url} failed with status code {response.status_code}...")
            raise Exception(f"Request failed with status code {response.status_code}: {response.text}")

    @tool
    async def extract_api(self, file_path: str, file_data, project_id: str | None = None, poll_interval=7):
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

        j_res = self.process_request(self.extract_url, project_id=project_id, file_path=file_path, file_data=file_data)
        # Detect response type
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
            res = self.get_invoice_json_data(ref_id)
            if res.get("status") == "FAILED":
                logger.error(f"Extract FAILED for job: {job_id}, Ref: {ref_id}")
                return None
            if res.get("status") == "SUCCESS":
                logger.info(f"Extract SUCCESS for job: {job_id}, Ref: {ref_id}")
                return res.get("extractJobInfo", {})

            time.sleep(poll_interval)

            logger.info(f'Extracting SUCCESS for JobId: {job_id}')
            return res if return_key == 'DF' else res.get('extractJobInfo')
