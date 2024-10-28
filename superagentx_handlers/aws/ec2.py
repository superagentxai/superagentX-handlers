import logging
import os

import boto3

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

logger = logging.getLogger(__name__)


class AWSEC2Handler(BaseHandler):

    def __init__(
            self,
            aws_access_key_id: str | None = None,
            aws_secret_access_key: str | None = None,
            region_name: str | None = None
    ):
        super().__init__()
        self.region = region_name or os.getenv("AWS_REGION")
        aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")

        self.ec2_client = boto3.client(
           'ec2',
            region_name=self.region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

    async def _get_all_instances(
            self,
            filters: list[dict]
    ):
        """
        Asynchronously retrieves and returns a list of all instances managed by this handler.

        This method interacts with an external service (e.g., AWS EC2, Google Cloud Compute, etc.) to fetch details
        of all instances currently available or active in the system. It is designed to be run asynchronously,
        allowing other tasks to execute concurrently without blocking.
        """
        try:
            instance = await sync_to_async(self.ec2_client.describe_instances, Filters=filters)
            if instance and instance["Reservations"]:
                instances = [
                    _instance async for reservation in iter_to_aiter(instance["Reservations"])
                    async for _instance in iter_to_aiter(reservation["Instances"])
                ]
                return instances
        except Exception as ex:
            logger.error(f"Get all Instance getting error: {ex}")

    @tool
    async def get_all_running_instances(self)->list[dict]:
        """
           Fetch all currently active or running instances.

           This method communicates with an external service (e.g., AWS EC2, Google Cloud Compute, etc.) to
           fetch details of all instances that are currently in the 'running' state. It is designed to run
           asynchronously to allow non-blocking execution.
        """
        _filters = { "Name": "instance-state-name", "Values": ["running"] }
        response = await self._get_all_instances(filters=[_filters])
        if response:
            logger.debug(f"Running Instances {len(response)}")
            return response

    @tool
    async def get_all_stopped_instances(self)->list[dict]:
        """
            Retrieve all currently stopped instances.

            This method interacts with an external service (e.g., AWS EC2, Google Cloud Compute, etc.) to
            fetch details of all instances that are in the 'stopped' state. It is designed to run
            asynchronously, enabling non-blocking execution.
        """
        _filters = {"Name": "instance-state-name", "Values": ["stopped"]}
        response = await self._get_all_instances(filters=[_filters])
        if response:
            logger.debug(f"Stopped Instances {len(response)}")
            return response
