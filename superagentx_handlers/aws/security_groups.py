import logging
import os

import boto3
from botocore.exceptions import ClientError

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class AWSSecurityGroupsHandler(BaseHandler):

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

    @tool
    async def get_ec2_security_groups(self):
        """
        Retrieves details of AWS Security Groups configured as virtual firewalls for networks and resources exposed to
        the internet. This function queries AWS EC2 service to collect metadata about security groups, including their
        inbound and outbound rules, attached instances, and associated VPCs.
        """
        logger.info("Collecting EC2 Security Groups...")
        try:
            return await sync_to_async(self.ec2_client.describe_security_groups)
        except ClientError as e:
            logger.error(f"Error collecting EC2 security groups: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during EC2 security group collection: {e}")
        return []
