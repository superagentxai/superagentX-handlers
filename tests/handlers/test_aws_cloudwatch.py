import os

import pytest
import logging
import datetime

from superagentx_handlers.aws.cloudwatch import AWSCloudWatchHandler, CloudWatch

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1.pytest --log-cli-level=INFO tests/handlers/test_aws_cloudwatch.py::TestAWSCloudwatch::test_get_metric_data
   

'''

@pytest.fixture
def aws_cloudwatch_client_init() -> AWSCloudWatchHandler:
    cloudwatch_handler = AWSCloudWatchHandler()
    return cloudwatch_handler


class TestAWSCloudwatch:

    async def test_get_metric_data(self, aws_cloudwatch_client_init: AWSCloudWatchHandler):
        try:
            end_time = datetime.datetime.utcnow()
            start_time = end_time - datetime.timedelta(hours=1)
            response = await aws_cloudwatch_client_init.get_metric_data(
                namespace="AWS/EC2",
                region_name="eu-central-1",
                metric_name="CPUUtilization",
                start_time=start_time,
                end_time=end_time,
                period=300,  # 5 minutes
                statistics=["Average"],
                dimensions=[{"Name": "InstanceId", "Value": "i-0cf72e3f766a27e0f"}]
            )
            return response
        except Exception as e:
            logging.error(f"Error fetching metric data: {e}")
            return None