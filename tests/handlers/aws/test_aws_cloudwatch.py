import datetime
import logging

import pytest

from superagentx_handlers.aws.cloudwatch import AWSCloudWatchHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1.pytest --log-cli-level=INFO tests/handlers/aws/test_aws_cloudwatch.py::TestAWSCloudwatch::test_get_metric_data
'''


@pytest.fixture
def aws_cloudwatch_client_init() -> AWSCloudWatchHandler:
    cloudwatch_handler = AWSCloudWatchHandler(
        aws_access_key_id="<ACCESS_KEY_ID>",
        aws_secret_access_key="<SECRET_ACCESS_KEY>",
        region_name="<REGION_NAME>"
    )
    return cloudwatch_handler


class TestAWSCloudwatch:

    async def test_get_metric_data(self, aws_cloudwatch_client_init: AWSCloudWatchHandler):
        try:
            end_time = datetime.datetime.utcnow()
            start_time = end_time - datetime.timedelta()
            response = await aws_cloudwatch_client_init.get_metric_data()
            logger.info(len(response))
            return start_time
        except Exception as e:
            logging.error(f"Error fetching metric data: {e}")
            return None