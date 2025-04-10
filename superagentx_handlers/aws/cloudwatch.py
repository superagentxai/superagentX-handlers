import logging
import os

import boto3
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class AWSCloudWatchHandler(BaseHandler):

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

        self.cloudwatch_client = boto3.client(
           'cloudwatch',
            region_name=self.region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

    @tool
    async def get_metric_data(
            self,
            namespace,
            metric_name,
            start_time,
            end_time,
            period,
            statistics,
            dimensions
    ):
            """
            Fetches metric data from CloudWatch for a specified namespace and metric.

            Args:
                namespace (str): The namespace of the metric (e.g., 'AWS/EC2').
                metric_name (str): The name of the metric to retrieve (e.g., 'CPUUtilization').
                start_time (datetime): The start time of the period for which to retrieve data.
                end_time (datetime): The end time of the period for which to retrieve data.
                period (int): The granularity of the metric in seconds.
                statistics (list): The type of statistic (e.g., 'Average', 'Sum', etc.).
                dimensions (list): A list of dimension filters for the metric (e.g., instance ID).

            Returns:
                dict: The response from CloudWatch containing the metric data.
            """
            try:
                response = await sync_to_async(
                    self.cloudwatch_client.get_metric_data,
                    Namespace=namespace,
                    MetricName=metric_name,
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=period,
                    Statistics=statistics,
                    Dimensions=dimensions
                )
                logging.info(f"Metric data for {metric_name}: {response['Datapoints']}")
                return response
            except Exception as e:
                logging.error(f"Error fetching metric data: {e}")
