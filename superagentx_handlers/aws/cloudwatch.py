import datetime
import logging
import os

import boto3
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class AWSCloudWatchHandler(BaseHandler):
    """
        AWS CloudWatch integration handler.

        This class provides asynchronous utilities for interacting with
        AWS CloudWatch Metrics and CloudWatch Logs, including:

        - Fetching metric data and listing available metrics
        - Inspecting CloudWatch Logs retention policies
        - Retrieving CloudWatch Logs resource access policies
        - Aggregating CloudWatch metadata for agent/tool consumption

        Public Tool Methods
        -------------------
        get_cloudwatch_data():
            Executes when the tool name is **AWS CLOUDWATCH**.
            Aggregates CloudWatch metadata, including metrics and
            (optionally) log retention and access policies.

            See `get_cloudwatch_data.__doc__` for full details.
    """

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

        self.client = boto3.client(
           'cloudwatch',
            region_name=self.region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

        self.cloud_watch_logs_cli = boto3.client(
            "logs",
            region_name=self.region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

    def convert_datetime_inplace(self, obj):
        """Recursively convert datetime objects to raw string format in-place."""
        if isinstance(obj, datetime.datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(obj, list):
            return [self.convert_datetime_inplace(v) for v in obj]
        elif isinstance(obj, dict):
            return {k: self.convert_datetime_inplace(v) for k, v in obj.items()}
        else:
            return obj

    async def get_metric_data(
            self,
            namespace: str = "AWS/EC2",
            metric_name: str = None,
            dimensions: list = None
    ):
        """
        Get CloudWatch metric data.
        - If no parameters → list all available metrics.
        - If namespace + metric_name provided → fetch datapoints for that metric.

        Args:
            namespace (str, optional): Metric namespace (e.g., "AWS/EC2").
            metric_name (str, optional): Metric name (e.g., "CPUUtilization").
            dimensions (list, optional): List of dimension dicts (e.g., [{"Name":"InstanceId", "Value":"i-123456"}]).

        Returns:
            dict: Metrics list or datapoints.
        """
        try:
            if namespace and metric_name:
                end_time = datetime.datetime.now()
                start_time = end_time - datetime.timedelta(hours=1)

                query = {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": metric_name,
                            "Dimensions": dimensions or []
                        },
                        "Period": 300,
                        "Stat": "Average"
                    },
                    "ReturnData": True
                }

                response = self.client.get_metric_data(
                    MetricDataQueries=[query],
                    StartTime=start_time,
                    EndTime=end_time,
                    ScanBy="TimestampDescending"
                )

                return {
                    "status": "success",
                    "namespace": namespace,
                    "metricName": metric_name,
                    "datapoints": response.get("MetricDataResults", [])
                }

            else:
                metrics = []
                paginator = await sync_to_async(self.client.get_paginator, "list_metrics")
                for page in paginator.paginate():
                    metrics.extend(page.get("Metrics", []))

                return metrics[0:100]

        except Exception as e:
            logger.error(f"An AWS CLOUDWATCH error occurred: {str(e)}")
            return {}

    async def get_log_group_retention(
            self,
            log_group_name: str = None
    ):
        """
        Get retention policy for CloudWatch Logs.
        - If log_group_name is provided → return retention for that log group.
        - If no log_group_name is provided → return all log groups with their retention.

        Args:
            log_group_name (str, optional): CloudWatch log group name.

        Returns:
            dict: Retention details.
        """

        try:
            if log_group_name:
                response = await sync_to_async(
                    self.cloud_watch_logs_cli.describe_log_groups,
                    logGroupNamePrefix=log_group_name,
                    limit=1
                )
                log_groups = response.get("logGroups", [])
                if not log_groups:
                    return {"status": "error", "message": f"Log group '{log_group_name}' not found."}

                log_group = log_groups[0]
                retention = log_group.get("retentionInDays", "Indefinite")

                return {
                    "status": "success",
                    "logGroupName": log_group_name,
                    "retentionInDays": retention
                }

            else:
                log_groups = []
                paginator = await sync_to_async(self.cloud_watch_logs_cli.get_paginator, "describe_log_groups")
                for page in paginator.paginate():
                    for lg in page.get("logGroups", []):
                        log_groups.append({
                            "logGroupName": lg["logGroupName"],
                            "retentionInDays": lg.get("retentionInDays", "Indefinite")
                        })

                return {
                    "status": "success",
                    "logGroups": log_groups
                }

        except Exception as e:
            logger.error(f"An AWS CLOUDWATCH error occurred: {str(e)}")
            return {}

    async def get_log_access(
            self,
            policy_name: str = None
    ):
        """
        Get CloudWatch Logs access policies.
        - If policy_name is provided → return that policy.
        - If no policy_name is provided → return all policies.

        Args:
            policy_name (str, optional): Name of the CloudWatch Logs resource policy.

        Returns:
            dict: Access policy details.
        """
        try:
            if policy_name:
                response = await sync_to_async(self.cloud_watch_logs_cli.describe_resource_policies)
                policies = [
                    p for p in response.get("resourcePolicies", [])
                    if p.get("policyName") == policy_name
                ]

                if not policies:
                    return {"status": "error", "message": f"Policy '{policy_name}' not found."}

                return {
                    "status": "success",
                    "policy": policies[0]
                }

            else:
                # Describe all policies
                policies = []
                paginator = await sync_to_async(self.cloud_watch_logs_cli.get_paginator, "describe_resource_policies")
                for page in paginator.paginate():
                    for p in page.get("resourcePolicies", []):
                        policies.append(p)

                return {
                    "status": "success",
                    "policies": policies
                }

        except Exception as e:
            logger.error(f"An AWS CLOUDWATCH error occurred:{str(e)}")
            return {}

    @tool
    async def get_cloudwatch_data(
            self
    ):
        """
        Executes this method when the specified tool name is **AWS CLOUDWATCH**.
        Aggregate CloudWatch Logs metadata.

        This coroutine fetches and returns a combined snapshot of CloudWatch Logs
        configuration details, including:

        - **log_retention**: Retention policies for log groups.
          Retrieved using `self.get_log_group_retention()`.
          Works with or without a log group parameter.
        - **log_access**: Account-level CloudWatch Logs resource access policies.
          Retrieved using `self.get_log_access()`.
          Works with or without a policy name parameter.
        """
        data = {
            # "log_retention": await self.get_log_group_retention(),
            # "log_access": await self.get_log_access(),
            "metric": await self.get_metric_data()
        }
        result = self.convert_datetime_inplace(data)
        logger.info(f"AWS CloudWatch: {result}")
        return result