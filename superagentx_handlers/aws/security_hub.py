import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class AWSSecurityHubHandler(BaseHandler):
    """
    A handler for managing interactions with AWS Security Hub.
    This class provides tools to retrieve security posture metrics,
    findings, and resource risk information.
    """

    def __init__(
            self,
            aws_access_key_id: str = None,
            aws_secret_access_key: str = None,
            region_name: str = None
    ):
        super().__init__()
        self.aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.region_name = region_name or os.getenv("AWS_REGION", "us-east-1")

        self.session = None

        if not self.aws_access_key_id or not self.aws_secret_access_key:
            logger.error("AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) not provided. "
                         "Handler will not be able to make API calls.")
            return

        try:
            self.session = boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=self.region_name
            )
            self.securityhub_client = self.session.client("securityhub")

            self._is_initialized = True
            logger.debug("AWSSecurityHubHandler initialized successfully.")
        except NoCredentialsError:
            logger.error("AWS credentials not found or invalid during handler initialization.",
                         exc_info=True)
            self._is_initialized = False
        except ClientError as e:
            logger.error(f"AWS Client error during Security Hub handler initialization: {e}", exc_info=True)
            self._is_initialized = False
        except Exception as e:
            logger.error(f"An unexpected error occurred during Security Hub handler initialization: {e}",
                         exc_info=True)
            self._is_initialized = False

    @staticmethod
    async def _list_all_paginated_data(client: Any, operation_name: str, result_key: str, **kwargs) -> list:
        """
        Helper method to handle pagination for AWS API calls.
        """
        all_data: list = []
        try:
            paginator = await sync_to_async(client.get_paginator, operation_name)
            for page in await sync_to_async(paginator.paginate, **kwargs):
                if result_key in page:
                    all_data.extend(page[result_key])
        except ClientError as e:
            logger.error(f"AWS Client error during pagination for {operation_name}: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"An unexpected error occurred during pagination for {operation_name}: {e}",
                         exc_info=True)
        return all_data

    @tool
    async def get_findings_over_time(
            self,
            days_ago: int = 30,
            severity_levels: list[str] = None
    ) -> dict[str, Any]:
        """
        Tracks the number of new findings and their severity levels over a period.
        Aggregates findings by day across all severity levels.

        Parameters:
            days_ago (int, optional): The number of past days to retrieve findings for (default: 30).
            severity_levels (list[str], optional): list of severity levels to filter (e.g., ['CRITICAL', 'HIGH']).
        """
        findings_data: dict[str, Any] = {
            "total_findings": 0,
            "findings_by_day": {},
            "findings_by_severity": defaultdict(int)
        }

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days_ago)

        filters = {
            'CreatedAt': [{
                'Start': start_time.isoformat(timespec='milliseconds'),
                'End': end_time.isoformat(timespec='milliseconds')
            }],
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }

        if severity_levels:
            filters['Severity.Label'] = [{'Value': s.upper(), 'Comparison': 'EQUALS'} for s in severity_levels]

        try:
            all_findings = await self._list_all_paginated_data(
                self.securityhub_client,
                'get_findings',
                'Findings',
                Filters=filters
            )

            findings_data["total_findings"] = len(all_findings)

            for finding in all_findings:
                created_at_str = finding.get('CreatedAt')
                if created_at_str:
                    created_date = datetime.fromisoformat(
                        created_at_str.replace('Z', '+00:00')
                    ).strftime('%Y-%m-%d')

                    if created_date not in findings_data["findings_by_day"]:
                        findings_data["findings_by_day"][created_date] = defaultdict(int)

                    severity_label = finding.get('Severity', {}).get('Label', 'UNKNOWN')
                    findings_data["findings_by_day"][created_date][severity_label] += 1
                    findings_data["findings_by_severity"][severity_label] += 1

            for date_key in findings_data["findings_by_day"]:
                findings_data["findings_by_day"][date_key] = \
                    dict(findings_data["findings_by_day"][date_key])
            findings_data["findings_by_severity"] = dict(findings_data["findings_by_severity"])

            logger.info(f"Retrieved findings over time.")

        except ClientError as e:
            logger.error(f"AWS Client error while getting findings over time: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred while getting findings over time: {e}", exc_info=True)

        return findings_data

    @tool
    async def get_top_risky_resources(
            self,
            top_n: int = 10,
            severity_levels: list[str] = None,
            days_ago: int = 30
    ) -> list[dict[str, Any]]:
        """
        Identifies the top N resources most frequently flagged in Security Hub findings.

        Parameters:
            top_n (int, optional): The number of top resources to return (default: 10).
            severity_levels (list[str], optional): list of severity levels to consider (e.g., ['CRITICAL', 'HIGH']).
            days_ago (int, optional): The number of past days to consider findings from (default: 30).
        """
        top_risky_resources = []
        resource_risk_counts: dict[str, dict[str, Any]] = \
            defaultdict(lambda: {"count": 0, "severities": defaultdict(int)})

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days_ago)

        filters = {
            'CreatedAt': [{
                'Start': start_time.isoformat(timespec='milliseconds'),
                'End': end_time.isoformat(timespec='milliseconds')
            }],
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }

        if severity_levels:
            filters['Severity.Label'] = [{'Value': s.upper(), 'Comparison': 'EQUALS'} for s in severity_levels]

        try:
            all_findings = await self._list_all_paginated_data(
                self.securityhub_client,
                'get_findings',
                'Findings',
                Filters=filters
            )

            for finding in all_findings:
                resource = finding.get('Resources', [])[0] if finding.get('Resources') else None
                if resource:
                    resource_id = resource.get('Id')
                    resource_type = resource.get('Type')
                    severity_label = finding.get('Severity', {}).get('Label', 'UNKNOWN')

                    if resource_id:
                        resource_risk_counts[resource_id]["count"] += 1
                        resource_risk_counts[resource_id]["resource_type"] = resource_type
                        resource_risk_counts[resource_id]["severities"][severity_label] += 1

            for resource_id, data in resource_risk_counts.items():
                resource_risk_counts[resource_id]["severities"] = dict(data["severities"])

            sorted_resources = sorted(
                resource_risk_counts.items(),
                key=lambda item: item[1]["count"],
                reverse=True
            )


            for i, (resource_id, data) in enumerate(sorted_resources):
                if i >= top_n:
                    break
                top_risky_resources.append({
                    "ResourceId": resource_id,
                    "ResourceType": data.get("resource_type"),
                    "FindingCount": data["count"],
                    "SeverityCounts": data["severities"]
                })

            logger.info(f"Retrieved top risky resources.")

        except ClientError as e:
            logger.error(f"AWS Client error while getting top risky resources: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"An unexpected error occurred while getting top risky resources: {e}", exc_info=True)

        return top_risky_resources
