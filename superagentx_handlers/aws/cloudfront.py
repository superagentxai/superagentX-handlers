import os
import logging
# Removed asyncio as boto3 is synchronous, and using sync_to_async
import boto3 # Using boto3
from botocore.exceptions import ClientError, NoCredentialsError
from superagentx.utils.helper import sync_to_async

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class AWSCloudFrontHandler(BaseHandler):
    """
    A handler for managing interactions with AWS CloudFront.
    This class provides methods to retrieve details about CloudFront distributions,
    associated certificates, cache behaviors, and access control configurations.
    """

    def __init__(
        self,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        region_name: str | None = None
    ):
        super().__init__()
        self.aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.region_name = region_name or os.getenv("AWS_REGION", "us-east-1")

        self._is_initialized = False
        self.session = None
        self.cloudfront_client = None
        self.acm_client = None
        self.session = boto3.Session(
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.region_name
        )
        self.cloudfront_client = self.session.client("cloudfront")
        self.acm_client = self.session.client(
            "acm",
            region_name=self.region_name
        )

        self._is_initialized = True
        logger.debug("AWSCloudFrontHandler initialized successfully.")

    @staticmethod
    async def _list_all_paginated_data(
            client: Any,
            operation_name: str,
            result_key: str
    ) -> list:
        """
        Helper method to handle pagination for AWS API calls.
        """
        all_data: list[Dict] = []
        try:
            paginator = await sync_to_async(client.get_paginator, operation_name)
            pages = await sync_to_async(paginator.paginate)
            for page in pages:
                if result_key in page:
                    all_data.extend(page[result_key])
        except ClientError as e:
            logger.error(f"AWS Client error during pagination for {operation_name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(
                f"An unexpected error occurred during pagination for {operation_name}: {e}",
                exc_info=True
            )
        return all_data

    @tool
    async def list_distributions(self) -> list:
        """
        Lists all CloudFront distributions with all available details.
        """

        final_distributions: list[Dict] = []
        try:
            paginator = await sync_to_async(self.cloudfront_client.get_paginator, 'list_distributions')
            pages = await sync_to_async(paginator.paginate)
            for page in pages:
                if 'DistributionList' in page and 'Items' in page['DistributionList']:
                    final_distributions.extend(page['DistributionList']['Items'])
            logger.info(f"Successfully retrieved {len(final_distributions)} CloudFront distributions.")
        except ClientError as e:
            logger.error(f"AWS Client error while listing CloudFront distributions: {e}", exc_info=True)
        except Exception as e:
            logger.error(
                f"An unexpected error occurred while listing CloudFront distributions: {e}",
                exc_info=True
            )

        return final_distributions

    @tool
    async def list_certificates(self) -> list:
        """
        Lists all SSL/TLS certificates managed by AWS Certificate Manager (ACM)
        in us-east-1 region, as these are typically used with CloudFront.
        Returns all available details for each certificate.
        """

        final_certificates: list[Dict] = []
        try:
            final_certificates = await self._list_all_paginated_data(
                client=self.acm_client,
                operation_name='list_certificates',
                result_key='CertificateSummaryList'
            )
            logger.info(f"Successfully retrieved {len(final_certificates)} ACM certificates.")
        except ClientError as e:
            logger.error(f"AWS Client error while listing ACM certificates: {e}", exc_info=True)
        except Exception as e:
            logger.error(
                f"An unexpected error occurred while listing ACM certificates: {e}",
                exc_info=True
            )
        return final_certificates

    @tool
    async def list_cache_behaviors(self) -> list:
        """
        Lists all cache behaviors configured across all CloudFront distributions.
        Returns a list of dictionaries, each containing distribution ID and its associated cache behaviors.
        """
        all_cache_behaviors: list[Dict] = []
        try:
            distributions = await self.list_distributions()
            for dist in distributions:
                dist_id = dist.get('Id')
                if dist_id:
                    try:
                        dist_config_response = await sync_to_async(
                            self.cloudfront_client.get_distribution_config, Id=dist_id
                        )
                        dist_config = dist_config_response.get('DistributionConfig')

                        if dist_config:
                            default_cache_behavior = dist_config.get('DefaultCacheBehavior')
                            if default_cache_behavior:
                                all_cache_behaviors.append({
                                    "DistributionId": dist_id,
                                    "Type": "Default",
                                    "CacheBehavior": default_cache_behavior
                                })

                            ordered_cache_behaviors = dist_config.get('CacheBehaviors', {}).get('Items', [])
                            for behavior in ordered_cache_behaviors:
                                all_cache_behaviors.append({
                                    "DistributionId": dist_id,
                                    "Type": "Ordered",
                                    "CacheBehavior": behavior
                                })
                    except ClientError as e:
                        logger.warning(
                            f"Could not retrieve config for distribution {dist_id}: {e}",
                            exc_info=True
                        )
                    except Exception as e:
                        logger.warning(
                            f"Unexpected error getting config for distribution {dist_id}: {e}",
                            exc_info=True
                        )

            logger.info(f"Successfully retrieved {len(all_cache_behaviors)} cache behaviors across distributions.")
        except Exception as e:
            logger.error(
                f"An unexpected error occurred while listing CloudFront cache behaviors: {e}",
                exc_info=True
            )

        return all_cache_behaviors

    @tool
    async def list_access_control_configs(self) -> list:
        """
        Lists access control configurations (geo-restrictions, WAF associations)
        for all CloudFront distributions.
        Returns a list of dictionaries, each containing distribution ID and its access control details.
        """

        all_access_controls: list[Dict] = []
        try:
            distributions = await self.list_distributions()
            for dist in distributions:
                dist_id = dist.get('Id')
                if dist_id:
                    try:
                        dist_config_response = await sync_to_async(
                            self.cloudfront_client.get_distribution_config, Id=dist_id
                        )
                        dist_config = dist_config_response.get('DistributionConfig')

                        if dist_config:
                            access_control_info = {
                                "DistributionId": dist_id,
                                "GeoRestriction": dist_config.get('Restrictions', {}).get('GeoRestriction', {}),
                                "WebACLId": dist_config.get('WebACLId')
                            }
                            all_access_controls.append(access_control_info)
                    except ClientError as e:
                        logger.warning(
                            f"Could not retrieve config for distribution {dist_id}: {e}",
                            exc_info=True
                        )
                    except Exception as e:
                        logger.warning(
                            f"Unexpected error getting config for distribution {dist_id}: {e}",
                            exc_info=True
                        )

            logger.info(f"Successfully retrieved {len(all_access_controls)} access control configurations.")
        except Exception as e:
            logger.error(
                f"An error occurred while listing CloudFront access control configurations: {e}",
                exc_info=True)

        return all_access_controls
