import asyncio
import logging
import mimetypes
import os
from typing import Optional

import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

UPLOAD_SEM = asyncio.Semaphore(10)

logger = logging.getLogger(__name__)


class AWSS3Handler(BaseHandler):
    """
    AWSS3Handler — Async AWS S3 Storage Operations Handler

    This handler provides asynchronous, LLM-friendly access to AWS S3. It authenticates
    using AWS credentials and exposes a comprehensive collection of tool methods to
    retrieve bucket configuration metadata, security controls, storage settings,
    object information, and to perform file upload and download operations.

    The handler abstracts boto3’s synchronous API, error handling, concurrency control,
    and multi-bucket aggregation to make AWS S3 inventory, security posture, and
    storage management simple for agents and LLM-driven workflows.

        - list_buckets:                     Retrieve all S3 buckets in the AWS account.
        - get_bucket:                       Retrieve basic bucket existence and metadata.
        - get_bucket_accelerate_config:     Retrieve transfer acceleration configuration.
        - get_bucket_acl:                   Retrieve bucket Access Control List (ACL).
        - get_bucket_analytics_config:      Retrieve bucket analytics configuration.
        - get_bucket_cors:                  Retrieve Cross-Origin Resource Sharing (CORS) rules.
        - get_bucket_encryption:            Retrieve server-side encryption configuration.
        - get_bucket_intelligent_tiering_config:
                                            Retrieve Intelligent-Tiering configuration.
        - get_bucket_inventory_config:      Retrieve bucket inventory configuration.
        - get_bucket_lifecycle_config:      Retrieve lifecycle management rules.
        - get_bucket_location:              Retrieve bucket region information.
        - get_bucket_logging:               Retrieve access logging configuration.
        - get_bucket_metadata_table_config: Retrieve metadata table configuration.
        - get_bucket_metrics_config:        Retrieve CloudWatch metrics configuration.
        - get_bucket_notification_config:   Retrieve event notification configuration.
        - get_bucket_ownership_controls:    Retrieve object ownership controls.
        - get_bucket_policy:                Retrieve bucket policy document.
        - get_bucket_policy_status:         Determine whether the bucket is publicly accessible.
        - get_bucket_replication:            Retrieve replication configuration.
        - get_bucket_req_payment:            Retrieve requester pays configuration.
        - get_bucket_tagging:                Retrieve bucket tags.
        - get_bucket_versioning:             Retrieve versioning configuration.
        - get_all_buckets_info:              Aggregate security and configuration details
                                            across all buckets in the account.
        - list_files:                        List objects within a bucket by prefix or delimiter.
        - get_file_info:                    Retrieve object metadata and properties.
        - upload:                            Upload a file or directory to S3 with
                                            concurrency control and cache optimization.
        - download_file:                    Download an object from S3 to a local path.
    """

    def __init__(
            self,
            aws_access_key_id: str | None = None,
            aws_secret_access_key: str | None = None,
            region_name: str | None = None,
            **kwargs
    ):
        super().__init__()
        self.region = region_name or os.getenv("AWS_REGION")
        self._storage = boto3.client(
           's3',
            region_name=self.region,
            aws_access_key_id=aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        )

    @tool
    async def list_buckets(self):
        """
        Asynchronously retrieves a list of all buckets in the specified AWS S3 account.
        """
        try:
            return await sync_to_async(self._storage.list_buckets)
        except (NoCredentialsError, ClientError) as ex:
            logger.error("Error listing files!", exc_info=ex)
            return {}

    @tool
    async def get_bucket(self, bucket_name: str):
        """
        Retrieves the bucket information for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The bucket information if available.
        """
        try:
            return await sync_to_async(
                self._storage.head_bucket,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_accelerate_config(self, bucket_name: str):
        """
        Retrieves the accelerate configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The accelerate configuration of the bucket, if available.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_accelerate_configuration,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket accelerate config!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_acl(self, bucket_name: str):
        """
        Retrieves the Access Control List (ACL) for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The dictionary containing the bucket's ACL information.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_acl,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket acl!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_analytics_config(
            self,
            bucket_name: str,
            analytics_config_id: str
    ):
        """
        Retrieves the analytics configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.
            analytics_config_id (str): The ID of the analytics configuration to retrieve.

        Returns:
            dict: The analytics configuration details if found.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_analytics_configuration,
                Bucket=bucket_name,
                Id=analytics_config_id
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket analytics configuration!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_cors(self, bucket_name: str):
        """
        Retrieves the Cross-Origin Resource Sharing (CORS) configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The CORS configuration for the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_cors,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket cors!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_encryption(self, bucket_name: str):
        """
        Retrieve the encryption configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The encryption configuration of the bucket if it exists.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_encryption,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket encryption!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_intelligent_tiering_config(
            self,
            bucket_name: str,
            intelli_tier_config_id: str
    ):
        """
        Retrieves the Intelligent-Tiering configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.
            intelli_tier_config_id (str): The ID of the Intelligent-Tiering configuration to retrieve.

        Returns:
            dict: The Intelligent-Tiering configration details.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_intelligent_tiering_configuration,
                Bucket=bucket_name,
                Id=intelli_tier_config_id
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket intelli tier config!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_inventory_config(
            self,
            bucket_name: str,
            inventory_config_id: str
    ):
        """
        Retrieves the inventory configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.
            inventory_config_id (str): The ID of the inventory configuration to retrieve.

        Returns:
            dict: The inventory configuration details.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_inventory_configuration,
                Bucket=bucket_name,
                Id=inventory_config_id
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket inventory config!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_lifecycle_config(self, bucket_name: str):
        """
        Retrieves the lifecycle configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The lifecycle configuration of the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_lifecycle_configuration,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket lifecycle config!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_location(self, bucket_name: str):
        """
        Retrieves the region (location) of the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The location details of the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_location,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket location!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_logging(self, bucket_name: str):
        """
        Retrieves the logging configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The logging configration of the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_logging,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket logging!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_metadata_table_config(self, bucket_name: str):
        """
        Retrieves the metadata table configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The metadata table configuration of the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_metadata_table_configuration,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket metadata table config!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_metrics_config(
            self,
            bucket_name: str,
            metrics_config_id: str
    ):

        """
        Retrieves the metrics configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.
            metrics_config_id (str): The ID of the metrics configuration to retrieve.

        Returns:
            dict: The metrics configuration details of the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_metrics_configuration,
                Bucket=bucket_name,
                Id=metrics_config_id
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket metrics config!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_notification_config(self, bucket_name: str):
        """
        Retrieves the notification configuration of the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The notification configuration details of the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_notification_configuration,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket notification config!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_ownership_controls(self, bucket_name: str):
        """
        Retrieves the ownership controls configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The ownership controls configuration of the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_ownership_controls,
                Bucket=bucket_name
            )
        except  (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket ownership controls!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_policy(self, bucket_name: str):
        """
        Retrieve the bucket policy for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The bucket policy as a dictionary if it exists.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_policy,
                Bucket=bucket_name
            )
        except (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket policy!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_policy_status(self, bucket_name: str):
        """
        Retrieves the policy status of the specified S3 bucket to determine if it is public.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The policy status of the bucket, including whether the bucket is publicly accessible.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_policy_status,
                Bucket=bucket_name
            )
        except (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket policy status!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_replication(self, bucket_name: str):
        """
        Retrieves the replication configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The replication configuration of the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_replication,
                Bucket=bucket_name
            )
        except (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket replication!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_req_payment(self, bucket_name: str):
        """
        Retrieves the request payment configuration for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: The request payment configuration, indicating who pays for the data access (bucket owner or requester)
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_request_payment,
                Bucket=bucket_name
            )
        except (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket request payment!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_tagging(self, bucket_name: str):
        """
        Retrieves the tag set for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: A dictionary containing the tags assigned to the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_tagging,
                Bucket=bucket_name
            )
        except (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket tagging!', exc_info=ex)
            return {}

    @tool
    async def get_bucket_versioning(self, bucket_name: str):
        """
        Retrieves the versioning information for the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.

        Returns:
            dict: A dictionary containing the versioning information for the bucket.
        """
        try:
            return await sync_to_async(
                self._storage.get_bucket_versioning,
                Bucket=bucket_name
            )
        except (NoCredentialsError, ClientError) as ex:
            logger.error('Error get bucket versioning!', exc_info=ex)
            return {}

    @tool
    async def get_all_buckets_info(self):
        """
        Retrieves detailed information for all S3 buckets in the AWS account.

        For each bucket, this method gathers:
        - Bucket name and creation date
        - Bucket policy (if any)
        - Bucket encryption configuration (if any)
        - Public accessibility status (based on Block Public Access and bucket ACL)

        Utilizes various `get_bucket_*` methods from the boto3 S3 client such as:
        - `get_bucket_policy`
        - `get_bucket_encryption`
        - `get_bucket_acl`
        - `get_public_access_block`

        Returns:
            list: A list of dictionaries containing bucket name and associated properties.
        """
        buckets_info = []
        _list_buckets = await self.list_buckets()
        buckets = _list_buckets.get('Buckets') if _list_buckets else []

        async for bucket in iter_to_aiter(buckets):
            bucket_name = bucket.get('Name')
            buckets_info.append({
                'accelerate_configuration': await self.get_bucket_accelerate_config(bucket_name=bucket_name),
                'acl': await self.get_bucket_acl(bucket_name=bucket_name),
                'cors': await self.get_bucket_cors(bucket_name=bucket_name),
                'encryption': await self.get_bucket_encryption(bucket_name=bucket_name),
                'life_cycle_configuration': await self.get_bucket_lifecycle_config(bucket_name=bucket_name),
                'location': await self.get_bucket_location(bucket_name=bucket_name),
                'logging': await self.get_bucket_logging(bucket_name=bucket_name),
                'metadata_table_configuration': await self.get_bucket_metadata_table_config(bucket_name=bucket_name),
                'notification_configuration': await self.get_bucket_notification_config(bucket_name=bucket_name),
                'ownership_controls': await self.get_bucket_ownership_controls(bucket_name=bucket_name),
                'policy': await self.get_bucket_policy(bucket_name=bucket_name),
                'policy_status': await self.get_bucket_policy_status(bucket_name=bucket_name),
                'replication': await self.get_bucket_replication(bucket_name=bucket_name),
                'request_payment': await self.get_bucket_req_payment(bucket_name=bucket_name),
                'tagging': await self.get_bucket_tagging(bucket_name=bucket_name),
                'versioning': await self.get_bucket_versioning(bucket_name=bucket_name)
            })
        return buckets_info

    @tool
    async def list_files(
            self,
            bucket_name: str,
            prefix: Optional[str] = None,
            delimiter: Optional[str] = None
    ):
        """
        Lists files (objects) in a S3 bucket under a specified prefix.

        Args:
            bucket_name (str): The name of the S3 bucket.
            prefix (str, optional): Limits the response to keys that begin with specified prefix. Defaults to None.
            delimiter (str, optional): A delimiter is used to groups keys. Defaults to None.

        Returns:
            list: A list of object keys that match the specific prefix and delimiter.
        """
        try:
            return await sync_to_async(
                self._storage.list_objects_v2,
                Bucket=bucket_name,
                Prefix=prefix,
                Delimiter=delimiter
            )
        except (NoCredentialsError, ClientError) as ex:
            logger.error('Error list files!', exc_info=ex)
            return []

    @tool
    async def get_file_info(
            self,
            bucket_name: str,
            file_name: str
    ):
        """
        Retrieves metadata and properties for the specific file (object) in the S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.
            file_name (str): The key (name) of the file in the bucket.

        Returns:
            dict: Metadata and properties of the specified file, such as size, content type and last modified date etc.
        """
        try:
            return await sync_to_async(
                self._storage.head_object,
                Bucket=bucket_name,
                Key=file_name
            )
        except (NoCredentialsError, ClientError) as ex:
            logger.error('Error get file info!', exc_info=ex)
            return {}

    @tool
    async def upload(
            self,
            filename_or_path: str,
            bucket_name: str,
            prefix: str = "",  # optional S3 prefix (recommended)
    ):
        """
        Upload a file or directory to an S3 bucket.

            This method supports uploading:
                - A single file (uploaded as one S3 object)

        Args:
            filename_or_path (str): Local file path or directory path to upload.
            bucket_name (str): Target S3 bucket name.
            prefix (str, optional): Optional S3 key prefix (folder path in S3).
                                    Example:
                                        "frontend/"
                                        "content/account/user/ui/"
                                    Defaults to empty string.


        """
        if not os.path.exists(filename_or_path):
            raise FileNotFoundError(f"Path not found: {filename_or_path}")

        loop = asyncio.get_running_loop()
        base_path = os.path.abspath(filename_or_path)

        async def _upload_file(local_path: str):
            # Always calculate key relative to base folder
            relative = os.path.relpath(local_path, base_path)
            key = os.path.join(prefix, relative).replace("\\", "/")

            content_type, _ = mimetypes.guess_type(local_path)

            extra_args = {
                "ContentType": content_type or "application/octet-stream",
            }

            # SPA cache rules
            if local_path.endswith("index.html"):
                extra_args["CacheControl"] = "no-cache, no-store, must-revalidate"
            else:
                extra_args["CacheControl"] = "public, max-age=31536000, immutable"

            async with UPLOAD_SEM:
                await loop.run_in_executor(
                    None,
                    self._storage.upload_file,
                    local_path,
                    bucket_name,
                    key,
                    extra_args,
                )

        # ---------- SINGLE FILE ----------
        if os.path.isfile(base_path):
            await _upload_file(base_path)
            return {"type": "file", "key": base_path}

        # ---------- FOLDER ----------
        tasks = []
        for root, _, files in os.walk(base_path):
            for name in files:
                tasks.append(_upload_file(os.path.join(root, name)))

                # prevent task explosion
                if len(tasks) >= 50:
                    await asyncio.gather(*tasks)
                    tasks.clear()

        if tasks:
            await asyncio.gather(*tasks)

        return {
            "type": "folder",
            "bucket": bucket_name,
            "prefix": prefix,
            "status": "uploaded",
        }

    @tool
    async def download_file(
            self,
            object_name: str,
            bucket_name: str,
            file_name: Optional[str] = None
    ):
        """
        Asynchronously downloads a file from an S3 bucket to a local path.
        This method facilitates the retrieval of stored data from AWS S3, allowing users to access their files conveniently.

        Args:
            file_name (str): The name of the file to be uploaded, including its path.
            bucket_name (str): The name of the bucket to be saved.
            object_name (str | None, optional): The name to assign to the object in the S3 bucket.
        """

        if not file_name:
            file_name = object_name
        try:
            await sync_to_async(self._storage.download_file,
                Bucket=bucket_name,
                Key=object_name,
                Filename=file_name
            )
            logger.info(f"File '{file_name}' downloaded from '{bucket_name}'.")
        except (NoCredentialsError, ClientError) as ex:
            logger.error(f'File {file_name} download failed!', exc_info=ex)
