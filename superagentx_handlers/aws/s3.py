import logging

import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class AWSS3Handler(BaseHandler):
    """
    A handler class for managing interactions with Amazon S3 (Simple Storage Service).
    This class extends BaseHandler and provides methods for uploading, downloading, deleting,
    and managing objects in S3 buckets, facilitating efficient storage and retrieval of data in the cloud.
    """

    def __init__(
            self,
            aws_access_key_id: str,
            aws_secret_access_key: str,
            bucket_name: str | None = None,
            region_name: str | None = None
    ):
        super().__init__()
        self.bucket_name = bucket_name
        self.region = region_name
        self._storage = boto3.client(
           's3',
            region_name=self.region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

    @tool
    async def list_buckets(self):
        """
        Asynchronously retrieves a list of all objects in the specified S3 bucket.
        This method provides an overview of the contents stored in the bucket, facilitating data management
        and organization.
        """
        try:
            return await sync_to_async(self._storage.list_buckets)
        except (NoCredentialsError, ClientError) as ex:
            _msg = "Error listing files"
            logger.error(_msg, exc_info=ex)
            return []

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
            _msg = 'Error get bucket accelerate config!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket acl!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket analytics configuration!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket cors!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket encryption!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket intelli tier config!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket inventory config!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket lifecycle config!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket location!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket logging!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket metadata table config!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket metrics config!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket notification config!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket ownership controls!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket policy!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket policy status!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket replication!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket request payment!'
            logger.error(_msg, exc_info=ex)
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
            _msg = 'Error get bucket tagging!'
            logger.error(_msg, exc_info=ex)
            return {}

    @tool
    async def upload_file(
            self,
            file_name: str,
            object_name: str | None = None
    ):
        """
        Asynchronously uploads a file to an S3 bucket, specifying the file name and optional object name in the bucket.
        This method facilitates the storage of files in AWS S3, allowing users to manage their cloud data effectively.

        Args:
           file_name (str): The name of the file to be uploaded, including its path.
           object_name (str | None, optional): The name to assign to the object in the S3 bucket.
           If None, the object name will default to the file name. Defaults to None.
        """

        if not object_name:
            object_name = file_name
        try:
            await sync_to_async(self._storage.upload_file,
                Filename=file_name,
                Bucket=self.bucket_name,
                Key=object_name
            )
            logger.info(f"File '{file_name}' uploaded to '{self.bucket_name}/{object_name}'.")
        except (FileNotFoundError, NoCredentialsError, ClientError) as ex:
            _msg = f'File {file_name} upload failed!'
            logger.error(_msg, exc_info=ex)

    @tool
    async def download_file(
            self,
            object_name: str,
            file_name: str | None = None
    ):
        """
        Asynchronously downloads a file from an S3 bucket to a local path.
        This method facilitates the retrieval of stored data from AWS S3, allowing users to access their files conveniently.

        Args:
            file_name (str): The name of the file to be uploaded, including its path.
            object_name (str | None, optional): The name to assign to the object in the S3 bucket.
        """

        if not file_name:
            file_name = object_name
        try:
            await sync_to_async(self._storage.download_file,
                Bucket=self.bucket_name,
                Key=object_name,
                Filename=file_name
            )
            logger.info(f"File '{file_name}' downloaded from '{self.bucket_name}/{object_name}'.")
        except (NoCredentialsError, ClientError) as ex:
            _msg = f'File {file_name} download failed!'
            logger.error(_msg, exc_info=ex)
