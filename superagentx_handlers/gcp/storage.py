import json
import logging
import os
from typing import Optional

from google.api_core import iam
from google.cloud import exceptions as gc_exc
from google.cloud import storage
from google.cloud.storage import Bucket, Blob
from google.cloud.storage.notification import BucketNotification
from google.oauth2 import service_account
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

logger = logging.getLogger(__name__)

async def bucket_to_dict(bucket: Bucket) -> dict:
    return {
        'name': bucket.name,
        'created': bucket.time_created,
        'autoclass_enabled': bucket.autoclass_enabled,
        'autoclass_terminal_storage_class': bucket.autoclass_terminal_storage_class,
        'autoclass_terminal_storage_class_update_time': bucket.autoclass_terminal_storage_class_update_time,
        'autoclass_toggle_time': bucket.autoclass_toggle_time,
        'cors': bucket.cors,
        'data_locations': bucket.data_locations,
        'default_kms_key_name': bucket.default_kms_key_name,
        'etag': bucket.etag,
        'generation': bucket.generation,
        'hard_delete_time': bucket.hard_delete_time,
        'hierarchical_namespace_enabled': bucket.hierarchical_namespace_enabled,
        'id': bucket.id,
        'labels': bucket.labels,
        'lifecycle_rules': dict(bucket.lifecycle_rules),
        'location': bucket.location,
        'location_type': bucket.location_type,
        'metageneration': bucket.metageneration,
        'object_retention_mode': bucket.object_retention_mode,
        'owner': bucket.owner,
        'path': bucket.path,
        'project_number': bucket.project_number,
        'requester_pays': bucket.requester_pays,
        'retention_period': bucket.retention_period,
        'retention_policy_effective_time': bucket.retention_policy_effective_time,
        'retention_policy_locked': bucket.retention_policy_locked,
        'rpo': bucket.rpo,
        'self_link': bucket.self_link,
        'soft_delete_time': bucket.soft_delete_time,
        'storage_class': bucket.storage_class,
        'time_created': bucket.time_created,
        'updated': bucket.updated,
        'versioning_enabled': bucket.versioning_enabled
    }


async def blob_to_dict(blob: Blob) -> dict:
    return {
        'chunk_size': blob.chunk_size,
        'component_count': blob.component_count,
        'content_disposition': blob.content_disposition,
        'content_encoding': blob.content_encoding,
        'content_language': blob.content_language,
        'content_type': blob.content_type,
        'custom_time': blob.custom_time,
        'etag': blob.etag,
        'hard_delete_time': blob.hard_delete_time,
        'id': blob.id,
        'kms_key_name': blob.kms_key_name,
        'media_link': blob.media_link,
        'metadata': blob.metadata,
        'metageneration': blob.metageneration,
        'owner': blob.owner,
        'path': blob.path,
        'retention_expiration_time': blob.retention_expiration_time,
        'size': blob.size,
        'soft_delete_time': blob.soft_delete_time,
        'storage_class': blob.storage_class,
        'time_created': blob.time_created,
        'time_deleted': blob.time_deleted,
        'updated': blob.updated
    }

# Extensive comments are required!

class GCPStorageHandler(BaseHandler):

    def __init__(
            self,
            service_account_info : dict | str | None = None,
    ):
        super().__init__()
        if service_account_info:
            if isinstance(service_account_info, str):
                service_account_info = json.loads(service_account_info)
            _credentials = service_account.Credentials.from_service_account_info(info=service_account_info)
        else:
            _creds_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
            _credentials = service_account.Credentials.from_service_account_file(filename=_creds_path)

        self._storage = storage.Client(
            project=service_account_info.get('project_id'),
            credentials=_credentials
        )

    @tool
    async def list_buckets(self):
        """
        Retrieves a list of all buckets in the specified Google Storage.
        """
        try:
            bucket_objs = await sync_to_async(self._storage.list_buckets)
            return [
                await bucket_to_dict(bucket)
                async for bucket in iter_to_aiter(bucket_objs)
            ]
        except (gc_exc.ClientError, gc_exc.Forbidden) as ex:
            logger.error(f"Error list buckets!", exc_info=ex)
            return []

    @tool
    async def get_bucket(self, bucket_name: str):
        """
        Retrieves the bucket information for the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            dict: The bucket information if available.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return await bucket_to_dict(bucket)
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket!", exc_info=ex)
            return {}

    @tool
    async def get_bucket_acl(self, bucket_name: str):
        """
        Retrieves the Access Control List (ACL) for the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            list: The list containing the bucket's ACL information.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return list(bucket.acl)
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket acl!", exc_info=ex)
            return []

    @tool
    async def get_bucket_cors(self, bucket_name: str):
        """
        Retrieves the Cross-Origin Resource Sharing (CORS) configuration for the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            list: The CORS configuration for the bucket.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return bucket.cors
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket cors!", exc_info=ex)
            return []

    @tool
    async def get_bucket_encryption(self, bucket_name: str):
        """
        Retrieves the encryption key name for the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            str: The encryption key name of the bucket if it exists.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return bucket.default_kms_key_name
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket encryption!", exc_info=ex)

    @tool
    async def get_bucket_labels(self, bucket_name: str):
        """
        Retrieves the label set for the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            dict: A dictionary containing the labels assigned to the bucket.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return bucket.labels
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket labels!", exc_info=ex)

    @tool
    async def get_bucket_lifecycle_rules(self, bucket_name: str):
        """
        Retrieves the lifecycle rules for the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            dic: The lifecycle rules of the bucket.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return dict(bucket.lifecycle_rules)
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket lifecycle rules!", exc_info=ex)
            return {}

    @tool
    async def get_bucket_location(self, bucket_name: str):
        """
        Retrieves the location of the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            str: The location of the bucket.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return bucket.location
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket location!", exc_info=ex)

    @tool
    async def get_bucket_logging(self, bucket_name: str):
        """
        Retrieves the logging configuration for the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            dict: The logging configuration of the bucket.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return await sync_to_async(bucket.get_logging)
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket logging!", exc_info=ex)

    @tool
    async def get_bucket_notification_config(self, bucket_name: str):
        """
        Retrieves the notification configuration of the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            list: The notification configuration details of the bucket.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            notifications: list[BucketNotification] = await sync_to_async(bucket.list_notifications)
            return [
                {
                    'topic_name': notification.topic_name,
                    'topic_project': notification.topic_project,
                    'custom_attributes': notification.custom_attributes,
                    'event_types': notification.event_types,
                    'blob_name_prefix': notification.blob_name_prefix,
                    'payload_format': notification.payload_format,
                    'notification_id': notification.notification_id
                }
                for notification in notifications
            ]
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket notification!", exc_info=ex)
            return []

    @tool
    async def get_bucket_owner(self, bucket_name: str):
        """
        Retrieves the ownership configuration for the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            dict: The ownership configuration of the bucket.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            return bucket.owner
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket owner!", exc_info=ex)
            return {}

    @tool
    async def get_bucket_iam_policy(self, bucket_name: str):
        """
        Retrieves the bucket IAM policy of the specified Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.

        Returns:
            dict: The bucket IAM policy as dictionary if it exists.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            policy: iam.Policy = await sync_to_async(bucket.get_iam_policy)
            return {
                "version": policy.version,
                "bindings": policy.bindings,
                "etag": policy.etag
            }
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get bucket iam policy!", exc_info=ex)
            return {}

    @tool
    async def get_all_buckets_info(self):
        """
        Retrieves a list of all buckets and its properties in the specified Google Storage account.

        Returns:
            list: List of buckets and its properties.
        """
        buckets_info = []
        async for bucket in iter_to_aiter(await self.list_buckets()):
            bucket_name = bucket.get('name')
            bucket.update({
                'acl': await self.get_bucket_acl(bucket_name=bucket_name),
                'encryption': await self.get_bucket_encryption(bucket_name=bucket_name),
                'logging': await self.get_bucket_logging(bucket_name=bucket_name),
                'notification_configuration': await self.get_bucket_notification_config(bucket_name=bucket_name),
                'iam': await self.get_bucket_iam_policy(bucket_name=bucket_name)
            })
            buckets_info.append(bucket)
        return buckets_info

    @tool
    async def list_files(
            self,
            bucket_name: str,
            prefix: Optional[str] = None,
            delimiter: Optional[str] = None
    ):
        """
        Lists files (blobs) in a Google Storage bucket under a specified prefix.

        Args:
            bucket_name (str): The name of the Google Storage bucket.
            prefix (str, optional): Limits the response to keys that begin with specified prefix. Defaults to None.
            delimiter (str, optional): A delimiter is used to groups blobs. Defaults to None.

        Returns:
            list: A list of blobs that match the specific prefix and delimiter.
        """
        try:
            blobs = await sync_to_async(
                self._storage.list_blobs,
                bucket_name,
                prefix=prefix,
                delimiter=delimiter
            )
            return [
                await blob_to_dict(blob=blob)
                async for blob in iter_to_aiter(blobs)
            ]
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error list files!", exc_info=ex)
            return []

    @tool
    async def get_file_info(
            self,
            bucket_name: str,
            file_name: str
    ):
        """
        Retrieves metadata and properties for the specific file (blob) in the Storage bucket.

        Args:
            bucket_name (str): The name of the Google Storage bucket.
            file_name (str): The blob (name) of the file in the bucket.

        Returns:
            dict: Metadata and properties of the specified file, such as size, content type and last modified date etc.
        """
        try:
            bucket = await sync_to_async(self._storage.get_bucket, bucket_name)
            blob = await sync_to_async(bucket.get_blob, blob_name=file_name)
            return await blob_to_dict(blob=blob)
        except (gc_exc.ClientError, gc_exc.Forbidden, gc_exc.NotFound) as ex:
            logger.error(f"Error get file info!", exc_info=ex)
            return {}
