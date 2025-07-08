import os
import base64
import asyncio
import json
import logging # Import the logging module

from google.oauth2 import service_account
from google.cloud import storage # Import the Google Cloud Storage client library
from google.api_core import exceptions
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

# Configure logging for the module
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Extensive comments are required!

class GcpStorageInfoCollector(BaseHandler):
    """
    A handler class to collect comprehensive information about GCP Cloud Storage
    buckets and objects. This class extends BaseHandler and provides methods
    for retrieving bucket properties, object metadata, and associated IAM policies.
    It focuses on 'get' operations for information collection.
    """

    def __init__(
            self,
            creds : str | None = None,
            scope : list | None = None
    ):
        """
        Initializes the GCP Storage Info Collector with an authenticated client.
        It expects the path to a service account key file in the
        GCP_AGENT_CREDENTIALS environment variable.
        """
        super().__init__()
        if not scope:
            scope = ["https://www.googleapis.com/auth/cloud-platform"]
        try:
            creds_path = creds or os.getenv("GCP_AGENT_CREDENTIALS")
            if not creds_path:
                raise ValueError(
                    "GCP_AGENT_CREDENTIALS environment variable is not set. "
                    "Please set it to the path of your service account key file."
                )

            # Load credentials file to extract project_id
            with open(creds_path, 'r') as f:
                creds_dict = json.load(f)
                # Store project_id as an instance variable, accessible by other methods
                self.project_from_creds = creds_dict.get("project_id")

            # Load credentials from file path with appropriate scopes.
            # 'cloud-platform' scope grants broad access to Google Cloud resources.
            credentials = service_account.Credentials.from_service_account_file(
                creds_path,
                scopes=scope
            )

            # Initialize the Cloud Storage client with custom credentials.
            self.storage_client = storage.Client(credentials=credentials)

            logger.info("GCP Cloud Storage client initialized with custom service account credentials.")
            if self.project_from_creds:
                logger.info(f"Default project ID from credentials: '{self.project_from_creds}'")
            else:
                logger.warning("Could not determine default project ID from credentials file.")

        except FileNotFoundError:
            logger.error(f"Credentials file not found at: {creds_path}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in credentials file: {creds_path}")
            raise
        except Exception as e:
            logger.error(
                f"Error initializing GCP Storage client: {e}\n"
                "Please ensure the GCP_AGENT_CREDENTIALS environment variable points to a valid service account key file, "
                "and that the service account has necessary permissions (e.g., storage.buckets.list, storage.buckets.get, "
                "storage.objects.list, storage.objects.get, storage.buckets.getIamPolicy)."
            )
            raise

    def _get_bucket_iam_policy(self, bucket_name: str) -> dict:
        """
        Helper method to fetch the IAM policy for a given Cloud Storage bucket.

        Args:
            bucket_name (str): The name of the bucket (e.g., "my-unique-bucket-name").

        Returns:
            dict: The IAM policy as a dictionary if found, otherwise None.
        """
        policy_details = None
        try:
            bucket = self.storage_client.get_bucket(bucket_name)
            # Get the IAM policy for the bucket.
            # This requires 'storage.buckets.getIamPolicy' permission on the bucket.
            policy = bucket.get_iam_policy()

            # Convert the policy object to a dictionary for easier consumption.
            # The etag is bytes, so encode it to base64 and then decode to string for safe representation.
            etag_string = base64.b64encode(policy.etag).decode('utf-8') if policy.etag else ''

            policy_details = {
                "version": policy.version,
                "etag": etag_string,
                "bindings": []
            }
            # Iterate through bindings (roles and members) and add them to the policy_details.
            for binding in policy.bindings:
                binding_info = {
                    "role": binding.role,
                    "members": list(binding.members),
                }
                # Add condition if it exists.
                if binding.condition:
                    binding_info["condition"] = {
                        "expression": binding.condition.expression,
                        "title": binding.condition.title,
                        "description": binding.condition.description
                    }
                policy_details["bindings"].append(binding_info)
            logger.info(f"  Successfully retrieved IAM policy for bucket: {bucket_name}")
        except exceptions.NotFound:
            logger.warning(f"  Bucket '{bucket_name}' not found for IAM policy retrieval.")
        except exceptions.Forbidden as e:
            logger.error(f"  Permission denied to get IAM policy for bucket '{bucket_name}'. Error: {e}")
        except Exception as e:
            logger.error(f"  An unexpected error occurred while getting IAM policy for bucket '{bucket_name}'. Error: {e}", exc_info=True)
        return policy_details

    @tool
    async def get_bucket_details(self, bucket_name: str, project_id: str = None) -> dict:
        """
        Fetches comprehensive details for a single Cloud Storage bucket.

        Args:
            bucket_name (str): The name of the bucket to retrieve details for.
            project_id (str, optional): The ID of the GCP project the bucket belongs to.
                                        Defaults to the project ID from credentials if None.

        Returns:
            dict: A dictionary containing bucket properties and its IAM policy.
        """
        target_project_id = project_id or self.project_from_creds
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot get bucket details.")
            return None

        logger.info(f"  Fetching details for bucket: {bucket_name} in project: {target_project_id}")
        bucket_info = {}
        try:
            # Ensure the client is associated with the target project if specified
            # The storage client is initialized with credentials that might be project-specific
            # or organization-wide. For get_bucket, the bucket name is globally unique,
            # but specifying project_id can help with context or if the bucket is new.
            bucket = self.storage_client.get_bucket(bucket_name)

            # Verify the bucket is in the target project if project_id was explicitly provided
            if project_id and bucket.project != project_id:
                logger.warning(f"Bucket '{bucket_name}' found but belongs to project '{bucket.project}', not '{project_id}'. Returning details for actual project.")

            bucket_info = {
                "name": bucket.name,
                "project": bucket.project,
                "location": bucket.location,
                "storage_class": bucket.storage_class,
                "time_created": bucket.time_created.isoformat() if bucket.time_created else None,
                "updated": bucket.updated.isoformat() if bucket.updated else None,
                "versioning_enabled": bucket.versioning_enabled,
                "requester_pays": bucket.requester_pays,
                "lifecycle_rules": [rule.to_api_repr() for rule in bucket.lifecycle_rules] if bucket.lifecycle_rules else [],
                "labels": bucket.labels,
                "logging_config": {
                    "logBucket": bucket.logging.log_bucket,
                    "logObjectPrefix": bucket.logging.log_object_prefix
                } if bucket.logging else None,
                "iam_policy": self._get_bucket_iam_policy(bucket_name)
            }
            logger.info(f"  Successfully retrieved details for bucket: {bucket_name}")
        except exceptions.NotFound:
            logger.warning(f"  Bucket '{bucket_name}' not found.")
            return None
        except exceptions.Forbidden as e:
            logger.error(f"  Permission denied to get details for bucket '{bucket_name}'. Error: {e}")
            return None
        except Exception as e:
            logger.error(f"  An unexpected error occurred while fetching bucket details for '{bucket_name}'. Error: {e}", exc_info=True)
        return bucket_info

    @tool
    async def list_objects_in_bucket(self, bucket_name: str, prefix: str = None, project_id: str = None) -> list:
        """
        Lists objects within a given Cloud Storage bucket and retrieves their metadata.

        Args:
            bucket_name (str): The name of the bucket.
            prefix (str, optional): A prefix to filter objects by name.
            project_id (str, optional): The ID of the GCP project the bucket belongs to.
                                        Defaults to the project ID from credentials if None.

        Returns:
            list: A list of dictionaries, where each dictionary contains object metadata.
        """
        target_project_id = project_id or self.project_from_creds
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot list objects.")
            return []

        logger.info(f"    Listing objects in bucket '{bucket_name}' with prefix '{prefix or ''}' in project '{target_project_id}'...")
        object_info_list = []
        try:
            bucket = self.storage_client.get_bucket(bucket_name)
            # List blobs (objects) in the bucket.
            # This requires 'storage.objects.list' permission on the bucket.
            blobs = bucket.list_blobs(prefix=prefix)

            for blob in blobs:
                object_metadata = {
                    "name": blob.name,
                    "size": blob.size,
                    "content_type": blob.content_type,
                    "time_created": blob.time_created.isoformat() if blob.time_created else None,
                    "updated": blob.updated.isoformat() if blob.updated else None,
                    "md5_hash": blob.md5_hash,
                    "crc32c": blob.crc32c,
                    "generation": blob.generation,
                    "metageneration": blob.metageneration,
                    "etag": base64.b64encode(blob.etag).decode('utf-8') if blob.etag else '', # Base64 encode etag
                    "storage_class": blob.storage_class,
                    "kms_key_name": blob.kms_key_name,
                    "event_based_hold": blob.event_based_hold,
                    "retention_expiration_time": blob.retention_expiration_time.isoformat() if blob.retention_expiration_time else None,
                    "custom_metadata": blob.metadata or {} # Custom metadata is in .metadata attribute
                }
                object_info_list.append(object_metadata)
            logger.info(f"    Successfully listed {len(object_info_list)} objects in bucket '{bucket_name}'.")
        except exceptions.NotFound:
            logger.warning(f"    Bucket '{bucket_name}' not found for object listing.")
        except exceptions.Forbidden as e:
            logger.error(f"    Permission denied to list objects in bucket '{bucket_name}'. Error: {e}")
        except Exception as e:
            logger.error(f"    An unexpected error occurred while listing objects in bucket '{bucket_name}'. Error: {e}", exc_info=True)
        return object_info_list

    @tool
    async def list_all_buckets(self, project_id: str = None) -> list:
        """
        Lists all accessible Cloud Storage buckets within a specified project.

        Args:
            project_id (str, optional): The ID of the GCP project to list buckets from.
                                        Defaults to the project ID from credentials if None.

        Returns:
            list: A list of dictionaries, where each dictionary contains basic bucket info.
        """
        target_project_id = project_id or self.project_from_creds
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot list buckets.")
            return []

        logger.info(f"\nListing all accessible buckets for project: {target_project_id}...")
        buckets_list = []
        try:
            # List all buckets accessible to the service account within the specified project.
            # This requires 'storage.buckets.list' permission.
            buckets = self.storage_client.list_buckets(project=target_project_id)
            for bucket in buckets:
                buckets_list.append({
                    "name": bucket.name,
                    "project": bucket.project,
                    "location": bucket.location,
                    "storage_class": bucket.storage_class,
                    "time_created": bucket.time_created.isoformat() if bucket.time_created else None,
                })
            logger.info(f"Successfully listed {len(buckets_list)} buckets in project '{target_project_id}'.")
        except exceptions.Forbidden as e:
            logger.error(f"Permission denied to list buckets in project '{target_project_id}'. Error: {e}")
            logger.error("Ensure the service account/user has 'storage.buckets.list' permission.")
        except Exception as e:
            logger.error(f"An unexpected error occurred while listing buckets: {e}", exc_info=True)
        return buckets_list

    @tool
    async def collect_all_storage_info(self, project_id: str = None) -> dict:
        """
        Collects comprehensive information for all accessible Cloud Storage buckets
        and their objects within a specified project. This method is exposed as a tool
        for the SuperagentX framework.

        Args:
            project_id (str, optional): The ID of the GCP project to collect storage info from.
                                        If None, the project ID from the service account credentials
                                        (if available) will be used as a default.

        Returns:
            dict: A dictionary containing lists of collected bucket and object information.
        """
        # Use the provided project_id, or fall back to the one from credentials
        target_project_id = project_id or self.project_from_creds

        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect Storage info.")
            return {
                "buckets": [],
                "objects_by_bucket": {}
            }

        all_storage_info = {
            "buckets": [],
            "objects_by_bucket": {}
        }

        logger.info(f"\nStarting comprehensive collection of Cloud Storage information for project: '{target_project_id}'...")

        try:
            # List all buckets using the dedicated tool function
            buckets_summary = await self.list_all_buckets(project_id=target_project_id)

            for bucket_summary in buckets_summary:
                bucket_name = bucket_summary['name']
                logger.info(f"\nProcessing Bucket: {bucket_name}")

                # Get detailed info for each bucket using the dedicated tool function
                bucket_details = await self.get_bucket_details(bucket_name, project_id=target_project_id)
                if bucket_details:
                    all_storage_info["buckets"].append(bucket_details)
                    # Also list objects within this bucket using the dedicated tool function
                    objects_in_bucket = await self.list_objects_in_bucket(bucket_name, project_id=target_project_id)
                    all_storage_info["objects_by_bucket"][bucket_name] = objects_in_bucket

        except Exception as e:
            logger.error(f"An unexpected error occurred during comprehensive Storage info collection: {e}", exc_info=True)

        return all_storage_info

