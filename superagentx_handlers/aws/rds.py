import logging
import os

import boto3

from botocore.exceptions import ClientError
from superagentx.utils.helper import sync_to_async, iter_to_aiter
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx_handlers.aws.ec2 import AWSEC2Handler

from superagentx_handlers.aws.helper import generate_aws_sts_token

logger = logging.getLogger(__name__)


async def format_datetime(dt):
    """Format datetime object to string"""
    if dt:
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    return 'N/A'


class AWSRDSHandler(BaseHandler):

    def __init__(
            self,
            aws_access_key_id: str | None = None,
            aws_secret_access_key: str | None = None,
            region_name: str | None = None
    ):
        super().__init__()
        region = region_name or os.getenv("AWS_REGION")
        aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")

        self.credentials = generate_aws_sts_token(
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        # Initialize AWS IAM client
        self.rds_client = boto3.client(
            'rds',
            **self.credentials
        )

        # Initialize AWS EC2 client
        self.ec2_client = boto3.client(
            'ec2',
            **self.credentials
        )

        self.ec2_handlers = AWSEC2Handler(
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

    @tool
    async def get_rds_association_details(self) -> dict:

        """
        This script provides a comprehensive read-only inventory of your AWS RDS resources.

        Features:

        ✅ Lists all RDS instances with detailed information
        ✅ Lists all RDS clusters (Aurora)
        ✅ Lists all RDS proxies with their targets
        ✅ Shows read replicas for both instances and clusters
        ✅ Displays backup configuration and retention periods
        ✅ Shows delete protection status
        ✅ Lists EC2 instances for potential RDS associations
        ✅ Provides a summary with counts
        """

        instances = await self.get_rds_instances() or []
        clusters = await self.get_rds_clusters() or []
        proxies = await self.get_rds_proxies() or []
        ec2_instances = await self.get_ec2_associations() or []

        protected_instances = len([inst for inst in instances if inst.get('DeletionProtection', False)])
        protected_clusters = len([cluster for cluster in clusters if cluster.get('DeletionProtection', False)])
        total_replicas = sum(len(inst.get('ReadReplicaDBInstanceIdentifiers', [])) for inst in instances)
        total_cluster_replicas = sum(len(cluster.get('ReadReplicaIdentifiers', [])) for cluster in clusters)

        response = {
            "rds_instances": instances,
            "rds_clusters": clusters,
            "rds_proxies": proxies,
            "ec2_associations": ec2_instances,
            "summary": {
                "protected_instances_count": protected_instances,
                "protected_clusters_count": protected_clusters,
                "total_instance_replicas": total_replicas,
                "total_cluster_replicas": total_cluster_replicas
            }
        }

        return response

    async def get_rds_instances(self):
        """Get all RDS instances"""
        try:
            response = await sync_to_async(self.rds_client.describe_db_instances)
            return response.get("DBInstances", [])
        except ClientError as e:
            logger.error(f"Error getting RDS instances: {e}")
            return []

    async def get_rds_clusters(self):
        """Get all RDS clusters"""
        try:
            response = await sync_to_async(self.rds_client.describe_db_clusters)
            return response.get("DBClusters", [])
        except ClientError as e:
            logger.error(f"Error getting RDS clusters: {e}")
            return []

    async def get_rds_proxies(self):
        """Get all RDS proxies"""
        try:
            response = await sync_to_async(self.rds_client.describe_db_proxies)
            return response.get("DBProxies", [])
        except ClientError as e:
            logger.error(f"Error getting RDS proxies: {e}")
            return []

    async def get_proxy_targets(
            self,
            proxy_name: str
    ):
        """Get targets for a specific RDS proxy"""
        try:
            response = await sync_to_async(
                self.rds_client.describe_db_proxy_targets,
                DBProxyName=proxy_name
            )
            return response.get("Targets", [])
        except ClientError as e:
            logger.error(f"Error getting proxy targets for {proxy_name}: {e}")
            return []

    async def get_ec2_associations(self):
        """Get EC2 instances to check for RDS associations"""
        try:
            response = await sync_to_async(self.ec2_client.describe_instances)
            return [
                {
                    'InstanceId': instance['InstanceId'],
                    'InstanceType': instance['InstanceType'],
                    'State': instance['State']['Name'],
                    'VpcId': instance.get('VpcId', 'N/A'),
                    'SubnetId': instance.get('SubnetId', 'N/A'),
                    'SecurityGroups': await self.ec2_handlers.get_security_groups(
                        group_ids=[sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    )
                }
                async for reservation in iter_to_aiter(response.get("Reservations"))
                async for instance in iter_to_aiter(reservation.get("Instances"))
            ]
        except ClientError as e:
            logger.error(f"Error getting EC2 instances: {e}")
            return []

    async def get_backup_config(
            self,
            db_identifier: str,
            is_cluster: bool = False
    ):
        """Get backup configuration for RDS instance or cluster"""
        try:
            if is_cluster:
                response = await sync_to_async(
                    self.rds_client.describe_db_clusters,
                    DBClusterIdentifier=db_identifier
                )
                clusters = response.get("DBClusters", [])
                if clusters:
                    cluster = clusters[0]
                else:
                    # handle case (log or raise a custom error)
                    cluster = None
                return {
                    'BackupRetentionPeriod': cluster.get('BackupRetentionPeriod', 0),
                    'PreferredBackupWindow': cluster.get('PreferredBackupWindow', 'N/A'),
                    'PreferredMaintenanceWindow': cluster.get('PreferredMaintenanceWindow', 'N/A'),
                    'BackupType': 'Cluster'
                }
            else:
                response = await sync_to_async(
                    self.rds_client.describe_db_instances,
                    DBInstanceIdentifier=db_identifier
                )
                instances = response.get("DBInstances", [])
                if instances:
                    instance = instances[0]
                else:
                    # handle case (log or raise a custom error)
                    instance = {}
                return {
                    'BackupRetentionPeriod': instance.get('BackupRetentionPeriod', 0),
                    'PreferredBackupWindow': instance.get('PreferredBackupWindow', 'N/A'),
                    'PreferredMaintenanceWindow': instance.get('PreferredMaintenanceWindow', 'N/A'),
                    'BackupType': 'Instance'
                }
        except ClientError as e:
            logger.error(f"Error getting backup config for {db_identifier}: {e}")
            return {}
