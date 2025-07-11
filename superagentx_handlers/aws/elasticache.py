import logging
import os

import boto3

from superagentx_handlers.aws.helper import generate_aws_sts_token
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from botocore.exceptions import ClientError, NoCredentialsError
from superagentx.utils.helper import sync_to_async, iter_to_aiter

logger = logging.getLogger(__name__)


class AWSElasticCacheHandler(BaseHandler):

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

        # Initialize ElasticCache client
        self.elasticache_client = boto3.client(
            'elasticache',
            **self.credentials
        )

        # Initialize AWS EC2 client
        self.ec2_client = boto3.client(
            'ec2',
            **self.credentials
        )

    @tool
    async def get_elastic_cache_details(self) -> dict:
        """
          List all ElastiCache clusters with their VPC and Security Groups information.
          Returns a dictionary containing all the information.
        """
        try:
            result = {
                'clusters': [],
                'replication_groups': [],
                'subnet_groups': [],
                'security_groups': [],
                'vpcs': [],
                'serverless': []
            }

            # Get all ElasticCache clusters
            logger.info(f"Fetching ElastiCache clusters...")
            clusters_response = await sync_to_async(
                self.elasticache_client.describe_cache_clusters,
                ShowCacheNodeInfo=True
            )

            async for cluster in iter_to_aiter(clusters_response['CacheClusters']):
                cluster_info = {
                    'cluster_id': cluster['CacheClusterId'],
                    'engine': cluster['Engine'],
                    'engine_version': cluster['EngineVersion'],
                    'status': cluster['CacheClusterStatus'],
                    'node_type': cluster['CacheNodeType'],
                    'num_cache_nodes': cluster['NumCacheNodes'],
                    'security_groups': cluster.get('SecurityGroups', []),
                    'cache_subnet_group_name': cluster.get('CacheSubnetGroupName'),
                    'vpc_id': None,
                    'availability_zone': cluster.get('PreferredAvailabilityZone'),
                    'replication_group_id': cluster.get('ReplicationGroupId')
                }
                result['clusters'].append(cluster_info)

            # Get all ElastiCache replication groups
            logger.info(f"Fetching ElastiCache replication groups...")
            replication_groups_response = await sync_to_async(self.elasticache_client.describe_replication_groups)

            async for rep_group in iter_to_aiter(replication_groups_response['ReplicationGroups']):
                rep_group_info = {
                    'replication_group_id': rep_group['ReplicationGroupId'],
                    'description': rep_group['Description'],
                    'status': rep_group['Status'],
                    'cache_node_type': rep_group.get('CacheNodeType'),
                    'engine': rep_group.get('Engine'),
                    'engine_version': rep_group.get('EngineVersion'),
                    'security_groups': rep_group.get('SecurityGroups', []),
                    'cache_subnet_group_name': rep_group.get('CacheSubnetGroupName'),
                    'vpc_id': None,
                    'member_clusters': rep_group.get('MemberClusters', [])
                }
                result['replication_groups'].append(rep_group_info)

            # Get all cache subnet groups to determine VPC information
            logger.info(f"Fetching ElastiCache subnet groups...")
            subnet_groups_response = await sync_to_async(self.elasticache_client.describe_cache_subnet_groups)

            subnet_group_vpc_mapping = {}
            async for subnet_group in iter_to_aiter(subnet_groups_response['CacheSubnetGroups']):
                subnet_group_info = {
                    'name': subnet_group['CacheSubnetGroupName'],
                    'description': subnet_group['CacheSubnetGroupDescription'],
                    'vpc_id': subnet_group['VpcId'],
                    'subnets': []
                }

                async for subnet in iter_to_aiter(subnet_group['Subnets']):
                    subnet_info = {
                        'subnet_id': subnet['SubnetIdentifier'],
                        'availability_zone': subnet['SubnetAvailabilityZone']['Name']
                    }
                    subnet_group_info['subnets'].append(subnet_info)

                result['subnet_groups'].append(subnet_group_info)
                subnet_group_vpc_mapping[subnet_group['CacheSubnetGroupName']] = subnet_group['VpcId']

            # Update clusters and replication groups with VPC information
            async for cluster in iter_to_aiter(result['clusters']):
                if cluster['cache_subnet_group_name']:
                    cluster['vpc_id'] = subnet_group_vpc_mapping.get(cluster['cache_subnet_group_name'])

            async for rep_group in iter_to_aiter(result['replication_groups']):
                if rep_group['cache_subnet_group_name']:
                    rep_group['vpc_id'] = subnet_group_vpc_mapping.get(rep_group['cache_subnet_group_name'])

            # Get unique security group IDs
            security_group_ids = set()
            async for cluster in iter_to_aiter(result['clusters']):
                for sg in cluster['security_groups']:
                    security_group_ids.add(sg['SecurityGroupId'])

            async for rep_group in iter_to_aiter(result['replication_groups']):
                async for sg in iter_to_aiter(rep_group['security_groups']):
                    security_group_ids.add(sg['SecurityGroupId'])

            # Get security group details
            if security_group_ids:
                logger.info(f"Fetching security groups information...")
                try:
                    security_groups_response = await sync_to_async(self.ec2_client.describe_security_groups,
                                                                   GroupIds=list(security_group_ids)
                                                                   )
                    async for sg in iter_to_aiter(security_groups_response['SecurityGroups']):
                        sg_info = {
                            'group_id': sg['GroupId'],
                            'group_name': sg['GroupName'],
                            'description': sg['Description'],
                            'vpc_id': sg.get('VpcId'),
                            'inbound_rules': [],
                            'outbound_rules': []
                        }

                        # Process inbound rules
                        async for rule in iter_to_aiter(sg.get('IpPermissions', [])):
                            rule_info = {
                                'protocol': rule.get('IpProtocol'),
                                'from_port': rule.get('FromPort'),
                                'to_port': rule.get('ToPort'),
                                'sources': []
                            }

                            async for ip_range in iter_to_aiter(rule.get('IpRanges', [])):
                                rule_info['sources'].append({'type': 'cidr', 'value': ip_range.get('CidrIp')})

                            async for sg_ref in iter_to_aiter(rule.get('UserIdGroupPairs', [])):
                                rule_info['sources'].append({'type': 'security_group', 'value': sg_ref.get('GroupId')})

                            sg_info['inbound_rules'].append(rule_info)

                        # Process outbound rules
                        async for rule in iter_to_aiter(sg.get('IpPermissionsEgress', [])):
                            rule_info = {
                                'protocol': rule.get('IpProtocol'),
                                'from_port': rule.get('FromPort'),
                                'to_port': rule.get('ToPort'),
                                'destinations': []
                            }

                            async for ip_range in iter_to_aiter(rule.get('IpRanges', [])):
                                rule_info['destinations'].append({'type': 'cidr', 'value': ip_range.get('CidrIp')})

                            async for sg_ref in iter_to_aiter(rule.get('UserIdGroupPairs', [])):
                                rule_info['destinations'].append(
                                    {'type': 'security_group', 'value': sg_ref.get('GroupId')})

                            sg_info['outbound_rules'].append(rule_info)

                        result['security_groups'].append(sg_info)

                except ClientError as e:
                    logger.error(f"Error fetching security groups: {e}")

            # Get unique VPC IDs
            vpc_ids = set()
            async for subnet_group in iter_to_aiter(result['subnet_groups']):
                if subnet_group['vpc_id']:
                    vpc_ids.add(subnet_group['vpc_id'])

            # Get VPC details
            if vpc_ids:
                logger.info(f"Fetching VPC information...")
                try:
                    vpcs_response = await sync_to_async(self.ec2_client.describe_vpcs, VpcIds=list(vpc_ids))

                    async for vpc in iter_to_aiter(vpcs_response['Vpcs']):
                        vpc_info = {
                            'vpc_id': vpc['VpcId'],
                            'cidr_block': vpc['CidrBlock'],
                            'state': vpc['State'],
                            'is_default': vpc['IsDefault'],
                            'tags': vpc.get('Tags', [])
                        }
                        result['vpcs'].append(vpc_info)

                except ClientError as e:
                    logger.error(f"Error fetching VPCs: {e}")

            try:
                response = await sync_to_async(self.elasticache_client.describe_serverless_caches)
                result['serverless'].append(response)
            except ClientError as e:
                logger.error(f"Serverless Error: {e}")

            # Print summary
            logger.debug(f"\nSummary:")
            logger.debug(f"- Found {len(result['clusters'])} ElastiCache clusters")
            logger.debug(f"- Found {len(result['replication_groups'])} replication groups")
            logger.debug(f"- Found {len(result['subnet_groups'])} subnet groups")
            logger.debug(f"- Found {len(result['security_groups'])} security groups")
            logger.debug(f"- Found {len(result['vpcs'])} VPCs")

            return result

        except NoCredentialsError:
            logger.error(f"Error: AWS credentials not found. Please configure your AWS credentials.")
            return {}
        except ClientError as e:
            logger.error(f"AWS Client Error: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {}
