import asyncio
import logging
import os

import boto3
from botocore.exceptions import ClientError

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

logger = logging.getLogger(__name__)


class AWSEC2Handler(BaseHandler):

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

        self.ec2_client = boto3.client(
           'ec2',
            region_name=self.region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
    @tool
    async def get_instances(self):
        """
        Collects EC2 instances, including details like state, type, AMI, tags,
        security groups, and IP addresses.
        """
        logger.info("Collecting EC2 Instance...")
        instances_data = []
        try:
            paginator = self.ec2_client.get_paginator('describe_instances')
            async for page in iter_to_aiter(paginator.paginate()):
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instance_info = {
                            'InstanceId': instance.get('InstanceId'),
                            'InstanceType': instance.get('InstanceType'),
                            'State': instance['State']['Name'],
                            'LaunchTime': str(instance.get('LaunchTime')), # Convert datetime to string
                            'ImageId': instance.get('ImageId'),
                            'VpcId': instance.get('VpcId'),
                            'SubnetId': instance.get('SubnetId'),
                            'PrivateIpAddress': instance.get('PrivateIpAddress'),
                            'PublicIpAddress': instance.get('PublicIpAddress'),
                            'KeyName': instance.get('KeyName'),
                            'Tags': instance.get('Tags', []),
                            'SecurityGroups': [{'GroupId': sg.get('GroupId'), 'GroupName': sg.get('GroupName')} for sg in instance.get('SecurityGroups', [])],
                            'BlockDeviceMappings': [
                                {'DeviceName': bdm.get('DeviceName'), 'EbsVolumeId': bdm['Ebs'].get('VolumeId')}
                                for bdm in instance.get('BlockDeviceMappings', []) if 'Ebs' in bdm
                            ],
                            'PlatformDetails': instance.get('PlatformDetails'),
                            'Architecture': instance.get('Architecture'),
                            'Hypervisor': instance.get('Hypervisor'),
                            'RootDeviceType': instance.get('RootDeviceType'),
                            'MonitoringState': instance.get('Monitoring', {}).get('State')
                        }
                        instances_data.append(instance_info)
            logger.info(f"Collected for {len(instances_data)} EC2 instances.")
            return instances_data
        except ClientError as e:
            logger.error(f"Error collecting EC2 instance: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during EC2 instance collection: {e}")
        return []

    @tool
    async def get_security_groups(
            self,
            group_ids: list = None,
            group_names: list = None
    ):
        """
        Retrieves information about specified EC2 security groups by ID or name.

        Args:
            group_ids (list, optional): A list of security group IDs to retrieve. Defaults to all.
            group_names (list, optional): A list of security group names to retrieve. Defaults to all.

        Returns:
            list: Details of the matching security groups.
        """
        logger.info("Collecting EC2 Security Group...")
        kwargs = {}
        if group_ids:
            kwargs['GroupIds'] = group_ids
        if group_names:
            kwargs['GroupNames'] = group_names
        security_groups_data = []
        try:
            if group_ids:
                response = await sync_to_async(self.ec2_client.describe_security_groups, GroupIds=group_ids)
            else:
                response = await sync_to_async(self.ec2_client.describe_security_groups)
            for sg in response['SecurityGroups']:
                sg_info = {
                    'GroupId': sg.get('GroupId'),
                    'GroupName': sg.get('GroupName'),
                    'Description': sg.get('Description'),
                    'VpcId': sg.get('VpcId'),
                    'IpPermissions': sg.get('IpPermissions', []), # Inbound rules
                    'IpPermissionsEgress': sg.get('IpPermissionsEgress', []), # Outbound rules
                    'Tags': sg.get('Tags', [])
                }
                security_groups_data.append(sg_info)
            logger.info(f"Collected for {len(security_groups_data)} Security Groups.")
        except ClientError as e:
            logger.error(f"Error collecting EC2 security group: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during EC2 security group collection: {e}")
        return security_groups_data

    @tool
    async def get_volumes(self):
        """
        Collects for EBS Volumes, including size, type, attachment info, and encryption status.
        """
        logger.info("Collecting EBS Volume ...")
        volumes_data = []
        try:
            paginator = self.ec2_client.get_paginator('describe_volumes')
            async for page in iter_to_aiter(paginator.paginate()):
                for volume in page['Volumes']:
                    volume_info = {
                        'VolumeId': volume.get('VolumeId'),
                        'Size': volume.get('Size'),
                        'VolumeType': volume.get('VolumeType'),
                        'State': volume.get('State'),
                        'CreateTime': str(volume.get('CreateTime')), # Convert datetime to string
                        'AvailabilityZone': volume.get('AvailabilityZone'),
                        'Encrypted': volume.get('Encrypted'),
                        'KmsKeyId': volume.get('KmsKeyId'),
                        'Attachments': [
                            {'InstanceId': att.get('InstanceId'), 'Device': att.get('Device'), 'State': att.get('State')}
                            for att in volume.get('Attachments', [])
                        ],
                        'Tags': volume.get('Tags', [])
                    }
                    volumes_data.append(volume_info)
            logger.info(f"Collected for {len(volumes_data)} EBS Volumes.")
            return volumes_data
        except ClientError as e:
            logger.error(f"Error collecting EBS volume: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during EBS volume collection: {e}")
        return []

    @tool
    async def get_amis(self):
        """
        Collects for AMIs (Amazon Machine Images) owned by the account.
        """
        logger.info("Collecting EC2 AMI (Owned by account)...")
        amis_data = []
        try:
            response = await sync_to_async(self.ec2_client.describe_images, Owners=['self'])
            for image in response['Images']:
                ami_info = {
                    'ImageId': image.get('ImageId'),
                    'Name': image.get('Name'),
                    'Description': image.get('Description'),
                    'State': image.get('State'),
                    'CreationDate': image.get('CreationDate'), # This is already a string
                    'Architecture': image.get('Architecture'),
                    'PlatformDetails': image.get('PlatformDetails'),
                    'ImageType': image.get('ImageType'),
                    'Tags': image.get('Tags', [])
                }
                amis_data.append(ami_info)
            logger.info(f"Collected for {len(amis_data)} AMIs.")
            return amis_data
        except ClientError as e:
            logger.error(f"Error collecting EC2 AMI: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during EC2 AMI collection: {e}")
            return []

    @tool
    async def get_snapshots(self):
        """
        Collects for EBS Snapshots owned by the account.
        """
        logger.info("Collecting EBS Snapshot(Owned by account)...")
        snapshots_data = []
        try:
            paginator = await sync_to_async(self.ec2_client.get_paginator, 'describe_snapshots')
            async for page in iter_to_aiter(paginator.paginate(OwnerIds=['self'])):
                for snapshot in page['Snapshots']:
                    snapshot_info = {
                        'SnapshotId': snapshot.get('SnapshotId'),
                        'VolumeId': snapshot.get('VolumeId'),
                        'State': snapshot.get('State'),
                        'StartTime': str(snapshot.get('StartTime')), # Convert datetime to string
                        'VolumeSize': snapshot.get('VolumeSize'),
                        'Description': snapshot.get('Description'),
                        'Encrypted': snapshot.get('Encrypted'),
                        'KmsKeyId': snapshot.get('KmsKeyId'),
                        'OwnerId': snapshot.get('OwnerId'),
                        'Tags': snapshot.get('Tags', [])
                    }
                    snapshots_data.append(snapshot_info)
            logger.info(f"Collected  for {len(snapshots_data)} Snapshots.")
            return snapshots_data
        except ClientError as e:
            logger.error(f"Error collecting EBS snapshot : {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during EBS snapshot collection: {e}")
            return []

    @tool
    async def get_key_pairs(self):
        """
        Collects for EC2 Key Pairs.
        """
        logger.info("Collecting EC2 Key Pair...")
        key_pairs_data = []
        try:
            response = await sync_to_async(self.ec2_client.describe_key_pairs)
            for key_pair in response['KeyPairs']:
                kp_info = {
                    'KeyPairId': key_pair.get('KeyPairId'),
                    'KeyName': key_pair.get('KeyName'),
                    'KeyFingerprint': key_pair.get('KeyFingerprint'),
                    'KeyType': key_pair.get('KeyType'),
                    'Tags': key_pair.get('Tags', [])
                }
                key_pairs_data.append(kp_info)
            logger.info(f"Collected for {len(key_pairs_data)} Key Pairs.")
            return key_pairs_data
        except ClientError as e:
            logger.error(f"Error collecting EC2 key pair: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during EC2 key pair collection: {e}")
            return []

    @tool
    async def get_network_interfaces(self):
        """
        Collects for Network Interfaces, including associated instances and security groups.
        """
        logger.info("Collecting Network Interface ...")
        network_interfaces_data = []
        try:
            paginator = await sync_to_async(self.ec2_client.get_paginator, 'describe_network_interfaces')
            async for page in iter_to_aiter(paginator.paginate()):
                for ni in page['NetworkInterfaces']:
                    ni_info = {
                        'NetworkInterfaceId': ni.get('NetworkInterfaceId'),
                        'VpcId': ni.get('VpcId'),
                        'SubnetId': ni.get('SubnetId'),
                        'Description': ni.get('Description'),
                        'Status': ni.get('Status'),
                        'PrivateIpAddress': ni.get('PrivateIpAddress'),
                        'Association': ni.get('Association'), # Contains PublicIp if associated
                        'Attachment': {
                            'InstanceId': ni['Attachment'].get('InstanceId'),
                            'DeviceIndex': ni['Attachment'].get('DeviceIndex'),
                            'Status': ni['Attachment'].get('Status')
                        } if ni.get('Attachment') else None,
                        'Groups': [{'GroupId': g.get('GroupId'), 'GroupName': g.get('GroupName')} for g in ni.get('Groups', [])],
                        'Tags': ni.get('Tags', [])
                    }
                    network_interfaces_data.append(ni_info)
            logger.info(f"Collected for {len(network_interfaces_data)} Network Interfaces.")
            return network_interfaces_data
        except ClientError as e:
            logger.error(f"Error collecting network interface : {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during network interface collection: {e}")
            return []

    @tool
    async def collect_all_ec2(self):
        """
        Collects all available comprehensive EC2  for purposes asynchronously.
        This is the main entry point for a full EC2  dump.

        Returns:
            dict: A dictionary containing all collected EC2 , categorized.
        """
        logger.debug("Starting collection of all comprehensive EC2 ...")
        try:

            (
                ec2_instances,
                ec2_security_groups,
                ec2_volumes,
                ec2_amis,
                ec2_snapshots,
                ec2_key_pairs,
                ec2_network_interfaces,
            ) = await asyncio.gather(
                self.get_instances(),
                self.get_security_groups(),
                self.get_volumes(),
                self.get_amis(),
                self.get_snapshots(),
                self.get_key_pairs(),
                self.get_network_interfaces(),
                # return_exceptions=True # Allows other tasks to complete even if one fails
            )
            logger.debug("Finished collecting all comprehensive EC2.")
            return {
                'ec2_instances': ec2_instances if not isinstance(ec2_instances, Exception) else [],
                'ec2_security_groups': ec2_security_groups if not isinstance(ec2_security_groups, Exception) else [],
                'ec2_volumes': ec2_volumes if not isinstance(ec2_volumes, Exception) else [],
                'ec2_amis': ec2_amis if not isinstance(ec2_amis, Exception) else [],
                'ec2_snapshots': ec2_snapshots if not isinstance(ec2_snapshots, Exception) else [],
                'ec2_key_pairs': ec2_key_pairs if not isinstance(ec2_key_pairs, Exception) else [],
                'ec2_network_interfaces': ec2_network_interfaces if not isinstance(ec2_network_interfaces, Exception) else [],
            }
        except Exception as e:
            logger.error(f"Error during overall EC2  collection: {e}")
            return {}
