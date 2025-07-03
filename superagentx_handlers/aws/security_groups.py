import logging
import os

import boto3
from botocore.exceptions import ClientError

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class AWSSecurityGroupsHandler(BaseHandler):

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
    async def get_ec2_security_groups(self):
        """
        Retrieves details of AWS Security Groups configured as virtual firewalls
    for networks and resources exposed to the internet.

    This function queries AWS EC2 service to collect metadata about security groups,
    including their inbound and outbound rules, attached instances, and associated VPCs.
        """
        logger.info("Collecting EC2 Security Groups...")
        security_groups_data = []
        try:
            response = await sync_to_async(self.ec2_client.describe_security_groups)
            for sg in response['SecurityGroups']:
                def format_permissions(perms):
                    formatted = []
                    for rule in perms:
                        formatted.append({
                            'IpProtocol': rule.get('IpProtocol'),
                            'FromPort': rule.get('FromPort'),
                            'ToPort': rule.get('ToPort'),
                            'IpRanges': [ip.get('CidrIp') for ip in rule.get('IpRanges', [])],
                            'Ipv6Ranges': [ip.get('CidrIpv6') for ip in rule.get('Ipv6Ranges', [])],
                            'PrefixListIds': [pl.get('PrefixListId') for pl in rule.get('PrefixListIds', [])],
                            'UserIdGroupPairs': [
                                {
                                    'GroupId': grp.get('GroupId'),
                                    'UserId': grp.get('UserId'),
                                    'PeeringStatus': grp.get('PeeringStatus'),
                                    'VpcId': grp.get('VpcId'),
                                    'VpcPeeringConnectionId': grp.get('VpcPeeringConnectionId')
                                }
                                for grp in rule.get('UserIdGroupPairs', [])
                            ]
                        })
                    return formatted

                sg_info = {
                    'GroupId': sg.get('GroupId'),
                    'GroupName': sg.get('GroupName'),
                    'Description': sg.get('Description'),
                    'VpcId': sg.get('VpcId'),
                    'Tags': sg.get('Tags', []),
                    'InboundRules': format_permissions(sg.get('IpPermissions', [])),
                    'OutboundRules': format_permissions(sg.get('IpPermissionsEgress', []))
                }
                security_groups_data.append(sg_info)

            logger.info(f"Collected {len(security_groups_data)} Security Groups.")
            return security_groups_data
        except ClientError as e:
            logger.error(f"Error collecting EC2 security groups: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during EC2 security group collection: {e}")
            return []
