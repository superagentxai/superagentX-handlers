import logging
import os
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from superagentx.utils.helper import sync_to_async, iter_to_aiter
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx_handlers.aws.ec2 import AWSEC2Handler

from superagentx_handlers.aws.helper import generate_aws_sts_token

logger = logging.getLogger(__name__)


class AWSElasticLoadBalancerHandler(BaseHandler):
    """
    Handler to interact with AWS Elastic Load Balancing (ELBv2) services,
    primarily to retrieve detailed configuration and health status
    of Application Load Balancers (ALBs), their listeners, rules,
    target groups, and individual target health.

    Attributes:
        elbv2_client (boto3.client): Boto3 ELBv2 client initialized with provided AWS credentials and region.

    Example:
        handler = AWSElastiCacheHandler(region_name='us-east-1')
        alb_details = await handler.get_elastic_cache_details()
    """

    def __init__(
            self,
            aws_access_key_id: str | None = None,
            aws_secret_access_key: str | None = None,
            region_name: str | None = None
    ):
        """
        Initialize the AWS ELBv2 client using provided credentials or environment variables.

        Args:
            aws_access_key_id (Optional[str]): AWS access key ID. Defaults to environment variable.
            aws_secret_access_key (Optional[str]): AWS secret access key. Defaults to environment variable.
            region_name (Optional[str]): AWS region. Defaults to environment variable.
        """
        super().__init__()
        region = region_name or os.getenv("AWS_REGION")
        aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")

        self.credentials = generate_aws_sts_token(
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

        self.elbv2_client = boto3.client(
            'elbv2',
            **self.credentials
        )

        self.ec2_handler = AWSEC2Handler(
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

    @tool
    async def get_elb_details(self) -> dict:
        """
        Fetches a comprehensive inventory of Application Load Balancers (ALBs),
        including their listeners, listener rules, associated target groups,
        and target health statuses.

        Returns:
            dict: A nested dictionary structured as:
                {
                    "alb_name": {
                        "arn": str,
                        "dns_name": str,
                        "state": str,
                        "scheme": str,
                        "vpc_id": str,
                        "availability_zones": [str],
                        "security_groups": [str],
                        "listeners": {
                            "protocol:port": {
                                "arn": str,
                                "port": int,
                                "protocol": str,
                                "ssl_policy": Optional[str],
                                "certificates": list,
                                "default_actions": list,
                                "target_groups": [
                                    {
                                        "arn": str,
                                        "name": str,
                                        "protocol": str,
                                        "port": int,
                                        "vpc_id": str,
                                        "health_check_*": ...,
                                        "matcher": dict,
                                        "targets": [
                                            {
                                                "id": str,
                                                "port": int,
                                                "availability_zone": str,
                                                "health_state": str,
                                                "health_description": str
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }

        Raises:
            ClientError: If AWS service call fails.
        """
        alb_info = {}

        logger.info("Fetching Application Load Balancers...")
        try:
            response = await sync_to_async(self.elbv2_client.describe_load_balancers)
            albs = [lb for lb in response.get('LoadBalancers', []) if lb.get('Type') == 'application']
        except ClientError as e:
            logger.error(f"Failed to describe load balancers: {e}")
            return {}

        if not albs:
            logger.info("No Application Load Balancers found.")
            return {}

        logger.info(f"Found {len(albs)} Application Load Balancer(s)")

        async for alb in iter_to_aiter(albs):
            alb_name = alb.get('LoadBalancerName', 'UnknownName')
            alb_info[alb_name] = {
                'arn': alb.get('LoadBalancerArn'),
                'dns_name': alb.get('DNSName'),
                'state': alb.get('State', {}).get('Code'),
                'scheme': alb.get('Scheme'),
                'vpc_id': alb.get('VpcId'),
                'availability_zones': [
                    az.get('ZoneName') for az in alb.get('AvailabilityZones', [])
                ],
                'security_groups': await self.ec2_handler.get_security_groups(
                    group_ids=alb.get('SecurityGroups', [])
                ),
                'listeners': {}
            }

            try:
                response = await sync_to_async(
                    self.elbv2_client.describe_listeners,
                    LoadBalancerArn=alb['LoadBalancerArn']
                )
                listeners = response.get('Listeners', [])

            except ClientError as e:
                logger.error(f"Error fetching listeners for ALB {alb_name}: {e}")
                continue

            logger.debug(f"{alb_name}: Found {len(listeners)} listener(s)")

            async for listener in iter_to_aiter(listeners):
                listener_key = f"{listener.get('Protocol', 'UNKNOWN')}:{listener.get('Port', 0)}"
                alb_info[alb_name]['listeners'][listener_key] = {
                    'arn': listener.get('ListenerArn'),
                    'port': listener.get('Port'),
                    'protocol': listener.get('Protocol'),
                    'ssl_policy': listener.get('SslPolicy'),
                    'certificates': listener.get('Certificates', []),
                    'default_actions': listener.get('DefaultActions', []),
                    'target_groups': []
                }

                # Collect all target groups from default actions and rules
                target_group_arns = set()

                for action in listener.get('DefaultActions', []):
                    if action['Type'] == 'forward':
                        if 'TargetGroupArn' in action:
                            target_group_arns.add(action['TargetGroupArn'])
                        elif 'ForwardConfig' in action:
                            for tg in action['ForwardConfig'].get('TargetGroups', []):
                                target_group_arns.add(tg['TargetGroupArn'])

                try:
                    response = await sync_to_async(
                        self.elbv2_client.describe_rules,
                        ListenerArn=listener['ListenerArn']
                    )
                    rules = response.get('Rules', [])

                    async for rule in iter_to_aiter(rules):
                        async for action in iter_to_aiter(rule.get('Actions', [])):
                            if action['Type'] == 'forward':
                                if 'TargetGroupArn' in action:
                                    target_group_arns.add(action['TargetGroupArn'])
                                elif 'ForwardConfig' in action:
                                    for tg in action['ForwardConfig'].get('TargetGroups', []):
                                        target_group_arns.add(tg['TargetGroupArn'])
                except ClientError as e:
                    logger.error(f"Error fetching rules for listener {listener_key}: {e}")

                # Fetch detailed target group info
                if target_group_arns:
                    try:
                        tg_response = await sync_to_async(
                            self.elbv2_client.describe_target_groups,
                            TargetGroupArns=list(target_group_arns)
                        )
                        async for tg in iter_to_aiter(tg_response.get('TargetGroups', [])):
                            tg_info = {
                                'arn': tg.get('TargetGroupArn'),
                                'name': tg.get('TargetGroupName'),
                                'protocol': tg.get('Protocol'),
                                'port': tg.get('Port'),
                                'vpc_id': tg.get('VpcId'),
                                'health_check_protocol': tg.get('HealthCheckProtocol'),
                                'health_check_port': tg.get('HealthCheckPort'),
                                'health_check_path': tg.get('HealthCheckPath', '/'),
                                'health_check_interval': tg.get('HealthCheckIntervalSeconds', 30),
                                'health_check_timeout': tg.get('HealthCheckTimeoutSeconds', 5),
                                'healthy_threshold': tg.get('HealthyThresholdCount', 5),
                                'unhealthy_threshold': tg.get('UnhealthyThresholdCount', 2),
                                'target_type': tg.get('TargetType', 'instance'),
                                'matcher': tg.get('Matcher', {}),
                                'targets': []
                            }

                            try:
                                health_desc_response = await sync_to_async(
                                    self.elbv2_client.describe_target_health,
                                    TargetGroupArn=tg['TargetGroupArn']
                                )
                                health_desc = health_desc_response.get("TargetHealthDescriptions")
                                async for target_health in iter_to_aiter(health_desc):
                                    target = target_health.get('Target', {})
                                    target_health_state = target_health.get('TargetHealth', {})

                                    tg_info['targets'].append({
                                        'id': target.get('Id', 'N/A'),
                                        'port': target.get('Port'),
                                        'availability_zone': target.get('AvailabilityZone'),
                                        'health_state': target_health_state.get('State', 'unknown'),
                                        'health_description': target_health_state.get('Description', '')
                                    })

                            except ClientError as e:
                                logger.info(f"Could not get target health for {tg['TargetGroupName']}: {e}")

                            alb_info[alb_name]['listeners'][listener_key]['target_groups'].append(tg_info)
                    except ClientError as e:
                        logger.error(f"Error fetching target group details: {e}")

        total_listeners = sum(len(alb['listeners']) for alb in alb_info.values())
        total_target_groups = sum(
            len(listener['target_groups'])
            for alb in alb_info.values()
            for listener in alb['listeners'].values()
        )

        logger.info(f"Total listeners: {total_listeners}")
        logger.info(f"Total target groups: {total_target_groups}")

        return alb_info
