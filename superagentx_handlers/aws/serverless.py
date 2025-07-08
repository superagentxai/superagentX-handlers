import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

from superagentx_handlers.aws.helper import generate_aws_sts_token

logger = logging.getLogger(__name__)


class AWSLambdaHandler(BaseHandler):

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
        # Initialize AWS Lambda client
        self.lambda_client = boto3.client(
            'lambda',
            **self.credentials
        )

        # Initialize AWS IAM client
        self.iam_client = boto3.client(
            'iam',
            **self.credentials
        )

        # Initialize AWS IAM client
        self.ec2_client = boto3.client(
            'ec2',
            **self.credentials
        )

    @tool
    async def get_lambda_functions(self) -> list:
        """
        Collects all AWS Lambdas, along with their images, associated security rules.
        """
        all_functions = []

        # Get all Lambda functions
        paginator = await sync_to_async(
            self.lambda_client.get_paginator,
            'list_functions'
        )
        async for page in iter_to_aiter(paginator.paginate()):
            for function in page['Functions']:
                function_name = function['FunctionName']
                logger.info(f"Processing function: {function_name}")

                try:
                    # Get detailed function configuration
                    function_config = await sync_to_async(
                        self.lambda_client.get_function,
                        FunctionName=function_name
                    )

                    # Get function policy (resource-based policy)
                    function_policy = None
                    try:
                        policy_response = await sync_to_async(
                            self.lambda_client.get_policy,
                            FunctionName=function_name
                        )
                        function_policy = json.loads(policy_response['Policy'])
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'ResourceNotFoundException':
                            logger.warning(f"Error getting policy for {function_name}: {e}")

                    # Get IAM role details
                    role_arn = function['Role']
                    role_name = role_arn.split('/')[-1]

                    # Get role policies
                    role_policies = await self.get_role_policies(role_name)

                    # Get VPC configuration if exists
                    vpc_config = function.get('VpcConfig', {})

                    # Get security group details if VPC is configured
                    security_groups = []
                    if vpc_config.get('SecurityGroupIds'):
                        security_groups = await self.get_security_group_details(vpc_config['SecurityGroupIds'])

                    # Extract image information
                    image_info = {}
                    if function.get('PackageType') == 'Image':
                        image_info = {
                            'ImageUri': function.get('Code', {}).get('ImageUri', 'N/A'),
                            'PackageType': 'Image'
                        }
                    else:
                        image_info = {
                            'Runtime': function.get('Runtime', 'N/A'),
                            'PackageType': 'Zip'
                        }

                    function_info = {
                        'FunctionName': function_name,
                        'FunctionArn': function['FunctionArn'],
                        'Runtime': function.get('Runtime', 'N/A'),
                        'Handler': function.get('Handler', 'N/A'),
                        'Role': role_arn,
                        'ImageInfo': image_info,
                        'VpcConfig': {
                            'VpcId': vpc_config.get('VpcId', 'N/A'),
                            'SubnetIds': vpc_config.get('SubnetIds', []),
                            'SecurityGroupIds': vpc_config.get('SecurityGroupIds', [])
                        },
                        'SecurityGroups': security_groups,
                        'IAMRolePolicies': role_policies,
                        'ResourceBasedPolicy': function_policy,
                        'Environment': function.get('Environment', {}),
                        'Timeout': function.get('Timeout', 'N/A'),
                        'MemorySize': function.get('MemorySize', 'N/A'),
                        'LastModified': function.get('LastModified', 'N/A'),
                        'CodeSize': function.get('CodeSize', 'N/A'),
                        'State': function.get('State', 'N/A'),
                        'Layers': function.get('Layers', [])
                    }

                    all_functions.append(function_info)

                except ClientError as e:
                    logger.error(f"Error processing function {function_name}: {e}")
                    continue
        return all_functions

    async def get_role_policies(self, role_name):
        """
        Get all policies attached to an IAM role
        """
        policies = {
            'AttachedPolicies': [],
            'InlinePolicies': []
        }

        try:
            # Get attached managed policies
            attached_policies = await sync_to_async(
                self.iam_client.list_attached_role_policies,
                RoleName=role_name
            )
            for policy in attached_policies.get("AttachedPolicies"):
                policy_arn = policy.get("PolicyArn")
                try:
                    # Get policy version
                    policy_info = await sync_to_async(
                        self.iam_client.get_policy,
                        PolicyArn=policy_arn
                    )
                    policy_version = await sync_to_async(
                        self.iam_client.get_policy_version,
                        PolicyArn=policy_arn,
                        VersionId=policy_info['Policy']['DefaultVersionId']
                    )
                    policies['AttachedPolicies'].append({
                        'PolicyName': policy.get('PolicyName'),
                        'PolicyArn': policy_arn,
                        'PolicyDocument': policy_version.get('PolicyVersion', {}).get('Document')
                    })

                except ClientError as e:
                    logger.warning(f"Error getting policy {policy_arn}: {e}")

            # Get inline policies
            inline_policies = await sync_to_async(
                self.iam_client.list_role_policies,
                RoleName=role_name
            )
            async for policy_name in iter_to_aiter(inline_policies['PolicyNames']):
                try:
                    policy_doc = await sync_to_async(
                        self.iam_client.get_role_policy,
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    policies['InlinePolicies'].append({
                        'PolicyName': policy_name,
                        'PolicyDocument': policy_doc['PolicyDocument']
                    })
                except ClientError as e:
                    logger.warning(f"Error getting inline policy {policy_name}: {e}")

        except ClientError as e:
            logger.error(f"Error getting policies for role {role_name}: {e}")

        return policies

    async def get_security_group_details(self, security_group_ids: str) -> list:
        """
        Get details of security groups
        """
        try:
            response = await sync_to_async(
                self.ec2_client.describe_security_groups,
                GroupIds=security_group_ids
            )

            security_groups = []
            async for sg in iter_to_aiter(response['SecurityGroups']):
                security_groups.append({
                    'GroupId': sg.get('GroupId'),
                    'GroupName': sg.get('GroupName'),
                    'Description': sg.get('Description'),
                    'VpcId': sg.get('VpcId'),
                    'InboundRules': sg.get('IpPermissions', []),
                    'OutboundRules': sg.get('IpPermissionsEgress', [])
                })

            return security_groups

        except ClientError as e:
            logger.error(f"Error getting security group details: {e}")
            return []
