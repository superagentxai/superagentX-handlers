import asyncio
import json
import logging
import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter  # Import helper functions

# Imports for testing

logger = logging.getLogger(__name__)


class AWSIAMHandler(BaseHandler):
    """
    A read-only handler class for common AWS IAM operations using boto3.
    This class wraps synchronous boto3 calls with sync_to_async for asynchronous execution.
    It focuses on providing comprehensive methods as tools for audit purposes.
    """

    def __init__(
            self,
            *,
            aws_access_key_id: str | None = None,
            aws_secret_access_key: str | None = None,
            region_name: str | None = None,
            **kwargs
    ):
        """
        Initializes the synchronous IAM client with provided credentials.

        Args:
            aws_access_key_id (str): The AWS access key ID.
            aws_secret_access_key (str): The AWS secret access key.
            region_name (str): The AWS region to connect to.
        """
        super().__init__()
        self.region = region_name or os.getenv("AWS_REGION")
        aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        config = Config(
            retries={"max_attempts": 10, "mode": "standard"},
            max_pool_connections=50
        )
        self.iam_client = boto3.client(
            'iam',
            region_name=self.region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            config=config
        )
        self.org_client = boto3.client(
            'organizations',
            region_name=self.region,  # Organizations API is global but boto3 client still expects a region
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            config=config
        )
        logger.info(f"IAM client initialized for region: {region_name}")

    async def _async_get_policy_document(self, policy_arn: str, version_id: str):
        """
        Asynchronously gets the policy document for a given policy ARN and version.
        This is a helper and not exposed as a direct tool.

        Args:
            policy_arn (str): The ARN of the IAM policy.
            version_id (str): The version ID of the policy to retrieve.

        Returns:
            dict: The policy document, or None if an error occurs.
        """
        try:
            response = await sync_to_async(
                self.iam_client.get_policy_version,
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            # boto3 returns 'PolicyDocument' as a URL-encoded string for inline policies
            # and a dictionary for managed policies. Ensure it's a dictionary.
            policy_document_content = response['PolicyVersion']['Document']
            if isinstance(policy_document_content, str):
                return await sync_to_async(json.loads, policy_document_content)
            return policy_document_content
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logger.debug(f"Policy version {version_id} not found for ARN {policy_arn}. Skipping.")
            else:
                logger.debug(f"Error getting policy document for {policy_arn} version {version_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting policy document for {policy_arn} version {version_id}: {e}")
            return None

    async def _get_full_user_details(self, user: dict):
        """
        Helper method to collect comprehensive details for a single IAM user,
        including attached policies, inline policies, and MFA devices.
        """
        user_name = user['UserName']
        user_details = {
            'UserName': user['UserName'],
            'UserId': user['UserId'],
            'Arn': user['Arn'],
            'CreateDate': str(user['CreateDate']),
            'Path': user.get('Path', '/'),
            'PasswordLastUsed': str(user.get('PasswordLastUsed')) if user.get('PasswordLastUsed') else None,
            'AttachedManagedPolicies': [],
            'InlinePolicies': [],
            'MFADevices': []
        }

        try:
            attached_policies_task = sync_to_async(self.iam_client.list_attached_user_policies, UserName=user_name)
            inline_policy_names_task = sync_to_async(self.iam_client.list_user_policies, UserName=user_name)
            mfa_devices_task = sync_to_async(self.iam_client.list_mfa_devices, UserName=user_name)
            login_profile_task = sync_to_async(self.iam_client.get_login_profile, UserName=user_name)
            access_keys_task = sync_to_async(self.iam_client.list_access_keys, UserName=user_name)
            groups_for_user_task = sync_to_async(self.iam_client.list_groups_for_user, UserName=user_name)

            (
                attached_policies_response,
                inline_policy_names_response,
                mfa_devices_response,
                login_profile_response,
                access_keys_response,
                groups_for_user_response
            ) = await asyncio.gather(
                attached_policies_task,
                inline_policy_names_task,
                mfa_devices_task,
                login_profile_task,
                access_keys_task,
                groups_for_user_task,
                return_exceptions=True
            )

            if not isinstance(attached_policies_response, Exception):
                user_details['AttachedManagedPolicies'] = attached_policies_response.get('AttachedPolicies', [])
            else:
                logger.warning(f"Error fetching attached policies for {user_name}: {attached_policies_response}")

            if not isinstance(mfa_devices_response, Exception):
                for device in mfa_devices_response.get('MFADevices', []):
                    user_details['MFADevices'].append({
                        'SerialNumber': device['SerialNumber'],
                        'EnableDate': str(device['EnableDate']),
                    })
            else:
                logger.warning(f"Error fetching MFA devices for {user_name}: {mfa_devices_response}")

            if not isinstance(login_profile_response, Exception):
                user_details['LoginProfile'] = {
                    'CreateDate': str(login_profile_response['LoginProfile']['CreateDate']),
                    'PasswordResetRequired': login_profile_response['LoginProfile'].get('PasswordResetRequired', False)
                }
            else:
                user_details['LoginProfile'] = None  # User might not have a login profile
                logger.debug(f"No login profile found for {user_name} or error: {login_profile_response}")

            if not isinstance(access_keys_response, Exception):
                user_details['AccessKeys'] = access_keys_response.get('AccessKeyMetadata', [])
            else:
                logger.warning(f"Error fetching access keys for {user_name}: {access_keys_response}")

            if not isinstance(groups_for_user_response, Exception):
                user_details['Groups'] = groups_for_user_response.get('Groups', [])
            else:
                logger.warning(f"Error fetching groups for user {user_name}: {groups_for_user_response}")

            # Fetch actual inline policy documents concurrently
            if not isinstance(inline_policy_names_response, Exception) and inline_policy_names_response.get(
                    'PolicyNames'):
                inline_policy_tasks = [
                    sync_to_async(self.iam_client.get_user_policy, UserName=user_name, PolicyName=policy_name)
                    for policy_name in inline_policy_names_response['PolicyNames']
                ]
                inline_policy_documents_responses = await asyncio.gather(*inline_policy_tasks, return_exceptions=True)

                for i, policy_doc_response in enumerate(inline_policy_documents_responses):
                    if not isinstance(policy_doc_response, Exception) and policy_doc_response:
                        policy_name = inline_policy_names_response['PolicyNames'][i]
                        policy_document = policy_doc_response['PolicyDocument']
                        user_details['InlinePolicies'].append({
                            'PolicyName': policy_name,
                            'PolicyDocument': policy_document
                        })
                    else:
                        policy_name = inline_policy_names_response['PolicyNames'][i] if i < len(
                            inline_policy_names_response['PolicyNames']) else 'UNKNOWN'
                        logger.warning(
                            f"Error fetching inline policy {policy_name} for {user_name}: {policy_doc_response}")
            else:
                logger.debug(
                    f"No inline policy names found or error fetching for {user_name}: {inline_policy_names_response}")

        except Exception as e:
            logger.error(f"Error collecting full details for user {user_name}: {e}")

        return user_details

    async def _get_full_role_details(self, role: dict):
        """
        Helper method to collect comprehensive details for a single IAM role,
        including assume role policy, attached policies, and inline policies.
        """
        role_name = role['RoleName']
        role_details = {
            'RoleName': role['RoleName'],
            'RoleId': role['RoleId'],
            'Arn': role['Arn'],
            'CreateDate': str(role['CreateDate']),
            'AssumeRolePolicyDocument': role.get('AssumeRolePolicyDocument'),
            'Description': role.get('Description'),
            'AttachedManagedPolicies': [],
            'InlinePolicies': [],
            'InstanceProfiles': []
        }

        try:
            attached_policies_task = sync_to_async(self.iam_client.list_attached_role_policies, RoleName=role_name)
            inline_policy_names_task = sync_to_async(self.iam_client.list_role_policies, RoleName=role_name)
            instance_profiles_task = sync_to_async(self.iam_client.list_instance_profiles_for_role, RoleName=role_name)

            attached_policies_response, inline_policy_names_response, instance_profiles_response = await asyncio.gather(
                attached_policies_task,
                inline_policy_names_task,
                instance_profiles_task,
                return_exceptions=True
            )

            if not isinstance(attached_policies_response, Exception):
                role_details['AttachedManagedPolicies'] = attached_policies_response.get('AttachedPolicies', [])
            else:
                logger.warning(f"Error fetching attached policies for {role_name}: {attached_policies_response}")

            if not isinstance(instance_profiles_response, Exception):
                role_details['InstanceProfiles'] = instance_profiles_response.get('InstanceProfiles', [])
            else:
                logger.warning(f"Error fetching instance profiles for {role_name}: {instance_profiles_response}")

            # Fetch actual inline policy documents concurrently
            if not isinstance(inline_policy_names_response, Exception) and inline_policy_names_response.get(
                    'PolicyNames'):
                inline_policy_tasks = [
                    sync_to_async(self.iam_client.get_role_policy, RoleName=role_name, PolicyName=policy_name)
                    for policy_name in inline_policy_names_response['PolicyNames']
                ]
                inline_policy_documents_responses = await asyncio.gather(*inline_policy_tasks, return_exceptions=True)

                for i, policy_doc_response in enumerate(inline_policy_documents_responses):
                    if not isinstance(policy_doc_response, Exception) and policy_doc_response:
                        policy_name = inline_policy_names_response['PolicyNames'][i]
                        policy_document = json.loads(policy_doc_response['PolicyDocument'])
                        role_details['InlinePolicies'].append({
                            'PolicyName': policy_name,
                            'PolicyDocument': policy_document
                        })
                    else:
                        policy_name = inline_policy_names_response['PolicyNames'][i] if i < len(
                            inline_policy_names_response['PolicyNames']) else 'UNKNOWN'
                        logger.warning(
                            f"Error fetching inline policy {policy_name} for {role_name}: {policy_doc_response}")
            else:
                logger.debug(
                    f"No inline policy names found or error fetching for {role_name}: {inline_policy_names_response}")

        except Exception as e:
            logger.error(f"Error collecting full details for role {role_name}: {e}")

        return role_details

    async def _get_full_group_details(self, group: dict):
        """
        Helper method to collect comprehensive details for a single IAM group,
        including associated users, attached policies, and inline policies.
        """
        group_name = group['GroupName']
        group_details = {
            'GroupName': group['GroupName'],
            'GroupId': group['GroupId'],
            'Arn': group['Arn'],
            'CreateDate': str(group['CreateDate']),
            'Path': group.get('Path', '/'),
            'Users': [],
            'AttachedManagedPolicies': [],
            'InlinePolicies': []
        }

        try:
            group_response_task = sync_to_async(self.iam_client.get_group, GroupName=group_name)
            attached_policies_task = sync_to_async(self.iam_client.list_attached_group_policies, GroupName=group_name)
            inline_policy_names_task = sync_to_async(self.iam_client.list_group_policies, GroupName=group_name)

            group_response, attached_policies_response, inline_policy_names_response = await asyncio.gather(
                group_response_task,
                attached_policies_task,
                inline_policy_names_task,
                return_exceptions=True
            )

            if not isinstance(group_response, Exception) and group_response:
                for user in group_response.get('Users', []):
                    group_details['Users'].append({
                        'UserName': user['UserName'],
                        'UserId': user['UserId'],
                        'Arn': user['Arn']
                    })
            else:
                logger.warning(f"Error fetching group users for {group_name}: {group_response}")

            if not isinstance(attached_policies_response, Exception):
                group_details['AttachedManagedPolicies'] = attached_policies_response.get('AttachedPolicies', [])
            else:
                logger.warning(f"Error fetching attached policies for {group_name}: {attached_policies_response}")

            # Fetch actual inline policy documents concurrently
            if not isinstance(inline_policy_names_response, Exception) and inline_policy_names_response.get(
                    'PolicyNames'):
                inline_policy_tasks = [
                    sync_to_async(self.iam_client.get_group_policy, GroupName=group_name, PolicyName=policy_name)
                    for policy_name in inline_policy_names_response['PolicyNames']
                ]
                inline_policy_documents_responses = await asyncio.gather(*inline_policy_tasks, return_exceptions=True)

                for i, policy_doc_response in enumerate(inline_policy_documents_responses):
                    if not isinstance(policy_doc_response, Exception) and policy_doc_response:
                        policy_name = inline_policy_names_response['PolicyNames'][i]
                        policy_document = json.loads(policy_doc_response['PolicyDocument'])
                        group_details['InlinePolicies'].append({
                            'PolicyName': policy_name,
                            'PolicyDocument': policy_document
                        })
                    else:
                        policy_name = inline_policy_names_response['PolicyNames'][i] if i < len(
                            inline_policy_names_response['PolicyNames']) else 'UNKNOWN'
                        logger.warning(
                            f"Error fetching inline policy {policy_name} for {group_name}: {policy_doc_response}")
            else:
                logger.debug(
                    f"No inline policy names found or error fetching for {group_name}: {inline_policy_names_response}")

        except Exception as e:
            logger.error(f"Error collecting full details for group {group_name}: {e}")

        return group_details

    async def _get_full_managed_policy_details(self, policy: dict):
        """
        Helper method to collect comprehensive details for a single IAM managed policy,
        including its default version's policy document.
        """
        policy_arn = policy['Arn']
        policy_details = {
            'PolicyName': policy['PolicyName'],
            'PolicyId': policy['PolicyId'],
            'Arn': policy['Arn'],
            'Path': policy['Path'],
            'DefaultVersionId': policy['DefaultVersionId'],
            'CreateDate': str(policy['CreateDate']),
            'UpdateDate': str(policy.get('UpdateDate')) if policy.get('UpdateDate') else None,
            'IsAttachable': policy['IsAttachable'],
            'Description': policy.get('Description'),
            'AttachedManagedPolicyDocument': None
        }
        try:
            policy_document = await self._async_get_policy_document(policy_arn, policy['DefaultVersionId'])
            if policy_document:
                policy_details['AttachedManagedPolicyDocument'] = policy_document
        except Exception as e:
            logger.error(f"Error fetching policy document for managed policy {policy_arn}: {e}")
        return policy_details

    @tool
    async def list_iam_users_with_details(self):
        """
        Lists all IAM users in the account with comprehensive details,
        including attached policies, inline policies, MFA devices, login profiles, access keys, and groups.

        Returns:
            list: A list of IAM user dictionaries with full details,
                  or an empty list if an error occurs.
        """
        logger.debug("Starting collection of detailed IAM users...")
        users_data = []
        try:
            paginator = await sync_to_async(self.iam_client.get_paginator, 'list_users')
            all_users_tasks = []
            async for page in iter_to_aiter(await sync_to_async(paginator.paginate)):
                async for user in iter_to_aiter(page.get('Users', [])):
                    all_users_tasks.append(self._get_full_user_details(user))

            users_data = await asyncio.gather(*all_users_tasks)
            # Filter out any None results from failed individual fetches
            users_data = [u for u in users_data if u is not None]
            logger.debug(f"Collected details for {len(users_data)} IAM users.")
        except ClientError as e:
            logger.error(f"Error listing IAM users with details: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during detailed user collection: {e}")
        return users_data

    @tool
    async def list_iam_roles_with_details(self):
        """
        Lists all IAM roles in the account with comprehensive details,
        including assume role policy, attached policies, inline policies, and associated instance profiles.

        Returns:
            list: A list of IAM role dictionaries with full details,
                  or an empty list if an error occurs.
        """
        logger.debug("Starting collection of detailed IAM roles...")
        roles_data = []
        try:
            paginator = await sync_to_async(self.iam_client.get_paginator, 'list_roles')
            all_roles_tasks = []
            async for page in iter_to_aiter(await sync_to_async(paginator.paginate)):
                async for role in iter_to_aiter(page.get('Roles', [])):
                    all_roles_tasks.append(self._get_full_role_details(role))

            roles_data = await asyncio.gather(*all_roles_tasks)
            roles_data = [r for r in roles_data if r is not None]
            logger.debug(f"Collected details for {len(roles_data)} IAM roles.")
        except ClientError as e:
            logger.error(f"Error listing IAM roles with details: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during detailed role collection: {e}")
        return roles_data

    @tool
    async def list_iam_groups_with_details(self):
        """
        Lists all IAM groups in the account with comprehensive details,
        including associated users, attached policies, and inline policies.

        Returns:
            list: A list of IAM group dictionaries with full details,
                  or an empty list if an error occurs.
        """
        logger.debug("Starting collection of detailed IAM groups...")
        groups_data = []
        try:
            paginator = await sync_to_async(self.iam_client.get_paginator, 'list_groups')
            all_groups_tasks = []
            async for page in iter_to_aiter(await sync_to_async(paginator.paginate)):
                for group in page.get('Groups', []):
                    all_groups_tasks.append(self._get_full_group_details(group))

            groups_data = await asyncio.gather(*all_groups_tasks)
            groups_data = [g async for g in iter_to_aiter(groups_data) if g is not None]
            logger.debug(f"Collected details for {len(groups_data)} IAM groups.")
        except ClientError as e:
            logger.error(f"Error listing IAM groups with details: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during detailed group collection: {e}")
        return groups_data

    @tool
    async def list_iam_managed_policies_with_documents(self, scope: str = 'All'):
        """
        Lists all IAM managed policies (customer-managed and AWS-managed) with their
        default policy version documents.

        Args:
            scope (str): The scope of the policies to list. 'All' | 'AWS' | 'Local'.
                         Defaults to 'All'.

        Returns:
            list: A list of IAM managed policy dictionaries with policy documents,
                  or an empty list if an error occurs.
        """
        logger.debug("Starting collection of detailed IAM managed policies with documents...")
        policies_data = []
        try:
            paginator = self.iam_client.get_paginator('list_policies')
            all_policies_tasks = []
            async for page in iter_to_aiter(paginator.paginate(Scope=scope)):
                for policy in page.get('Policies', []):
                    all_policies_tasks.append(self._get_full_managed_policy_details(policy))

            policies_data = await asyncio.gather(*all_policies_tasks)
            policies_data = [p for p in policies_data if p is not None]
            logger.debug(f"Collected details for {len(policies_data)} IAM managed policies.")
        except ClientError as e:
            logger.error(f"Error listing IAM managed policies with documents: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during detailed managed policy collection: {e}")
        return policies_data

    @tool
    async def collect_all_iam(self):
        """
        Collects all available comprehensive IAM.
        This is the main entry point for a full .

        Returns:
            dict: A dictionary containing all collected IAM, categorized.
        """
        logger.debug("Starting collection of all comprehensive IAM ...")
        try:
            # Concurrently collect different categories
            account_summary_task = self.get_account_summary()
            users_details_task = self.list_iam_users_with_details()
            roles_details_task = self.list_iam_roles_with_details()
            groups_details_task = self.list_iam_groups_with_details()
            managed_policies_details_task = self.list_iam_managed_policies_with_documents()
            credential_report_task = self.get_credential_report()
            virtual_mfa_devices_task = self.list_virtual_mfa_devices()
            account_password_policy_task = self.get_account_password_policy()
            account_authorization_details_task = self.get_account_authorization_details()
            list_account_aliases_task = self.list_account_aliases()
            organization_accounts_task = self.list_organization_accounts()

            (
                account_summary,
                users,
                roles,
                groups,
                managed_policies,
                credential_report,
                virtual_mfa_devices,
                account_password_policy,
                account_authorization_details,
                account_aliases,
                organization_accounts
            ) = await asyncio.gather(
                account_summary_task,
                users_details_task,
                roles_details_task,
                groups_details_task,
                managed_policies_details_task,
                credential_report_task,
                virtual_mfa_devices_task,
                account_password_policy_task,
                account_authorization_details_task,
                list_account_aliases_task,
                organization_accounts_task,
                return_exceptions=True
            )

            evidence = {
                'account_summary': account_summary if not isinstance(account_summary, Exception) else {},
                'users': users if not isinstance(users, Exception) else [],
                'roles': roles if not isinstance(roles, Exception) else [],
                'groups': groups if not isinstance(groups, Exception) else [],
                'managed_policies': managed_policies if not isinstance(managed_policies, Exception) else [],
                'credential_report_csv': credential_report if not isinstance(credential_report, Exception) else None,
                'virtual_mfa_devices': virtual_mfa_devices if not isinstance(virtual_mfa_devices, Exception) else [],
                'account_password_policy': account_password_policy if not isinstance(account_password_policy,
                                                                                     Exception) else {},
                'account_authorization_details': account_authorization_details if not isinstance(
                    account_authorization_details, Exception) else {},
                'account_aliases': account_aliases if not isinstance(account_aliases, Exception) else [],
                'organization_accounts_inventory': organization_accounts if not isinstance(organization_accounts,
                                                                                           Exception) else []
            }
            logger.debug("Finished collecting all comprehensive IAM.")
            return evidence
        except Exception as e:
            logger.error(f"Error during overall IAM collection: {e}")
            return {}

    @tool
    async def list_mfa_enabled_users(self):
        """
        Lists all IAM users that have MFA devices enabled asynchronously.
        Useful for quick checks on MFA adoption.

        Returns:
            list: A list of dictionaries, where each dictionary contains 'UserName'
                  and 'MfaDeviceSerial' for users with MFA enabled,
                  or an empty list if an error occurs.
        """
        mfa_enabled_users = []
        try:
            # Using list_users directly and then checking MFA for each
            paginator = await sync_to_async(self.iam_client.get_paginator, 'list_users')
            page_data = await sync_to_async(paginator.paginate)
            users_to_check = []
            async for page in iter_to_aiter(page_data):
                users_to_check.extend(page.get('Users', []))

            mfa_check_tasks = []
            async for user in iter_to_aiter(users_to_check):
                async def _check_user_mfa_status(user_name):
                    try:
                        response = await sync_to_async(self.iam_client.list_mfa_devices, UserName=user_name)
                        if response.get('MFADevices'):
                            logger.debug(f"User '{user_name}' has MFA enabled.")
                            return {
                                'UserName': user_name,
                                'MfaDeviceSerial': [d['SerialNumber'] for d in response['MFADevices']]
                            }
                        else:
                            logger.debug(f"User '{user_name}' does NOT have MFA enabled.")
                            return None
                    except ClientError as e:
                        logging.warning(f"Could not check MFA for user '{user_name}': {e}")
                        return None

                mfa_check_tasks.append(_check_user_mfa_status(user['UserName']))

            results = await asyncio.gather(*mfa_check_tasks)
            mfa_enabled_users = [res async for res in iter_to_aiter(results) if res is not None]
            return mfa_enabled_users
        except ClientError as e:
            logger.error(f"Error listing MFA enabled users: {e}")
            return []

    @tool
    async def get_account_summary(self):
        """
        Retrieves information about the account's IAM entity usage and quota.
        Relevant for IAM capacity planning and overview.

        Returns:
            dict: A dictionary containing various account summary metrics, or None if an error occurs.
        """
        try:
            response = await sync_to_async(self.iam_client.get_account_summary)
            return response['SummaryMap']
        except ClientError as e:
            logger.error(f"Error getting account summary: {e}")
            return None

    @tool
    async def get_credential_report(self):
        """
        Retrieves the credential report for the account.
        This method first generates the report if it's not ready, then retrieves it.
        It can take some time for the report to be generated.
        Crucial for auditing password age, MFA status, access key rotation, etc.

        Returns:
            str: The raw CSV content of the credential report, or None if an error occurs.
        """
        try:
            # Request report generation
            logger.info("Generating IAM credential report...")
            await sync_to_async(self.iam_client.generate_credential_report)

            # Wait for the report to be ready
            max_attempts = 10
            attempt = 0
            while attempt < max_attempts:
                try:
                    response = await sync_to_async(self.iam_client.get_credential_report)
                    return response
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ReportNotPresent':
                        logger.info(f"Report not yet present, waiting... (Attempt {attempt + 1}/{max_attempts})")
                        await asyncio.sleep(1)  # Wait for 1 second
                    else:
                        raise e  # Re-raise other errors
                attempt += 1

            logger.error("Failed to get credential report after multiple attempts.")
            return None
        except ClientError as e:
            logger.error(f"Error generating or getting credential report: {e}")
            return None

    @tool
    async def list_virtual_mfa_devices(self, assignment_status: str = 'Any'):
        """
        Lists the virtual MFA devices in the account.
        Useful for auditing unassigned virtual MFA devices.

        Args:
            assignment_status (str): The status of the MFA devices to list.
                                     'Assigned' | 'Unassigned' | 'Any'. Defaults to 'Any'.

        Returns:
            list: A list of dictionaries, each containing 'SerialNumber', 'EnableDate', 'User', etc.,
                  or an empty list if an error occurs.
        """
        try:
            mfa_devices = []
            paginator = await sync_to_async(self.iam_client.get_paginator, 'list_virtual_mfa_devices')
            paginator_list = await sync_to_async(paginator.paginate, AssignmentStatus=assignment_status)
            async for page in iter_to_aiter(paginator_list):
                mfa_devices.extend(page['VirtualMFADevices'])
            return mfa_devices
        except ClientError as e:
            logger.error(f"Error listing virtual MFA devices: {e}")
            return []

    @tool
    async def get_account_authorization_details(self, filter_type: str = 'All'):
        """
        Retrieves information about the account's authorization entities (users, groups, roles, policies)
        and their relationships. This is a very comprehensive report from AWS IAM.

        Args:
            filter_type (str): The entity type to include in the report.
                               'User' | 'Group' | 'Role' | 'Policy' | 'All'. Defaults to 'All'.

        Returns:
            dict: A dictionary containing lists of detailed information about users, groups, roles, and policies,
                  or None if an error occurs.
        """
        try:
            details = {'UserDetailList': [], 'GroupDetailList': [], 'RoleDetailList': [], 'PolicyDetailList': []}
            paginator = await sync_to_async(self.iam_client.get_paginator, 'get_account_authorization_details')
            filter_list = [filter_type] if filter_type != 'All' else []
            paginator_list = await sync_to_async(paginator.paginate, Filter=filter_list)
            async for page in iter_to_aiter(paginator_list):
                if 'UserDetailList' in page:
                    details['UserDetailList'].extend(page['UserDetailList'])
                if 'GroupDetailList' in page:
                    details['GroupDetailList'].extend(page['GroupDetailList'])
                if 'RoleDetailList' in page:
                    details['RoleDetailList'].extend(page['RoleDetailList'])
                if 'PolicyDetailList' in page:
                    details['PolicyDetailList'].extend(page['PolicyDetailList'])
            return details
        except ClientError as e:
            logger.error(f"Error getting account authorization details: {e}")
            return None

    @tool
    async def get_account_password_policy(self):
        """
        Retrieves the password policy for the account.
        Relevant for auditing of password complexity, rotation, etc.

        Returns:
            dict: A dictionary containing the account's password policy, or None if no policy is set or an error occurs.
        """
        try:
            response = await sync_to_async(self.iam_client.get_account_password_policy)
            return response['PasswordPolicy']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logger.debug("No password policy found for the account.")
            else:
                logger.error(f"Error getting account password policy: {e}")
            return None

    @tool
    async def list_account_aliases(self):
        """
        Lists the account aliases associated with the AWS account.
        Useful for quick identification of account nicknames.

        Returns:
            list: A list of account aliases (strings), or an empty list if none exist or an error occurs.
        """
        try:
            response = await sync_to_async(self.iam_client.list_account_aliases)
            return response['AccountAliases']
        except ClientError as e:
            logger.error(f"Error listing account aliases: {e}")
            return []

    @tool
    async def list_organization_accounts(self):
        """
        Lists all AWS accounts that are part of the current AWS Organizations.
        This method provides an inventory of the top-level AWS accounts within the enterprise's organization structure.
        It returns details for each AWS account itself (e.g., Account ID, Name, Email, Status).
        Note: This method lists AWS accounts, not individual IAM users, root users, or service roles within those accounts.
        To gather IAM entity details for each account, this method's output would need to be combined with other
        IAM-specific tools (e.g., list_iam_users_with_details) by assuming roles into each account.

        Returns:
            list: A list of dictionaries, where each dictionary represents an AWS account (e.g., {'Id': '123...', 'Name': 'DevAccount', 'Email': '...', 'Status': 'ACTIVE'}),
                  or an empty list if AWS Organizations is not enabled/configured for the authenticated account,
                  or if an error occurs.
        """
        logger.debug("Starting collection of all AWS accounts in the organization...")
        accounts = []
        try:
            paginator = self.org_client.get_paginator('list_accounts')
            async for page in iter_to_aiter(paginator.paginate()):
                accounts.extend(page.get('Accounts', []))
            logger.debug(f"Collected {len(accounts)} AWS accounts from Organizations.")
            return accounts
        except ClientError as e:
            if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
                logger.warning("AWS Organizations is not enabled for this account. Cannot list organization accounts.")
            else:
                logger.error(f"Error listing organization accounts: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing organization accounts: {e}")
            return []

    # @tool
    # async def get_mfa_device(self, user_name: str, serial_number: str):
    #     """
    #     Retrieves information about a specific MFA device.
    #
    #     Args:
    #         user_name (str): The name of the IAM user that the MFA device is associated with.
    #         serial_number (str): The serial number that uniquely identifies the MFA device.
    #
    #     Returns:
    #         dict: A dictionary containing MFA device details, or None if not found or an error occurs.
    #     """
    #     try:
    #         response = await sync_to_async(self.iam_client.get_mfa_device, UserName=user_name,
    #                                        SerialNumber=serial_number)
    #         return response
    #     except ClientError as e:
    #         if e.response['Error']['Code'] == 'NoSuchEntity':
    #             logger.debug(f"MFA device '{serial_number}' not found for user '{user_name}'.")
    #         else:
    #             msg = f"Error getting MFA device '{serial_number}' for user '{user_name}': {e}"
    #             logger.error(f"Error getting MFA device '{serial_number}' for user '{user_name}': {e}")
    #         return None

    # @tool
    # async def get_login_profile(self, user_name: str):
    #     """
    #     Retrieves the login profile (password details, not the password itself) for the specified IAM user.
    #     Relevant for GRC auditing of console password creation dates and existence.
    #
    #     Args:
    #         user_name (str): The name of the IAM user.
    #
    #     Returns:
    #         dict: A dictionary containing 'UserName' and 'CreateDate' of the login profile,
    #               or None if not found (user might not have a console password) or an error occurs.
    #     """
    #     try:
    #         response = await sync_to_async(self.iam_client.get_login_profile, UserName=user_name)
    #         logger.debug(f"Retrieved login profile details for user '{user_name}'.")
    #         return response['LoginProfile']
    #     except ClientError as e:
    #         if e.response['Error']['Code'] == 'NoSuchEntity':
    #             logger.debug(
    #                 f"Login profile not found for user '{user_name}'. This user might not have a console password.")
    #         else:
    #             logger.error(f"Error getting login profile for user '{user_name}': {e}")
    #         return None

    # @tool
    # async def list_access_keys(self, user_name: str = None):
    #     """
    #     Lists the access keys for the specified IAM user. If no user_name is provided,
    #     it lists access keys for the calling user.
    #     Relevant for auditing access key existence and status.
    #
    #     Args:
    #         user_name (str, optional): The name of the IAM user. Defaults to None.
    #
    #     Returns:
    #         list: A list of dictionaries, each containing 'AccessKeyId', 'CreateDate', 'Status', etc.,
    #               or an empty list if an error occurs.
    #     """
    #     try:
    #         if user_name:
    #             response = await sync_to_async(self.iam_client.list_access_keys, UserName=user_name)
    #         else:
    #             response = await sync_to_async(self.iam_client.list_access_keys)
    #         return response['AccessKeyMetadata']
    #     except ClientError as e:
    #         logger.error(f"Error listing access keys: {e}")
    #         return []

    # @tool
    # async def get_access_key_last_used(self, access_key_id: str):
    #     """
    #     Retrieves information about when the specified access key was last used.
    #     Crucial for identifying inactive access keys as part of GRC.
    #
    #     Args:
    #         access_key_id (str): The ID of the access key.
    #
    #     Returns:
    #         dict: A dictionary containing 'UserName', 'LastUsedDate', and 'ServiceName',
    #               or None if not found or an error occurs.
    #     """
    #     try:
    #         response = await sync_to_async(self.iam_client.get_access_key_last_used, AccessKeyId=access_key_id)
    #         return response.get('AccessKeyLastUsed')
    #     except ClientError as e:
    #         if e.response['Error']['Code'] == 'NoSuchEntity':
    #             logger.debug(f"Access key '{access_key_id}' not found.")
    #         else:
    #             logger.error(f"Error getting access key last used for '{access_key_id}': {e}")
    #         return None

    # @tool
    # async def get_policy_version(self, policy_arn: str, version_id: str):
    #     """
    #     Retrieves information about the specified version of the specified managed policy.
    #     Useful for examining specific policy versions, not just the default.
    #
    #     Args:
    #         policy_arn (str): The ARN of the managed policy.
    #         version_id (str): The ID of the policy version to retrieve.
    #
    #     Returns:
    #         dict: A dictionary containing the policy version details, including the policy document,
    #               or None if not found or an error occurs.
    #     """
    #     try:
    #         response = await sync_to_async(
    #             self.iam_client.get_policy_version,
    #             PolicyArn=policy_arn,
    #             VersionId=version_id
    #         )
    #         # Ensure the document is loaded correctly if it's a string
    #         policy_version_data = response['PolicyVersion']
    #         if isinstance(policy_version_data.get('Document'), str):
    #             policy_version_data['Document'] = json.loads(policy_version_data['Document'])
    #         return policy_version_data
    #     except ClientError as e:
    #         if e.response['Error']['Code'] == 'NoSuchEntity':
    #             logger.debug(f"Policy version '{version_id}' not found for policy '{policy_arn}'.")
    #         else:
    #             logger.error(f"Error getting policy version '{version_id}' for '{policy_arn}': {e}")
    #         return None
