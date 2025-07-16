import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import iter_to_aiter

logger = logging.getLogger(__name__)


class EntraIAMHandler(BaseHandler):
    """
    A handler class for interaction with Identity and Access Management (IAM) of Microsoft Entra ID.
    This class extends BaseHandler (from superagentx) and provides methods for retrieving
    IAM related information from Microsoft Entra ID for Governance, Risk,
    and Compliance (GRC) evidence purposes.
    This class only implements 'get' operations and does not support create, update, or delete operations.
    """

    def __init__(
        self,
        *,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None
    ):
        super().__init__()
        """
        Initializes the Microsoft Entra ID IAM Handler with an authenticated Microsoft Graph client.

        Args:
            tenant_id (str, optional): Your Microsoft Entra ID tenant ID. Defaults to ENTRA_TENANT_ID environment variable.
            client_id (str, optional): The Application (client) ID of your registered Entra ID application. Defaults to ENTRA_CLIENT_ID environment variable.
            client_secret (str, optional): The client secret of your registered Entra ID application. Defaults to ENTRA_CLIENT_SECRET environment variable.
        """
        # Load credentials from environment variables if not provided
        tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID")
        client_id = client_id or os.getenv("ENTRA_CLIENT_ID")
        client_secret = client_secret or os.getenv("ENTRA_CLIENT_SECRET")

        try:
            if not all([tenant_id, client_id, client_secret]):
                raise ValueError(
                    "All Microsoft Entra ID credentials (tenant_id, client_id, client_secret) "
                    "must be provided either directly or via ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET environment variables."
                )

            # Authenticate using Client Secret Credential
            credentials = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )

            # Initialize the Microsoft Graph client
            self.graph_client = GraphServiceClient(credentials)
            logger.debug(
                "Microsoft Graph client initialized with custom credentials.")

        except Exception as e:
            logger.error(
                f"Error initializing Microsoft Graph client: {e}", exc_info=True)
            raise

    async def _get_user_details_and_roles(self, user_id: str) -> dict:
        """
        Helper method to fetch details and assigned roles for a given user.
        This method is internal and not exposed as a tool directly.
        Requires User.Read.All and RoleManagement.Read.All permissions (for comprehensive roles).
        """
        try:
            user = await self.graph_client.users.by_user_id(user_id).get()
            if user:
                return {
                    "id": user.id,
                    "displayName": user.display_name,
                    "userPrincipalName": user.user_principal_name,
                    "mail": user.mail,
                    "userType": user.user_type,
                    "assignedRoles": []
                }

            logger.debug(f"Successfully retrieved user details for: {user_id}")
        except Exception as e:
            logger.error(
                f"Error retrieving user details or roles for {user_id}. Error: {e}", exc_info=True)
        return {}

    async def _get_group_details_and_members(self, group_id: str) -> dict:
        """
        Helper method to fetch details and members for a given group.
        This method is internal and not exposed as a tool directly.
        Requires Group.Read.All and optionally User.Read.All, Device.Read.All, ServicePrincipal.Read.All for members.
        """
        try:
            group = await self.graph_client.groups.by_group_id(group_id).get()
            if group:
                group_info = {
                    "id": group.id,
                    "displayName": group.display_name,
                    "mailNickname": group.mail_nickname,
                    "securityEnabled": group.security_enabled,
                    "groupTypes": list(group.group_types) if group.group_types else [],
                    "members": []
                }

                members_result = await self.graph_client.groups.by_group_id(group_id).members.get()
                if members_result and members_result.value:
                    async for member in iter_to_aiter(members_result.value):
                        member_details = {"id": member.id,
                                          "odata_type": member.odata_type}
                        if hasattr(member, "display_name"):
                            member_details["displayName"] = member.display_name
                        if hasattr(member, "user_principal_name"):
                            member_details["userPrincipalName"] = member.user_principal_name
                        group_info["members"].append(member_details)

                logger.debug(f"Successfully retrieved group details for: {group_id}")
                return group_info
        except Exception as e:
            logger.error(
                f"Error retrieving group details or members for {group_id}. Error: {e}", exc_info=True)
        return {}

    async def _get_application_details_and_owners(self, app_id: str) -> dict:
        """
        Helper method to fetch details and owners for a given application (Service Principal).
        This method is internal and not exposed as a tool directly.
        Requires Application.Read.All.
        """
        try:
            service_principal = await self.graph_client.service_principals.by_service_principal_id(app_id).get()
            if service_principal:
                app_info = {
                    "id": service_principal.id,
                    "appId": service_principal.app_id,  # This is the application object's client_id
                    "displayName": service_principal.display_name,
                    "servicePrincipalType": service_principal.service_principal_type,
                    "owners": []
                }
                # Get owners of the service principal
                owners_result = await self.graph_client.service_principals.by_service_principal_id(app_id).owners.get()
                if owners_result and owners_result.value:
                    async for owner in iter_to_aiter(owners_result.value):
                        owner_details = {"id": owner.id,
                                         "odata_type": owner.odata_type}
                        if hasattr(owner, "display_name"):
                            owner_details["displayName"] = owner.display_name
                        app_info["owners"].append(owner_details)

                logger.debug(f"Successfully retrieved application details for: {app_id}")
                return app_info
        except Exception as e:
            logger.error(
                f"Error retrieving application details or owners for {app_id}. Error: {e}", exc_info=True)
        return {}

    @tool
    async def collect_users_iam_evidence(self) -> list:
        """
        Collects IAM related evidence for all accessible users in Microsoft Entra ID.
        This includes user profiles and a placeholder for directly assigned roles.
        Requires the 'User.Read.All' Microsoft Graph API permission. For comprehensive role details,
        'RoleManagement.Read.All' or 'Directory.Read.All' may be needed for broader access to role assignments.

        Returns:
            list: A list of dictionaries, where each dictionary contains
                  user details and their assigned roles.
        """
        logger.debug("\nCollecting IAM evidence for Users...")
        user_evidence = []
        try:
            # List all users. Requires User.Read.All permission.
            users_response = await self.graph_client.users.get()
            if users_response and users_response.value:
                async for user in iter_to_aiter(users_response.value):
                    user_details = await self._get_user_details_and_roles(user.id)
                    if user_details:
                        user_evidence.append(user_details)
            logger.debug(f"Collected {len(user_evidence)} user records.")
        except Exception as e:
            logger.error(f"An error occurred while collecting user IAM evidence: {e}", exc_info=True)
            logger.error(
                "Ensure the Entra ID application has 'User.Read.All' and potentially 'RoleManagement.Read.All'"
                " permissions."
            )
        return user_evidence

    @tool
    async def collect_groups_iam_evidence(self) -> list:
        """
        Collects IAM related evidence for all accessible groups in Microsoft Entra ID.
        This includes group details and its members.
        Requires the 'Group.Read.All' Microsoft Graph API permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains
                  group details and its members.
        """
        logger.debug("\nCollecting IAM evidence for Groups...")
        group_evidence = []
        try:
            # List all groups. Requires Group.Read.All permission.
            groups_response = await self.graph_client.groups.get()
            if groups_response and groups_response.value:
                async for group in iter_to_aiter(groups_response.value):
                    group_details = await self._get_group_details_and_members(group.id)
                    if group_details:
                        group_evidence.append(group_details)
            logger.debug(f"Collected {len(group_evidence)} group records.")
        except Exception as e:
            logger.error(f"An error occurred while collecting group IAM evidence: {e}", exc_info=True)
            logger.error("Ensure the Entra ID application has 'Group.Read.All' permission.")
        return group_evidence

    @tool
    async def collect_applications_iam_evidence(self) -> list:
        """
        Collects IAM related evidence for all accessible applications (Service Principals) in Microsoft Entra ID.
        This includes application details and their owners.
        Requires the 'Application.Read.All' Microsoft Graph API permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains
                  application details and its owners.
        """
        logger.debug(
            "\nCollecting IAM evidence for Applications (Service Principals)...")
        app_evidence = []
        try:
            # List all service principals. Requires Application.Read.All permission.
            service_principals_response = await self.graph_client.service_principals.get()
            if service_principals_response and service_principals_response.value:
                async for sp in iter_to_aiter(service_principals_response.value):
                    app_details = await self._get_application_details_and_owners(sp.id)
                    if app_details:
                        app_evidence.append(app_details)
            logger.debug(f"Collected {len(app_evidence)} application records.")
        except Exception as e:
            logger.error(f"An error occurred while collecting application IAM evidence: {e}", exc_info=True)
            logger.error("Ensure the Entra ID application has 'Application.Read.All' permission.")
        return app_evidence

    @tool
    async def collect_roles_definitions(self) -> list:
        """
        Collects definitions of built-in and custom roles in Microsoft Entra ID.
        This provides details about what permissions each role encompasses.
        Requires the 'RoleManagement.Read.Directory' Microsoft Graph API permission.

        Returns:
            list: A list of dictionaries, where each dictionary contains
                role definition details.
        """
        logger.debug("\nCollecting Microsoft Entra ID Role Definitions...")
        role_definitions = []
        try:
            roles_response = await self.graph_client.directory_roles.get()
            if roles_response and roles_response.value:
                async for role in iter_to_aiter(roles_response.value):
                    role_definitions.append({
                        "id": role.id,
                        "displayName": role.display_name,
                        "description": role.description,
                        "roleTemplateId": role.role_template_id
                    })
            logger.debug(
                f"Collected {len(role_definitions)} role definitions.")

        except Exception as e:
            logger.error(f"Error collecting role definitions: {e}", exc_info=True)
            logger.error("Ensure the Entra ID application has 'RoleManagement.Read.Directory' permission.")
        return role_definitions

    @tool
    async def collect_mfa_status_evidence(self, days_ago: int = 30) -> list:
        """
        Collects MFA registration status and recent MFA usage from sign-in logs for all users.
        Args:
            days_ago (int): Number of days to look back for sign-in logs. Default is 30.
                            Sign-in logs are typically retained for 30 days in Entra ID.
        Requires 'Reports.Read.All', 'UserAuthenticationMethod.Read.All', and 'AuditLog.Read.All'
        Microsoft Graph API permissions.

        Returns:
            list: A list of dictionaries, where each dictionary contains user MFA details.
        """
        logger.debug(f"\nCollecting MFA status evidence for users (registration and usage for last {days_ago} days)...")
        mfa_evidence = []
        users_with_mfa_data = {}  # To store combined data for each user

        try:
            # 1. Fetch MFA Registration Status for all users from userRegistrationDetails
            # Requires Reports.Read.All permission.
            logger.debug(
                "Fetching MFA registration details from /reports/authenticationMethods/userRegistrationDetails..."
            )
            # This endpoint provides `is_mfa_registered`, `is_mfa_capable`, and `methods_registered`
            registration_details_response = await (
                self.graph_client.reports.authentication_methods.user_registration_details.get()
            )

            if registration_details_response and registration_details_response.value:
                # Use iter_to_aiter to correctly handle async iteration over the collection
                async for detail in iter_to_aiter(registration_details_response.value):
                    users_with_mfa_data[detail.id] = {
                        "id": detail.id,
                        "displayName": detail.display_name,
                        "userPrincipalName": detail.user_principal_name,
                        # This is the correct attribute from UserRegistrationDetails
                        "isMfaRegistered": detail.is_mfa_registered,
                        "isMfaCapable": detail.is_mfa_capable,
                        "registeredMethodsSummary": list(detail.methods_registered) if detail.methods_registered else [],
                        # Detailed methods via authentication/methods, fetched separately
                        "registeredAuthenticationMethods": [],
                        "recentMfaAttempts": []
                    }
                logger.debug(f"Retrieved MFA registration status for {len(users_with_mfa_data)} users.")
            else:
                logger.warning("No user registration details found.")

            # 2. Fetch Registered Authentication Methods for each user (optional, but good for detail)
            logger.debug("Collecting registered authentication methods (this may take a while for many users)...")
            # Create a list of tasks to run concurrently for faster execution
            tasks = []
            for user_id, user_data in users_with_mfa_data.items():
                async def fetch_auth_methods(u_id, u_data):
                    try:
                        auth_methods_response = await (
                            self.graph_client.users.by_user_id(u_id).authentication.methods.get()
                        )
                        if auth_methods_response and auth_methods_response.value:
                            async for method in iter_to_aiter(auth_methods_response.value):
                                u_data["registeredAuthenticationMethods"].append(
                                    {"type": method.odata_type.split('.')[-1].replace('AuthenticationMethod', ''),
                                     "id": method.id}  # basic info, can add more detail based on type
                                )
                    except Exception as e:
                        u_data["registeredAuthenticationMethods"].append(
                            {"error": f"Could not retrieve authentication methods for user {u_id}: {e}"})
                        logger.debug(
                            f"Could not retrieve authentication methods "
                            f"for {u_data.get('userPrincipalName', u_id)}. Error: {e}"
                        )
                tasks.append(fetch_auth_methods(user_id, user_data))

            # Run all tasks concurrently
            await asyncio.gather(*tasks)
            logger.debug(
                "Finished collecting registered authentication methods.")

            # 3. Fetch recent MFA usage from Sign-in Logs
            now_utc = datetime.now(timezone.utc)
            start_date_time = now_utc - timedelta(days=days_ago)
            # Format the date-time string in ISO 8601 format with 'Z' for UTC
            filter_string = (
                f"createdDateTime ge "
                f"{start_date_time.isoformat(timespec='seconds').replace('+00:00', 'Z')}"
            )

            logger.debug(
                f"Collecting sign-in logs for MFA usage since "
                f"{start_date_time.isoformat(timespec='seconds').replace('+00:00', 'Z')}..."
            )

            mfa_sign_ins = []
            params = {
                "$filter": filter_string,
                "$top": 999,  # Max top value for sign-in logs is 999
                "$select": "id,userId,userPrincipalName,createdDateTime,status,authenticationRequirement,"
                           "authenticationMethodsUsed,authenticationDetails"
            }
            sign_ins_response = await self.graph_client.audit_logs.sign_ins.get(
                query_parameters=params
            )

            while sign_ins_response:
                if sign_ins_response.value:
                    async for sign_in in iter_to_aiter(sign_ins_response.value):
                        # Determine if MFA was involved in the sign-in
                        is_mfa_attempt = False
                        if sign_in.authentication_requirement in [
                            "multiFactorAuthentication", "multiFactorAuthenticationService"
                        ]:
                            is_mfa_attempt = True
                        elif sign_in.authentication_details:
                            # Check authentication details for MFA-related steps
                            for detail in sign_in.authentication_details:
                                if (detail.authentication_step_result_detail
                                        and "MFA" in detail.authentication_step_result_detail):
                                    is_mfa_attempt = True
                                    break
                        # You can add more heuristics if needed, but these are common

                        if is_mfa_attempt:
                            mfa_sign_ins.append({
                                "id": sign_in.id,
                                "userId": sign_in.user_id,
                                "userPrincipalName": sign_in.user_principal_name,
                                "createdDateTime": sign_in.created_date_time.isoformat() if sign_in.created_date_time else None,
                                "status": "Success" if sign_in.status and sign_in.status.is_successful else "Failure",
                                "authenticationRequirement": sign_in.authentication_requirement,
                                "authenticationMethodsUsed": sign_in.authentication_methods_used,
                                "authenticationDetails": [{
                                    "step": d.authentication_step, "resultDetail": d.authentication_step_result_detail
                                }
                                    for d in sign_in.authentication_details
                                ] if sign_in.authentication_details else []
                            })

                # Handle pagination if there's a next link
                if sign_ins_response.odata_next_link:
                    sign_ins_response = await self.graph_client.audit_logs.sign_ins.by_url(
                        sign_ins_response.odata_next_link
                    ).get()
                    logger.debug(f"Fetching next page of sign-in logs...")
                else:
                    sign_ins_response = None  # No more pages

            logger.debug(
                f"Collected {len(mfa_sign_ins)} relevant sign-in records for MFA analysis.")

            # Aggregate sign-in usage into user data
            for sign_in_record in mfa_sign_ins:  # Iterating over a list directly is fine here
                user_id = sign_in_record.get("userId")
                if user_id and user_id in users_with_mfa_data:
                    users_with_mfa_data[user_id]["recentMfaAttempts"].append(
                        sign_in_record)
                elif user_id:
                    # Log if a sign-in record refers to a user not in our registration details list
                    logger.debug(
                        f"Sign-in record for user ID {user_id} ({sign_in_record.get('userPrincipalName')})"
                        f" found but not in user registration details. Skipping aggregation."
                    )

            # Convert dictionary back to list for final output
            mfa_evidence = list(users_with_mfa_data.values())
            logger.debug(
                f"Finished collecting MFA status evidence for {len(mfa_evidence)} users.")

        except Exception as e:
            logger.error(
                f"An error occurred while collecting MFA status evidence: {e}", exc_info=True)

        return mfa_evidence

    # @tool
    async def collect_all_entra_iam_evidence(self) -> dict:
        """
        Collects IAM related information for all accessible users, groups, applications,
        and role definitions in Microsoft Entra ID. This method orchestrates calls
        to other specific collection tools.

        Returns:
            dict: A dictionary containing lists of evidence for users, groups,
            applications, and role definitions.
        """
        logger.debug("\nCollecting ALL Microsoft Entra ID IAM evidence...")
        all_evidence = {
            "users": [],
            "groups": [],
            "applications": [],
            "roleDefinitions": [],
            "mfaStatus": []
        }

        # Call the individual tool methods
        all_evidence["users"] = await self.collect_users_iam_evidence()
        all_evidence["groups"] = await self.collect_groups_iam_evidence()
        all_evidence["applications"] = await self.collect_applications_iam_evidence()
        all_evidence["roleDefinitions"] = await self.collect_roles_definitions()
        all_evidence["mfaStatus"] = await self.collect_mfa_status_evidence()

        logger.debug(
            "\nFinished collecting all Microsoft Entra ID IAM evidence.")
        return all_evidence
