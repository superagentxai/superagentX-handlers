import boto3
import logging
import os
from botocore.exceptions import ClientError
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async
from typing import Optional

from superagentx_handlers.aws.helper import generate_aws_sts_token

logger = logging.getLogger(__name__)


class AWSCognitoHandler(BaseHandler):
    """
    AWS Cognito Handler for managing User Pools, Clients, and IdPs.
    """

    def __init__(
        self,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        region_name: Optional[str] = None,
        aws_role_arn: Optional[str] = None,
        role_session_name: Optional[str] = None,
        external_id: Optional[str] = None,
    ):
        super().__init__()
        region = region_name or os.getenv("AWS_REGION")
        aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")

        # Assume role with STS for secure, temporary credentials
        self.credentials = generate_aws_sts_token(
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_role_arn=aws_role_arn,
            role_session_name=role_session_name,
            external_id=external_id,
        )

        # Initialize Cognito client
        self.cognito_client = boto3.client(
            "cognito-idp",
            **self.credentials,
        )

    async def _call(self, method: str, **kwargs) -> dict:
        """
        Generic async wrapper for Cognito boto3 calls.
        """
        try:
            _function = getattr(self.cognito_client, method)
            response = await sync_to_async(_function, **kwargs)
            logger.info(f"Cognito {method} success: {response}")
            return response
        except ClientError as e:
            logger.error(f"Cognito {method} failed: {e}")
            return {"error": str(e)}

    # ---------------- TOOLS ---------------- #

    @tool
    async def add_custom_attributes(self, user_pool_id: str, custom_attributes: list[dict]) -> dict:
        """
        Add custom attributes to a User Pool.
        """
        return await self._call(
            "add_custom_attributes",
            UserPoolId=user_pool_id,
            CustomAttributes=custom_attributes,
        )

    @tool
    async def admin_add_user_to_group(self, user_pool_id: str, username: str, group_name: str) -> dict:
        return await self._call(
            "admin_add_user_to_group",
            UserPoolId=user_pool_id,
            Username=username,
            GroupName=group_name,
        )

    @tool
    async def admin_confirm_sign_up(self, user_pool_id: str, username: str, **kwargs) -> dict:
        return await self._call(
            "admin_confirm_sign_up",
            UserPoolId=user_pool_id,
            Username=username,
            **kwargs
        )

    @tool
    async def admin_create_user(self, user_pool_id: str, username: str, temporary_password: str, user_attributes: list[dict], **kwargs) -> dict:
        return await self._call(
            "admin_create_user",
            UserPoolId=user_pool_id,
            Username=username,
            TemporaryPassword=temporary_password,
            UserAttributes=user_attributes,
            **kwargs
        )

    @tool
    async def admin_delete_user(self, user_pool_id: str, username: str) -> dict:
        return await self._call(
            "admin_delete_user",
            UserPoolId=user_pool_id,
            Username=username,
        )

    @tool
    async def admin_delete_user_attributes(self, user_pool_id: str, username: str, attributes: list[str]) -> dict:
        return await self._call(
            "admin_delete_user_attributes",
            UserPoolId=user_pool_id,
            Username=username,
            UserAttributeNames=attributes,
        )

    @tool
    async def admin_disable_provider_for_user(self, user_pool_id: str, provider_name: str, provider_user_id: str, **kwargs) -> dict:
        return await self._call(
            "admin_disable_provider_for_user",
            UserPoolId=user_pool_id,
            User={"ProviderName": provider_name, "ProviderAttributeValue": provider_user_id, **kwargs},
        )

    @tool
    async def admin_disable_user(self, user_pool_id: str, username: str) -> dict:
        return await self._call(
            "admin_disable_user",
            UserPoolId=user_pool_id,
            Username=username,
        )

    @tool
    async def admin_enable_user(self, user_pool_id: str, username: str) -> dict:
        return await self._call(
            "admin_enable_user",
            UserPoolId=user_pool_id,
            Username=username,
        )

    @tool
    async def admin_forget_device(self, user_pool_id: str, username: str, device_key: str) -> dict:
        return await self._call(
            "admin_forget_device",
            UserPoolId=user_pool_id,
            Username=username,
            DeviceKey=device_key,
        )

    @tool
    async def admin_get_device(self, user_pool_id: str, username: str, device_key: str) -> dict:
        return await self._call(
            "admin_get_device",
            UserPoolId=user_pool_id,
            Username=username,
            DeviceKey=device_key,
        )

    @tool
    async def admin_get_user(self, user_pool_id: str, username: str) -> dict:
        return await self._call(
            "admin_get_user",
            UserPoolId=user_pool_id,
            Username=username,
        )

    @tool
    async def admin_initiate_auth(self, user_pool_id: str, client_id: str, auth_flow: str, auth_parameters: dict, **kwargs) -> dict:
        return await self._call(
            "admin_initiate_auth",
            UserPoolId=user_pool_id,
            ClientId=client_id,
            AuthFlow=auth_flow,
            AuthParameters=auth_parameters,
            **kwargs
        )

    @tool
    async def admin_link_provider_for_user(self, user_pool_id: str, destination: dict, source: dict) -> dict:
        return await self._call(
            "admin_link_provider_for_user",
            UserPoolId=user_pool_id,
            DestinationUser=destination,
            SourceUser=source,
        )

    @tool
    async def admin_list_devices(self, user_pool_id: str, username: str, limit: int = 10, **kwargs) -> dict:
        return await self._call(
            "admin_list_devices",
            UserPoolId=user_pool_id,
            Username=username,
            Limit=limit,
            **kwargs
        )

    @tool
    async def admin_list_groups_for_user(self, user_pool_id: str, username: str, **kwargs) -> dict:
        return await self._call(
            "admin_list_groups_for_user",
            UserPoolId=user_pool_id,
            Username=username,
            **kwargs
        )

    @tool
    async def admin_list_user_auth_events(self, user_pool_id: str, username: str, max_results: int = 10, **kwargs) -> dict:
        return await self._call(
            "admin_list_user_auth_events",
            UserPoolId=user_pool_id,
            Username=username,
            MaxResults=max_results,
            **kwargs
        )

    @tool
    async def admin_remove_user_from_group(self, user_pool_id: str, username: str, group_name: str) -> dict:
        return await self._call(
            "admin_remove_user_from_group",
            UserPoolId=user_pool_id,
            Username=username,
            GroupName=group_name,
        )

    @tool
    async def admin_reset_user_password(self, user_pool_id: str, username: str, **kwargs) -> dict:
        return await self._call(
            "admin_reset_user_password",
            UserPoolId=user_pool_id,
            Username=username,
            **kwargs
        )

    @tool
    async def admin_respond_to_auth_challenge(
            self,
            user_pool_id: str,
            client_id: str,
            challenge_name: str,
            challenge_responses: dict,
            session: Optional[str] = None,
            **kwargs
    ) -> dict:
        kwargs["UserPoolId"] = user_pool_id
        kwargs["ClientId"] = client_id
        kwargs["ChallengeName"] = challenge_name
        kwargs["ChallengeResponses"] = challenge_responses
        if session:
            kwargs["Session"] = session
        return await self._call("admin_respond_to_auth_challenge", **kwargs)

    @tool
    async def admin_set_user_mfa_preference(self, user_pool_id: str, username: str, sms_mfa: dict | None = None,
                                            software_token_mfa: dict | None = None, **kwargs) -> dict:
        return await self._call(
            "admin_set_user_mfa_preference",
            UserPoolId=user_pool_id,
            Username=username,
            SMSMfaSettings=sms_mfa,
            SoftwareTokenMfaSettings=software_token_mfa,
            **kwargs
        )

    @tool
    async def admin_set_user_password(self, user_pool_id: str, username: str, password: str,
                                      permanent: bool = False) -> dict:
        return await self._call(
            "admin_set_user_password",
            UserPoolId=user_pool_id,
            Username=username,
            Password=password,
            Permanent=permanent,
        )

    @tool
    async def admin_set_user_settings(self, user_pool_id: str, username: str, mfa_options: list[dict]) -> dict:
        return await self._call(
            "admin_set_user_settings",
            UserPoolId=user_pool_id,
            Username=username,
            MFAOptions=mfa_options,
        )

    @tool
    async def admin_update_auth_event_feedback(self, user_pool_id: str, username: str, event_id: str,
                                               feedback_value: str) -> dict:
        return await self._call(
            "admin_update_auth_event_feedback",
            UserPoolId=user_pool_id,
            Username=username,
            EventId=event_id,
            FeedbackValue=feedback_value,
        )

    @tool
    async def admin_update_device_status(self, user_pool_id: str, username: str, device_key: str,
                                         device_remembered_status: str) -> dict:
        return await self._call(
            "admin_update_device_status",
            UserPoolId=user_pool_id,
            Username=username,
            DeviceKey=device_key,
            DeviceRememberedStatus=device_remembered_status,
        )

    @tool
    async def admin_update_user_attributes(self, user_pool_id: str, username: str, attributes: list[dict], **kwargs) -> dict:
        return await self._call(
            "admin_update_user_attributes",
            UserPoolId=user_pool_id,
            Username=username,
            UserAttributes=attributes,
            **kwargs
        )

    @tool
    async def admin_user_global_sign_out(self, user_pool_id: str, username: str) -> dict:
        return await self._call(
            "admin_user_global_sign_out",
            UserPoolId=user_pool_id,
            Username=username,
        )

    @tool
    async def associate_software_token(
            self,
            access_token: Optional[str] = None,
            session: Optional[str] = None,
            **kwargs
    ) -> dict:
        if access_token:
            kwargs["AccessToken"] = access_token
        if session:
            kwargs["Session"] = session
        return await self._call("associate_software_token", **kwargs)

    @tool
    async def can_paginate(self, operation_name: str) -> dict:
        result = await sync_to_async(self.cognito_client.can_paginate, operation_name)
        return {"operation": operation_name, "can_paginate": result}

    @tool
    async def change_password(self, previous_password: str, proposed_password: str, access_token: str) -> dict:
        return await self._call(
            "change_password",
            PreviousPassword=previous_password,
            ProposedPassword=proposed_password,
            AccessToken=access_token,
        )

    @tool
    async def close(self) -> dict:
        return await sync_to_async(self.cognito_client.close)

    @tool
    async def complete_web_authn_registration(self, access_token: str, credential: dict) -> dict:
        return await self._call(
            "complete_web_authn_registration",
            AccessToken=access_token,
            Credential=credential,
        )

    @tool
    async def confirm_device(
            self,
            access_token: str,
            device_key: str,
            device_secret_verifier_config: dict,
            device_name: Optional[str] = None
    ) -> dict:
        kwargs = {
            "AccessToken": access_token,
            "DeviceKey": device_key,
            "DeviceSecretVerifierConfig": device_secret_verifier_config,
        }
        if device_name:
            kwargs["DeviceName"] = device_name
        return await self._call("confirm_device", **kwargs)

    @tool
    async def confirm_forgot_password(self, client_id: str, username: str, confirmation_code: str, password: str,
                                      secret_hash: Optional[str] = None, session: Optional[str] = None) -> dict:
        kwargs = {
            "ClientId": client_id,
            "Username": username,
            "ConfirmationCode": confirmation_code,
            "Password": password,
        }
        if secret_hash:
            kwargs["SecretHash"] = secret_hash
        if session:
            kwargs["Session"] = session
        return await self._call("confirm_forgot_password", **kwargs)

    @tool
    async def confirm_sign_up(self, client_id: str, username: str, confirmation_code: str,
                              secret_hash: Optional[str] = None, force_alias_creation: bool = False) -> dict:
        kwargs = {
            "ClientId": client_id,
            "Username": username,
            "ConfirmationCode": confirmation_code,
            "ForceAliasCreation": force_alias_creation,
        }
        if secret_hash:
            kwargs["SecretHash"] = secret_hash
        return await self._call("confirm_sign_up", **kwargs)

    @tool
    async def create_group(self, group_name: str, user_pool_id: str, description: Optional[str] = None,
                           role_arn: Optional[str] = None, precedence: int | None = None) -> dict:
        kwargs = {"GroupName": group_name, "UserPoolId": user_pool_id}
        if description:
            kwargs["Description"] = description
        if role_arn:
            kwargs["RoleArn"] = role_arn
        if precedence:
            kwargs["Precedence"] = precedence
        return await self._call("create_group", **kwargs)

    @tool
    async def create_identity_provider(self, user_pool_id: str, provider_name: str, provider_type: str,
                                       provider_details: dict, attribute_mapping: dict | None = None,
                                       idp_identifiers: list[str] | None = None) -> dict:
        kwargs = {
            "UserPoolId": user_pool_id,
            "ProviderName": provider_name,
            "ProviderType": provider_type,
            "ProviderDetails": provider_details,
        }
        if attribute_mapping:
            kwargs["AttributeMapping"] = attribute_mapping
        if idp_identifiers:
            kwargs["IdpIdentifiers"] = idp_identifiers
        return await self._call("create_identity_provider", **kwargs)

    @tool
    async def create_managed_login_branding(self, user_pool_id: str, branding_content: dict) -> dict:
        return await self._call(
            "create_managed_login_branding",
            UserPoolId=user_pool_id,
            ManagedLoginBranding=branding_content,
        )

    @tool
    async def create_resource_server(self, user_pool_id: str, identifier: str, name: str,
                                     scopes: list[dict] | None = None) -> dict:
        kwargs = {"UserPoolId": user_pool_id, "Identifier": identifier, "Name": name}
        if scopes:
            kwargs["Scopes"] = scopes
        return await self._call("create_resource_server", **kwargs)

    @tool
    async def create_terms(self, user_pool_id: str, terms: dict) -> dict:
        return await self._call("create_terms", UserPoolId=user_pool_id, Terms=terms)

    @tool
    async def create_user_import_job(self, job_name: str, user_pool_id: str, cloudwatch_arn: str,
                                     role_arn: str) -> dict:
        return await self._call(
            "create_user_import_job",
            JobName=job_name,
            UserPoolId=user_pool_id,
            CloudWatchLogsRoleArn=cloudwatch_arn,
            RoleArn=role_arn,
        )

    @tool
    async def create_user_pool(self, pool_name: str, policies: dict | None = None,
                               schema: list[dict] | None = None) -> dict:
        kwargs = {"PoolName": pool_name}
        if policies:
            kwargs["Policies"] = policies
        if schema:
            kwargs["Schema"] = schema
        return await self._call("create_user_pool", **kwargs)

    @tool
    async def create_user_pool_client(self, user_pool_id: str, client_name: str, generate_secret: bool = False,
                                      explicit_auth_flows: list[str] | None = None) -> dict:
        kwargs = {"UserPoolId": user_pool_id, "ClientName": client_name, "GenerateSecret": generate_secret}
        if explicit_auth_flows:
            kwargs["ExplicitAuthFlows"] = explicit_auth_flows
        return await self._call("create_user_pool_client", **kwargs)

    # ---------------- DOMAIN / GROUPS / PROVIDERS ---------------- #

    @tool
    async def create_user_pool_domain(self, user_pool_id: str, domain: str,
                                      custom_domain_config: dict | None = None) -> dict:
        kwargs = {"UserPoolId": user_pool_id, "Domain": domain}
        if custom_domain_config:
            kwargs["CustomDomainConfig"] = custom_domain_config
        return await self._call("create_user_pool_domain", **kwargs)

    @tool
    async def delete_group(self, group_name: str, user_pool_id: str) -> dict:
        return await self._call("delete_group", GroupName=group_name, UserPoolId=user_pool_id)

    @tool
    async def delete_identity_provider(self, user_pool_id: str, provider_name: str) -> dict:
        return await self._call("delete_identity_provider", UserPoolId=user_pool_id, ProviderName=provider_name)

    @tool
    async def delete_managed_login_branding(self, user_pool_id: str) -> dict:
        return await self._call("delete_managed_login_branding", UserPoolId=user_pool_id)

    @tool
    async def delete_resource_server(self, user_pool_id: str, identifier: str) -> dict:
        return await self._call("delete_resource_server", UserPoolId=user_pool_id, Identifier=identifier)

    @tool
    async def delete_terms(self, user_pool_id: str, terms_name: str) -> dict:
        return await self._call("delete_terms", UserPoolId=user_pool_id, TermsName=terms_name)

    @tool
    async def delete_user(self, access_token: str) -> dict:
        return await self._call("delete_user", AccessToken=access_token)

    @tool
    async def delete_user_attributes(self, access_token: str, attributes: list[str]) -> dict:
        return await self._call("delete_user_attributes", AccessToken=access_token, UserAttributeNames=attributes)

    @tool
    async def delete_user_pool(self, user_pool_id: str) -> dict:
        return await self._call("delete_user_pool", UserPoolId=user_pool_id)

    @tool
    async def delete_user_pool_client(self, user_pool_id: str, client_id: str) -> dict:
        return await self._call("delete_user_pool_client", UserPoolId=user_pool_id, ClientId=client_id)

    @tool
    async def delete_user_pool_domain(self, user_pool_id: str, domain: str) -> dict:
        return await self._call("delete_user_pool_domain", UserPoolId=user_pool_id, Domain=domain)

    @tool
    async def delete_web_authn_credential(self, access_token: str, credential_id: str) -> dict:
        return await self._call("delete_web_authn_credential", AccessToken=access_token, CredentialId=credential_id)

    # ---------------- DESCRIBE APIs ---------------- #

    @tool
    async def describe_identity_provider(self, user_pool_id: str, provider_name: str) -> dict:
        return await self._call("describe_identity_provider", UserPoolId=user_pool_id, ProviderName=provider_name)

    @tool
    async def describe_managed_login_branding(self, user_pool_id: str) -> dict:
        return await self._call("describe_managed_login_branding", UserPoolId=user_pool_id)

    @tool
    async def describe_managed_login_branding_by_client(self, user_pool_id: str, client_id: str) -> dict:
        return await self._call("describe_managed_login_branding_by_client", UserPoolId=user_pool_id,
                                ClientId=client_id)

    @tool
    async def describe_resource_server(self, user_pool_id: str, identifier: str) -> dict:
        return await self._call("describe_resource_server", UserPoolId=user_pool_id, Identifier=identifier)

    @tool
    async def describe_risk_configuration(self, user_pool_id: str, client_id: str | None = None) -> dict:
        kwargs = {"UserPoolId": user_pool_id}
        if client_id:
            kwargs["ClientId"] = client_id
        return await self._call("describe_risk_configuration", **kwargs)

    @tool
    async def describe_terms(self, user_pool_id: str, terms_name: str) -> dict:
        return await self._call("describe_terms", UserPoolId=user_pool_id, TermsName=terms_name)

    @tool
    async def describe_user_import_job(self, user_pool_id: str, job_id: str) -> dict:
        return await self._call("describe_user_import_job", UserPoolId=user_pool_id, JobId=job_id)

    @tool
    async def describe_user_pool(self, user_pool_id: str) -> dict:
        return await self._call("describe_user_pool", UserPoolId=user_pool_id)

    @tool
    async def describe_user_pool_client(self, user_pool_id: str, client_id: str) -> dict:
        return await self._call("describe_user_pool_client", UserPoolId=user_pool_id, ClientId=client_id)

    @tool
    async def describe_user_pool_domain(self, domain: str) -> dict:
        return await self._call("describe_user_pool_domain", Domain=domain)

    # ---------------- GET APIs ---------------- #

    @tool
    async def forget_device(self, access_token: str, device_key: str) -> dict:
        return await self._call("forget_device", AccessToken=access_token, DeviceKey=device_key)

    @tool
    async def forgot_password(self, client_id: str, username: str, secret_hash: str | None = None) -> dict:
        kwargs = {"ClientId": client_id, "Username": username}
        if secret_hash:
            kwargs["SecretHash"] = secret_hash
        return await self._call("forgot_password", **kwargs)

    @tool
    async def get_csv_header(self, user_pool_id: str) -> dict:
        return await self._call("get_csv_header", UserPoolId=user_pool_id)

    @tool
    async def get_device(self, access_token: str, device_key: str) -> dict:
        return await self._call("get_device", AccessToken=access_token, DeviceKey=device_key)

    @tool
    async def get_group(self, group_name: str, user_pool_id: str) -> dict:
        return await self._call("get_group", GroupName=group_name, UserPoolId=user_pool_id)

    @tool
    async def get_identity_provider_by_identifier(self, user_pool_id: str, provider_name: str) -> dict:
        return await self._call("get_identity_provider_by_identifier", UserPoolId=user_pool_id,
                                ProviderName=provider_name)

    @tool
    async def get_log_delivery_configuration(self, user_pool_id: str) -> dict:
        return await self._call("get_log_delivery_configuration", UserPoolId=user_pool_id)

    @tool
    async def get_paginator(self, operation_name: str) -> dict:
        paginator = await sync_to_async(self.cognito_client.get_paginator)(operation_name)
        return {"operation": operation_name, "paginator": str(paginator)}

    @tool
    async def get_signing_certificate(self, user_pool_id: str) -> dict:
        return await self._call("get_signing_certificate", UserPoolId=user_pool_id)

    @tool
    async def get_tokens_from_refresh_token(self, client_id: str, refresh_token: str,
                                            secret_hash: str | None = None) -> dict:
        kwargs = {"ClientId": client_id, "AuthFlow": "REFRESH_TOKEN_AUTH",
                  "AuthParameters": {"REFRESH_TOKEN": refresh_token}}
        if secret_hash:
            kwargs["AuthParameters"]["SECRET_HASH"] = secret_hash
        return await self._call("initiate_auth", **kwargs)

    @tool
    async def get_ui_customization(self, user_pool_id: str, client_id: str | None = None) -> dict:
        kwargs = {"UserPoolId": user_pool_id}
        if client_id:
            kwargs["ClientId"] = client_id
        return await self._call("get_ui_customization", **kwargs)

    @tool
    async def get_user(self, access_token: str) -> dict:
        return await self._call("get_user", AccessToken=access_token)

    @tool
    async def get_user_attribute_verification_code(self, access_token: str, attribute_name: str,
                                                   client_metadata: dict | None = None) -> dict:
        kwargs = {"AccessToken": access_token, "AttributeName": attribute_name}
        if client_metadata:
            kwargs["ClientMetadata"] = client_metadata
        return await self._call("get_user_attribute_verification_code", **kwargs)

    @tool
    async def get_user_auth_factors(self, access_token: str) -> dict:
        return await self._call("get_user_auth_factors", AccessToken=access_token)

    @tool
    async def get_user_pool_mfa_config(self, user_pool_id: str) -> dict:
        return await self._call("get_user_pool_mfa_config", UserPoolId=user_pool_id)

    @tool
    async def get_waiter(self, waiter_name: str) -> dict:
        waiter = await sync_to_async(self.cognito_client.get_waiter)(waiter_name)
        return {"waiter_name": waiter_name, "waiter": str(waiter)}

    # ---------------- AUTH FLOWS ---------------- #

    @tool
    async def global_sign_out(self, access_token: str) -> dict:
        return await self._call("global_sign_out", AccessToken=access_token)

    @tool
    async def initiate_auth(self, client_id: str, auth_flow: str, auth_parameters: dict,
                            client_metadata: dict | None = None) -> dict:
        kwargs = {"ClientId": client_id, "AuthFlow": auth_flow, "AuthParameters": auth_parameters}
        if client_metadata:
            kwargs["ClientMetadata"] = client_metadata
        return await self._call("initiate_auth", **kwargs)

    @tool
    async def list_devices(self, access_token: str, limit: int = 10) -> dict:
        return await self._call("list_devices", AccessToken=access_token, Limit=limit)

    @tool
    async def list_groups(self, user_pool_id: str, limit: int = 10) -> dict:
        return await self._call("list_groups", UserPoolId=user_pool_id, Limit=limit)

    @tool
    async def list_identity_providers(self, user_pool_id: str, max_results: int = 10) -> dict:
        return await self._call("list_identity_providers", UserPoolId=user_pool_id, MaxResults=max_results)

    @tool
    async def list_resource_servers(self, user_pool_id: str, max_results: int = 10) -> dict:
        return await self._call("list_resource_servers", UserPoolId=user_pool_id, MaxResults=max_results)

    @tool
    async def list_tags_for_resource(self, resource_arn: str) -> dict:
        return await self._call("list_tags_for_resource", ResourceArn=resource_arn)

    @tool
    async def list_terms(self, user_pool_id: str, max_results: int = 10) -> dict:
        return await self._call("list_terms", UserPoolId=user_pool_id, MaxResults=max_results)

    @tool
    async def list_user_import_jobs(self, user_pool_id: str, max_results: int = 10) -> dict:
        return await self._call("list_user_import_jobs", UserPoolId=user_pool_id, MaxResults=max_results)

    @tool
    async def list_user_pool_clients(self, user_pool_id: str, max_results: int = 10) -> dict:
        return await self._call("list_user_pool_clients", UserPoolId=user_pool_id, MaxResults=max_results)

    @tool
    async def list_user_pools(self, max_results: int = 10) -> dict:
        return await self._call("list_user_pools", MaxResults=max_results)

    @tool
    async def list_users(self, user_pool_id: str, limit: int = 10) -> dict:
        return await self._call("list_users", UserPoolId=user_pool_id, Limit=limit)

    @tool
    async def list_users_in_group(self, user_pool_id: str, group_name: str, limit: int = 10) -> dict:
        return await self._call("list_users_in_group", UserPoolId=user_pool_id, GroupName=group_name, Limit=limit)

    @tool
    async def list_web_authn_credentials(self, access_token: str) -> dict:
        return await self._call("list_web_authn_credentials", AccessToken=access_token)

    # ---------------- CONFIRM / RESPOND / SIGNUP ---------------- #

    @tool
    async def resend_confirmation_code(self, client_id: str, username: str, secret_hash: str | None = None) -> dict:
        kwargs = {"ClientId": client_id, "Username": username}
        if secret_hash:
            kwargs["SecretHash"] = secret_hash
        return await self._call("resend_confirmation_code", **kwargs)

    @tool
    async def respond_to_auth_challenge(self, client_id: str, challenge_name: str, challenge_responses: dict,
                                        session: str | None = None) -> dict:
        kwargs = {"ClientId": client_id, "ChallengeName": challenge_name, "ChallengeResponses": challenge_responses}
        if session:
            kwargs["Session"] = session
        return await self._call("respond_to_auth_challenge", **kwargs)

    @tool
    async def revoke_token(self, token: str, client_id: str, client_secret: str | None = None) -> dict:
        kwargs = {"Token": token, "ClientId": client_id}
        if client_secret:
            kwargs["ClientSecret"] = client_secret
        return await self._call("revoke_token", **kwargs)

    @tool
    async def set_log_delivery_configuration(self, user_pool_id: str, log_config: dict) -> dict:
        return await self._call("set_log_delivery_configuration", UserPoolId=user_pool_id,
                                LogDeliveryConfiguration=log_config)

    @tool
    async def set_risk_configuration(self, user_pool_id: str, risk_config: dict, client_id: str | None = None) -> dict:
        kwargs = {"UserPoolId": user_pool_id, "RiskConfiguration": risk_config}
        if client_id:
            kwargs["ClientId"] = client_id
        return await self._call("set_risk_configuration", **kwargs)

    @tool
    async def set_ui_customization(self, user_pool_id: str, ui_config: dict, client_id: str | None = None) -> dict:
        kwargs = {"UserPoolId": user_pool_id, "UICustomization": ui_config}
        if client_id:
            kwargs["ClientId"] = client_id
        return await self._call("set_ui_customization", **kwargs)

    @tool
    async def set_user_mfa_preference(self, access_token: str, sms_mfa: dict | None = None,
                                      software_mfa: dict | None = None) -> dict:
        return await self._call("set_user_mfa_preference", AccessToken=access_token, SMSMfaSettings=sms_mfa,
                                SoftwareTokenMfaSettings=software_mfa)

    @tool
    async def set_user_pool_mfa_config(self, user_pool_id: str, mfa_config: dict) -> dict:
        return await self._call("set_user_pool_mfa_config", UserPoolId=user_pool_id, MfaConfiguration=mfa_config)

    @tool
    async def set_user_settings(self, access_token: str, mfa_options: list[dict]) -> dict:
        return await self._call("set_user_settings", AccessToken=access_token, MFAOptions=mfa_options)

    @tool
    async def sign_up(self, client_id: str, username: str, password: str, user_attributes: list[dict],
                      validation_data: list[dict] | None = None, secret_hash: str | None = None) -> dict:
        kwargs = {"ClientId": client_id, "Username": username, "Password": password, "UserAttributes": user_attributes}
        if validation_data:
            kwargs["ValidationData"] = validation_data
        if secret_hash:
            kwargs["SecretHash"] = secret_hash
        return await self._call("sign_up", **kwargs)

    @tool
    async def start_user_import_job(self, user_pool_id: str, job_id: str) -> dict:
        return await self._call("start_user_import_job", UserPoolId=user_pool_id, JobId=job_id)

    @tool
    async def start_web_authn_registration(self, access_token: str) -> dict:
        return await self._call("start_web_authn_registration", AccessToken=access_token)

    @tool
    async def stop_user_import_job(self, user_pool_id: str, job_id: str) -> dict:
        return await self._call("stop_user_import_job", UserPoolId=user_pool_id, JobId=job_id)

    @tool
    async def tag_resource(self, resource_arn: str, tags: dict) -> dict:
        return await self._call("tag_resource", ResourceArn=resource_arn, Tags=tags)

    @tool
    async def untag_resource(self, resource_arn: str, tag_keys: list[str]) -> dict:
        return await self._call("untag_resource", ResourceArn=resource_arn, TagKeys=tag_keys)

    @tool
    async def update_auth_event_feedback(self, user_pool_id: str, username: str, event_id: str,
                                         feedback_value: str) -> dict:
        return await self._call("update_auth_event_feedback", UserPoolId=user_pool_id, Username=username,
                                EventId=event_id, FeedbackValue=feedback_value)

    @tool
    async def update_device_status(self, access_token: str, device_key: str, device_remembered_status: str) -> dict:
        return await self._call("update_device_status", AccessToken=access_token, DeviceKey=device_key,
                                DeviceRememberedStatus=device_remembered_status)

    @tool
    async def update_group(
            self,
            group_name: str,
            user_pool_id: str,
            description: str = None,
            role_arn: str = None,
            precedence: int = None,
    ) -> dict:
        """Updates an existing group in a user pool."""
        return await self._call(
            "update_group",
            GroupName=group_name,
            UserPoolId=user_pool_id,
            Description=description,
            RoleArn=role_arn,
            Precedence=precedence,
        )

    @tool
    async def update_identity_provider(self, user_pool_id: str, provider_name: str,
                                       provider_details: dict) -> dict:
        """Updates an existing identity provider in a user pool."""
        return await self._call(
            "update_identity_provider",
            UserPoolId=user_pool_id,
            ProviderName=provider_name,
            ProviderDetails=provider_details,
        )

    @tool
    async def update_managed_login_branding(self, client_id: str, image_url: str) -> dict:
        """Updates managed login branding for a client."""
        return await self._call(
            "update_managed_login_branding",
            ClientId=client_id,
            ImageUrl=image_url,
        )

    @tool
    async def update_resource_server(self, user_pool_id: str, identifier: str, name: str, scopes: list) -> dict:
        """Updates an existing resource server."""
        return await self._call(
            "update_resource_server",
            UserPoolId=user_pool_id,
            Identifier=identifier,
            Name=name,
            Scopes=scopes,
        )

    @tool
    async def update_terms(self, user_pool_id: str, terms_id: str, content: dict, **kwargs) -> dict:
        """Updates terms for a user pool."""
        return await self._call(
            "update_terms",
            UserPoolId=user_pool_id,
            TermsId=terms_id,
            Content=content,
            **kwargs
        )

    @tool
    async def update_user_attributes(self, user_pool_id: str, username: str, user_attributes: list, **kwargs) -> dict:
        """Updates user attributes for a given user."""
        return await self._call(
            "update_user_attributes",
            UserPoolId=user_pool_id,
            Username=username,
            UserAttributes=user_attributes,
            **kwargs
        )

    @tool
    async def update_user_pool(self, user_pool_id: str, policies: dict = None,
                               lambda_config: dict = None, **kwargs) -> dict:
        """Updates a user pool’s configuration."""
        return await self._call(
            "update_user_pool",
            UserPoolId=user_pool_id,
            Policies=policies or {},
            LambdaConfig=lambda_config or {},
            **kwargs
        )

    @tool
    async def update_user_pool_client(
            self, user_pool_id: str, client_id: str, client_name: str = None, explicit_auth_flows: list = None, **kwargs
    ) -> dict:
        """Updates an existing user pool client."""
        return await self._call(
            "update_user_pool_client",
            UserPoolId=user_pool_id,
            ClientId=client_id,
            ClientName=client_name,
            ExplicitAuthFlows=explicit_auth_flows or [],
            **kwargs
        )

    @tool
    async def update_user_pool_domain(self, domain: str, user_pool_id: str, custom_domain_config: dict, **kwargs) -> dict:
        """Updates the configuration for a user pool domain."""
        return await self._call(
            "update_user_pool_domain",
            Domain=domain,
            UserPoolId=user_pool_id,
            CustomDomainConfig=custom_domain_config,
            **kwargs
        )

    # ---------------- Verification Methods ---------------- #

    @tool
    async def verify_software_token(self, access_token: str, user_code: str,
                                    friendly_device_name: str = None, **kwargs) -> dict:
        """Verifies a software token for multi-factor authentication (MFA)."""
        return await self._call(
            "verify_software_token",
            AccessToken=access_token,
            UserCode=user_code,
            FriendlyDeviceName=friendly_device_name,
            **kwargs
        )

    @tool
    async def verify_user_attribute(self, access_token: str, attribute_name: str, code: str) -> dict:
        """Verifies a user attribute using a confirmation code."""
        return await self._call(
            "verify_user_attribute",
            AccessToken=access_token,
            AttributeName=attribute_name,
            Code=code,
        )
