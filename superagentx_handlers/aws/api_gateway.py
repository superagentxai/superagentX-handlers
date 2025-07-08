import logging
import os

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

from superagentx_handlers.aws.helper import generate_aws_sts_token

logger = logging.getLogger(__name__)


class AWSAPIGatewayHandler(BaseHandler):
    """
        A handler to interact with AWS API Gateway (both v1 and v2) using Boto3.

        This class provides functionality to retrieve detailed information
        about all REST, HTTP, and WebSocket APIs in API Gateway, along with
        their associated resources, stages, deployments, integrations, and VPC links.

        Attributes:
            apigw_client (boto3.client): Boto3 client for 'apigateway' (REST APIs - v1).
            apigwv2_client (boto3.client): Boto3 client for 'apigatewayv2' (HTTP/WebSocket APIs - v2).

        Args:
            aws_access_key_id (Optional[str], optional): AWS access key ID.
                Defaults to environment variable `AWS_ACCESS_KEY_ID` if not provided.
            aws_secret_access_key (Optional[str], optional): AWS secret access key.
                Defaults to environment variable `AWS_SECRET_ACCESS_KEY` if not provided.
            region_name (Optional[str], optional): AWS region.
                Defaults to environment variable `AWS_REGION` if not provided.

        Raises:
            NoCredentialsError: If credentials are missing or invalid.
            ClientError: If the Boto3 client fails to initialize.

        Example:
            handler = AWSAPIGatewayHandler(region_name="us-west-2")
        """

    def __init__(
            self,
            aws_access_key_id: str | None = None,
            aws_secret_access_key: str | None = None,
            region_name: str | None = None
    ):
        """
        Retrieve comprehensive information about all API Gateways, their APIs, and VPC links.

         Returns:
          Dict containing all API Gateway information
       """
        super().__init__()
        region = region_name or os.getenv("AWS_REGION")
        aws_access_key_id = aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY")

        self.credentials = generate_aws_sts_token(region_name=region,
                                                  aws_access_key_id=aws_access_key_id,
                                                  aws_secret_access_key=aws_secret_access_key)
        self.apigw_client = boto3.client(
            'apigateway',
            **self.credentials
        )

        self.apigwv2_client = boto3.client(
            'apigatewayv2',
            **self.credentials
        )

    @tool
    async def get_all_api_gateways_info(self) -> dict:
        """
        Retrieve comprehensive information about all API Gateways in the AWS account.

        This includes:
            - REST APIs (API Gateway v1), with resources, stages, and deployments.
            - HTTP APIs (API Gateway v2), with routes, stages, and integrations.
            - WebSocket APIs (API Gateway v2), with routes, stages, and integrations.
            - VPC Links (for both v1 and v2, if extended).

        Returns:
            Dict[str, Any]: A dictionary with structure:
                {
                    'rest_apis': [...],
                    'http_apis': [...],
                    'websocket_apis': [...],
                    'vpc_links': {
                        'v1': [...],
                        'v2': [...]
                    },
                    'summary': {
                        'total_rest_apis': int,
                        'total_http_apis': int,
                        'total_websocket_apis': int,
                        'total_vpc_links_v1': int,
                        'total_vpc_links_v2': int
                    }
                }

        Raises:
            ClientError: If any API Gateway operation fails.
            NoCredentialsError: If AWS credentials are not found.

        Example:
            result = await handler.get_all_api_gateways_info()
            print(result['summary'])
        """
        try:
            result = {
                'rest_apis': [],
                'http_apis': [],
                'websocket_apis': [],
                'vpc_links': {
                    'v1': [],
                    'v2': []
                },
                'summary': {
                    'total_rest_apis': 0,
                    'total_http_apis': 0,
                    'total_websocket_apis': 0,
                    'total_vpc_links_v1': 0,
                    'total_vpc_links_v2': 0
                }
            }

            # Get REST APIs (API Gateway v1)
            logger.debug(f"Fetching REST APIs...")
            try:
                rest_apis_response = await sync_to_async(self.apigw_client.get_rest_apis)

                async for api in iter_to_aiter(rest_apis_response.get('items', [])):
                    api_id = api['id']
                    api_info = {
                        "response": api,
                        "authorizers": await sync_to_async(self.apigw_client.get_authorizers, restApiId=api_id),
                        'resources': [],
                        'stages': [],
                        'deployments': []
                    }

                    # Get resources for each API
                    try:
                        resources_response = await sync_to_async(self.apigw_client.get_resources, restApiId=api_id)
                        async for resource in iter_to_aiter(resources_response.get('items', [])):
                            resource_info = {
                                'id': resource.get('id'),
                                'parent_id': resource.get('parentId'),
                                'path_part': resource.get('pathPart'),
                                'path': resource.get('path'),
                                'resource_methods': list(
                                    resource.get(
                                        'resourceMethods',
                                        {}
                                    ).keys()) if resource.get('resourceMethods') else []
                            }
                            api_info['resources'].append(resource_info)
                    except ClientError as e:
                        logger.error(f"Error getting resources for REST API {api_id}: {e}")

                    # Get stages for each API
                    try:
                        stages_response = await sync_to_async(self.apigw_client.get_stages, restApiId=api_id)
                        async for stage in iter_to_aiter(stages_response.get('item', [])):
                            stage_info = {
                                'stage_name': stage.get('stageName'),
                                'deployment_id': stage.get('deploymentId'),
                                'description': stage.get('description'),
                                'created_date': str(stage.get('createdDate', 'N/A')),
                                'last_updated_date': str(stage.get('lastUpdatedDate', 'N/A')),
                                'cache_cluster_enabled': stage.get('cacheClusterEnabled', False),
                                'cache_cluster_size': stage.get('cacheClusterSize'),
                                'method_settings': stage.get('methodSettings', {}),
                                'variables': stage.get('variables', {}),
                                'tags': stage.get('tags', {})
                            }
                            api_info['stages'].append(stage_info)
                    except ClientError as e:
                        logger.error(f"Error getting stages for REST API {api_id}: {e}")

                    # Get deployments for each API
                    try:
                        deployments_response = await sync_to_async(self.apigw_client.get_deployments, restApiId=api_id)
                        async for deployment in iter_to_aiter(deployments_response.get('items', [])):
                            deployment_info = {
                                'id': deployment.get('id'),
                                'description': deployment.get('description'),
                                'created_date': str(deployment.get('createdDate', 'N/A')),
                                'api_summary': deployment.get('apiSummary', {})
                            }
                            api_info['deployments'].append(deployment_info)
                    except ClientError as e:
                        logger.error(f"Error getting deployments for REST API {api_id}: {e}")

                    result['rest_apis'].append(api_info)

            except ClientError as e:
                logger.error(f"Error fetching REST APIs: {e}")

            # Get HTTP APIs (API Gateway v2)
            logger.debug("Fetching HTTP APIs...")
            try:
                http_apis_response = await sync_to_async(self.apigwv2_client.get_apis)

                async for api in iter_to_aiter(http_apis_response.get('Items', [])):
                    if api.get('ProtocolType') == 'HTTP':
                        api_id = api['ApiId']
                        api_info = {
                            "response": api,
                            "authorizers": await sync_to_async(self.apigwv2_client.get_authorizers, ApiId=api_id)
                        }

                        # Get routes for each HTTP API
                        try:
                            routes_response = await sync_to_async(self.apigwv2_client.get_routes, ApiId=api_id)
                            async for route in iter_to_aiter(routes_response.get('Items', [])):
                                route_info = {
                                    'route_id': route.get('RouteId'),
                                    'route_key': route.get('RouteKey'),
                                    'target': route.get('Target'),
                                    'authorization_type': route.get('AuthorizationType'),
                                    'authorizer_id': route.get('AuthorizerId'),
                                    'model_selection_expression': route.get('ModelSelectionExpression'),
                                    'operation_name': route.get('OperationName'),
                                    'request_models': route.get('RequestModels', {}),
                                    'request_parameters': route.get('RequestParameters', {}),
                                    'route_response_selection_expression': route.get('RouteResponseSelectionExpression')
                                }
                                api_info['routes'].append(route_info)
                        except ClientError as e:
                            logger.error(f"Error getting routes for HTTP API {api_id}: {e}")

                        # Get stages for each HTTP API
                        try:
                            stages_response = await sync_to_async(self.apigwv2_client.get_stages, ApiId=api_id)
                            async for stage in iter_to_aiter(stages_response.get('Items', [])):
                                stage_info = {
                                    'stage_name': stage.get('StageName'),
                                    'deployment_id': stage.get('DeploymentId'),
                                    'description': stage.get('Description'),
                                    'created_date': str(stage.get('CreatedDate', 'N/A')),
                                    'last_updated_date': str(stage.get('LastUpdatedDate', 'N/A')),
                                    'auto_deploy': stage.get('AutoDeploy', False),
                                    'client_certificate_id': stage.get('ClientCertificateId'),
                                    'default_route_settings': stage.get('DefaultRouteSettings', {}),
                                    'route_settings': stage.get('RouteSettings', {}),
                                    'stage_variables': stage.get('StageVariables', {}),
                                    'tags': stage.get('Tags', {})
                                }
                                api_info['stages'].append(stage_info)
                        except ClientError as e:
                            logger.error(f"Error getting stages for HTTP API {api_id}: {e}")

                        # Get integrations for each HTTP API
                        try:
                            integrations_response = await sync_to_async(self.apigwv2_client.get_integrations,
                                                                        ApiId=api_id)
                            async for integration in iter_to_aiter(integrations_response.get('Items', [])):
                                integration_info = {
                                    'integration_id': integration.get('IntegrationId'),
                                    'integration_type': integration.get('IntegrationType'),
                                    'integration_uri': integration.get('IntegrationUri'),
                                    'integration_method': integration.get('IntegrationMethod'),
                                    'connection_type': integration.get('ConnectionType'),
                                    'connection_id': integration.get('ConnectionId'),
                                    'credentials_arn': integration.get('CredentialsArn'),
                                    'description': integration.get('Description'),
                                    'integration_response_selection_expression': integration.get(
                                        'IntegrationResponseSelectionExpression'),
                                    'passthrough_behavior': integration.get('PassthroughBehavior'),
                                    'payload_format_version': integration.get('PayloadFormatVersion'),
                                    'request_parameters': integration.get('RequestParameters', {}),
                                    'request_templates': integration.get('RequestTemplates', {}),
                                    'timeout_in_millis': integration.get('TimeoutInMillis')
                                }
                                api_info['integrations'].append(integration_info)
                        except ClientError as e:
                            logger.error(f"Error getting integrations for HTTP API {api_id}: {e}")

                        result['http_apis'].append(api_info)

            except ClientError as e:
                logger.error(f"Error fetching HTTP APIs: {e}")

            # Get WebSocket APIs (API Gateway v2)
            logger.info("Fetching WebSocket APIs...")
            try:
                websocket_apis_response = await sync_to_async(self.apigwv2_client.get_apis)
                async for api in iter_to_aiter(websocket_apis_response.get('Items', [])):
                    if api.get('ProtocolType') == 'WEBSOCKET':
                        api_id = api['ApiId']
                        api_info = {
                            'api_id': api_id,
                            'name': api.get('Name', 'N/A'),
                            'description': api.get('Description', 'N/A'),
                            'version': api.get('Version', 'N/A'),
                            'protocol_type': api.get('ProtocolType'),
                            'route_selection_expression': api.get('RouteSelectionExpression'),
                            'api_endpoint': api.get('ApiEndpoint'),
                            'created_date': str(api.get('CreatedDate', 'N/A')),
                            'tags': api.get('Tags', {}),
                            'routes': [],
                            'stages': [],
                            'integrations': []
                        }

                        # Get routes, stages, and integrations (same as HTTP APIs)
                        # Routes
                        try:
                            routes_response = await sync_to_async(self.apigwv2_client.get_routes, ApiId=api_id)
                            async for route in iter_to_aiter(routes_response.get('Items', [])):
                                route_info = {
                                    'route_id': route.get('RouteId'),
                                    'route_key': route.get('RouteKey'),
                                    'target': route.get('Target'),
                                    'authorization_type': route.get('AuthorizationType'),
                                    'authorizer_id': route.get('AuthorizerId'),
                                    'model_selection_expression': route.get('ModelSelectionExpression'),
                                    'operation_name': route.get('OperationName'),
                                    'request_models': route.get('RequestModels', {}),
                                    'request_parameters': route.get('RequestParameters', {}),
                                    'route_response_selection_expression': route.get('RouteResponseSelectionExpression')
                                }
                                api_info['routes'].append(route_info)
                        except ClientError as e:
                            logger.error(f"Error getting routes for WebSocket API {api_id}: {e}")

                        # Stages
                        try:
                            stages_response = await sync_to_async(self.apigwv2_client.get_stages, ApiId=api_id)
                            async for stage in iter_to_aiter(stages_response.get('Items', [])):
                                stage_info = {
                                    'stage_name': stage.get('StageName'),
                                    'deployment_id': stage.get('DeploymentId'),
                                    'description': stage.get('Description'),
                                    'created_date': str(stage.get('CreatedDate', 'N/A')),
                                    'last_updated_date': str(stage.get('LastUpdatedDate', 'N/A')),
                                    'auto_deploy': stage.get('AutoDeploy', False),
                                    'client_certificate_id': stage.get('ClientCertificateId'),
                                    'default_route_settings': stage.get('DefaultRouteSettings', {}),
                                    'route_settings': stage.get('RouteSettings', {}),
                                    'stage_variables': stage.get('StageVariables', {}),
                                    'tags': stage.get('Tags', {})
                                }
                                api_info['stages'].append(stage_info)
                        except ClientError as e:
                            logger.error(f"Error getting stages for WebSocket API {api_id}: {e}")

                        # Integrations
                        try:
                            integrations_response = await sync_to_async(self.apigwv2_client.get_integrations,
                                                                        ApiId=api_id)
                            async for integration in iter_to_aiter(integrations_response.get('Items', [])):
                                integration_info = {
                                    'integration_id': integration.get('IntegrationId'),
                                    'integration_type': integration.get('IntegrationType'),
                                    'integration_uri': integration.get('IntegrationUri'),
                                    'integration_method': integration.get('IntegrationMethod'),
                                    'connection_type': integration.get('ConnectionType'),
                                    'connection_id': integration.get('ConnectionId'),
                                    'credentials_arn': integration.get('CredentialsArn'),
                                    'description': integration.get('Description'),
                                    'integration_response_selection_expression': integration.get(
                                        'IntegrationResponseSelectionExpression'),
                                    'passthrough_behavior': integration.get('PassthroughBehavior'),
                                    'payload_format_version': integration.get('PayloadFormatVersion'),
                                    'request_parameters': integration.get('RequestParameters', {}),
                                    'request_templates': integration.get('RequestTemplates', {}),
                                    'timeout_in_millis': integration.get('TimeoutInMillis')
                                }
                                api_info['integrations'].append(integration_info)
                        except ClientError as e:
                            logger.error(f"Error getting integrations for WebSocket API {api_id}: {e}")

                        result['websocket_apis'].append(api_info)

            except ClientError as e:
                logger.error(f"Error fetching WebSocket APIs: {e}")

            # Get VPC Links v1 (for REST APIs)
            logger.debug(f"Fetching VPC Links v1...")
            try:
                vpc_links_v1_response = await sync_to_async(self.apigw_client.get_vpc_links)
                async for vpc_link in iter_to_aiter(vpc_links_v1_response.get('items', [])):
                    vpc_link_info = {
                        'id': vpc_link.get('id'),
                        'name': vpc_link.get('name'),
                        'description': vpc_link.get('description'),
                        'target_arns': vpc_link.get('targetArns', []),
                        'status': vpc_link.get('status'),
                        'status_message': vpc_link.get('statusMessage'),
                        'tags': vpc_link.get('tags', {})
                    }
                    result['vpc_links']['v1'].append(vpc_link_info)

            except ClientError as e:
                logger.error(f"Error fetching VPC Links v1: {e}")

            # Get VPC Links v2 (for HTTP/WebSocket APIs)
            logger.debug(f"Fetching VPC Links v2...")
            try:
                vpc_links_v2_response = await sync_to_async(self.apigwv2_client.get_vpc_links)
                async for vpc_link in iter_to_aiter(vpc_links_v2_response.get('items', [])):
                    vpc_link_info = {
                        'vpc_link_id': vpc_link.get('VpcLinkId'),
                        'name': vpc_link.get('Name'),
                        'security_group_ids': vpc_link.get('SecurityGroupIds', []),
                        'subnet_ids': vpc_link.get('SubnetIds', []),
                        'vpc_link_status': vpc_link.get('VpcLinkStatus'),
                        'vpc_link_status_message': vpc_link.get('VpcLinkStatusMessage'),
                        'vpc_link_version': vpc_link.get('VpcLinkVersion'),
                        'created_date': str(vpc_link.get('CreatedDate', 'N/A')),
                        'tags': vpc_link.get('Tags', {})
                    }
                    result['vpc_links']['v2'].append(vpc_link_info)

            except ClientError as e:
                logger.error(f"Error fetching VPC Links v2: {e}")

            # Update summary
            result['summary'] = {
                'total_rest_apis': len(result['rest_apis']),
                'total_http_apis': len(result['http_apis']),
                'total_websocket_apis': len(result['websocket_apis']),
                'total_vpc_links_v1': len(result['vpc_links']['v1']),
                'total_vpc_links_v2': len(result['vpc_links']['v2'])
            }

            return result

        except NoCredentialsError:
            logger.error("Error: AWS credentials not found. Please configure your credentials.")
            return {'error': 'AWS credentials not found'}
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {'error': str(e)}
