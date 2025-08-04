import boto3
import logging
import os
from botocore.exceptions import ClientError

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

from superagentx_handlers.aws.helper import generate_aws_sts_token

logger = logging.getLogger(__name__)


class AWSECSHandler(BaseHandler):

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

        self.ecs_client = boto3.client('ecs', **self.credentials)

    @tool
    async def get_all_ecs_data(self) -> dict:
        """
        Gather comprehensive ECS data, including running containers with images.
        """
        try:
            clusters_response = await sync_to_async(self.ecs_client.list_clusters)
            cluster_arns = clusters_response.get('clusterArns', [])

            clusters_detail = {}
            if cluster_arns:
                clusters_detail = await sync_to_async(
                    self.ecs_client.describe_clusters, clusters=cluster_arns
                )

            all_services = []
            services_detail = {}
            async for cluster_arn in iter_to_aiter(cluster_arns):
                try:
                    services_response = await sync_to_async(
                        self.ecs_client.list_services, cluster=cluster_arn
                    )
                    service_arns = services_response.get('serviceArns', [])
                    if service_arns:
                        services_detail[cluster_arn] = await sync_to_async(
                            self.ecs_client.describe_services,
                            cluster=cluster_arn,
                            services=service_arns
                        )
                        all_services.extend(service_arns)
                except ClientError:
                    continue

            all_tasks = []
            tasks_detail = {}
            async for cluster_arn in iter_to_aiter(cluster_arns):
                try:
                    tasks_response = await sync_to_async(
                        self.ecs_client.list_tasks, cluster=cluster_arn
                    )
                    task_arns = tasks_response.get('taskArns', [])
                    if task_arns:
                        tasks_detail[cluster_arn] = await sync_to_async(
                            self.ecs_client.describe_tasks,
                            cluster=cluster_arn,
                            tasks=task_arns
                        )
                        all_tasks.extend(task_arns)
                except ClientError:
                    continue

            task_definitions_list = await sync_to_async(self.ecs_client.list_task_definitions)
            task_definition_families = await sync_to_async(self.ecs_client.list_task_definition_families)

            task_definitions_detail = {}
            async for td_arn in iter_to_aiter(task_definitions_list.get('taskDefinitionArns', [])):
                try:
                    task_definitions_detail[td_arn] = await sync_to_async(
                        self.ecs_client.describe_task_definition,
                        taskDefinition=td_arn
                    )
                except ClientError:
                    continue

            container_instances_detail = {}
            async for cluster_arn in iter_to_aiter(cluster_arns):
                try:
                    ci_response = await sync_to_async(
                        self.ecs_client.list_container_instances,
                        cluster=cluster_arn
                    )
                    ci_arns = ci_response.get('containerInstanceArns', [])
                    if ci_arns:
                        container_instances_detail[cluster_arn] = await sync_to_async(
                            self.ecs_client.describe_container_instances,
                            cluster=cluster_arn,
                            containerInstances=ci_arns
                        )
                except ClientError:
                    continue

            try:
                capacity_providers = await sync_to_async(
                    self.ecs_client.describe_capacity_providers
                )
            except ClientError:
                capacity_providers = {}

            try:
                account_settings = await sync_to_async(
                    self.ecs_client.list_account_settings
                )
            except ClientError:
                account_settings = {}

            try:
                attributes = await sync_to_async(
                    self.ecs_client.list_attributes, targetType='container-instance'
                )
            except ClientError:
                attributes = {}

            running_containers = []
            async for cluster_arn, tasks_data in iter_to_aiter(tasks_detail.items()):
                async for task in iter_to_aiter(tasks_data.get('tasks', [])):
                    if task.get('lastStatus') == 'RUNNING':
                        task_def_arn = task.get('taskDefinitionArn')
                        task_def = task_definitions_detail.get(task_def_arn, {})
                        container_definitions = task_def.get('taskDefinition', {}).get('containerDefinitions', [])

                        async for container_def in iter_to_aiter(container_definitions):
                            running_containers.append({
                                'cluster_arn': cluster_arn,
                                'task_arn': task.get('taskArn'),
                                'task_definition_arn': task_def_arn,
                                'container_name': container_def.get('name'),
                                'image': container_def.get('image'),
                                'launch_type': task.get('launchType'),
                                'platform_version': task.get('platformVersion'),
                                'cpu': container_def.get('cpu'),
                                'memory': container_def.get('memory'),
                                'memory_reservation': container_def.get('memoryReservation'),
                                'essential': container_def.get('essential'),
                                'port_mappings': container_def.get('portMappings', []),
                                'environment': container_def.get('environment', []),
                                'task_created_at': task.get('createdAt'),
                                'task_started_at': task.get('startedAt'),
                                'availability_zone': task.get('availabilityZone'),
                                'connectivity': task.get('connectivity'),
                                'connectivity_at': task.get('connectivityAt')
                            })

            service_deployments = {}
            service_revisions = {}
            task_sets = {}
            async for cluster_arn, services_data in iter_to_aiter(services_detail.items()):
                async for service in iter_to_aiter(services_data.get('services', [])):
                    service_name = service.get('serviceName')
                    try:
                        service_deployments[f"{cluster_arn}:{service_name}"] = await sync_to_async(
                            self.ecs_client.describe_service_deployments,
                            cluster=cluster_arn,
                            service=service_name
                        )
                    except ClientError:
                        pass
                    try:
                        service_revisions[f"{cluster_arn}:{service_name}"] = await sync_to_async(
                            self.ecs_client.describe_service_revisions,
                            cluster=cluster_arn,
                            service=service_name
                        )
                    except ClientError:
                        pass
                    try:
                        task_sets[f"{cluster_arn}:{service_name}"] = await sync_to_async(
                            self.ecs_client.describe_task_sets,
                            cluster=cluster_arn,
                            service=service_name
                        )
                    except ClientError:
                        pass

            tags = {}
            async for cluster_arn in iter_to_aiter(cluster_arns):
                try:
                    tags[cluster_arn] = await sync_to_async(
                        self.ecs_client.list_tags_for_resource,
                        resourceArn=cluster_arn
                    )
                except ClientError:
                    pass

            try:
                services_by_namespace = await sync_to_async(
                    self.ecs_client.list_services_by_namespace,
                    namespace='default'
                )
            except ClientError:
                services_by_namespace = {}

            return {
                'running_containers': running_containers,
                'capacity_providers': capacity_providers,
                'clusters': clusters_detail,
                'container_instances': container_instances_detail,
                'service_deployments': service_deployments,
                'service_revisions': service_revisions,
                'services': services_detail,
                'task_definitions': task_definitions_detail,
                'task_sets': task_sets,
                'tasks': tasks_detail,
                'account_settings': account_settings,
                'attributes': attributes,
                'clusters_list': clusters_response,
                'container_instances_list': {cluster: [] for cluster in cluster_arns},
                'service_deployments_list': dict(service_deployments),
                'services_list': {cluster: [] for cluster in cluster_arns},
                'services_by_namespace': services_by_namespace,
                'tags_for_resources': tags,
                'task_definition_families': task_definition_families,
                'task_definitions_list': task_definitions_list,
                'tasks_list': {cluster: [] for cluster in cluster_arns}
            }

        except Exception as e:
            logger.error(f"Error fetching ECS data: {e}", exc_info=True)
            return {
                'error': str(e),
                'running_containers': [],
                'capacity_providers': {},
                'clusters': {},
                'container_instances': {},
                'service_deployments': {},
                'service_revisions': {},
                'services': {},
                'task_definitions': {},
                'task_sets': {},
                'tasks': {},
                'account_settings': {},
                'attributes': {},
                'clusters_list': {},
                'container_instances_list': {},
                'service_deployments_list': {},
                'services_list': {},
                'services_by_namespace': {},
                'tags_for_resources': {},
                'task_definition_families': {},
                'task_definitions_list': {},
                'tasks_list': {}
            }

    @tool
    async def create_cluster(self, cluster_name: str, **kwargs):
        """
        Creates a new Amazon ECS cluster.

        Args:
            cluster_name (str): The name of the cluster to create.
            **kwargs: Optional additional parameters for the ECS API call.
                      For example: capacityProviders, defaultCapacityProviderStrategy, tags.

        Returns:
            dict: API response containing details of the created cluster or error message.

        Docs:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.create_cluster
        """
        logger.info(f"Creating ECS cluster '{cluster_name}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.create_cluster,
                clusterName=cluster_name,
                **kwargs
            )
            logger.info(f"ECS cluster '{cluster_name}' created successfully.")
            return response
        except ClientError as e:
            logger.error(f"Failed to create ECS cluster '{cluster_name}': {e}")
            return {"error": str(e)}

    @tool
    async def create_service(self, cluster_name: str, service_name: str, task_definition: str, **kwargs):
        """
        Creates a new Amazon ECS service.

        Args:
            cluster_name (str): The name of the ECS cluster to create the service in.
            service_name (str): The name of the service to create.
            task_definition (str): The task definition to use for the service.
            **kwargs: Optional additional parameters for the ECS API call.
                      For example: desiredCount, launchType, platformVersion, deploymentConfiguration, networkConfiguration, etc.

        Returns:
            dict: API response containing details of the created service or error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.create_service
        """
        logger.info(f"Creating ECS service '{service_name}' in cluster '{cluster_name}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.create_service,
                cluster=cluster_name,
                serviceName=service_name,
                taskDefinition=task_definition,
                **kwargs
            )
            logger.info(f"ECS service '{service_name}' created successfully in cluster '{cluster_name}'.")
            return response
        except ClientError as e:
            logger.error(f"Failed to create ECS service '{service_name}': {e}")
            return {"error": str(e)}

    @tool
    async def create_task_set(
            self,
            cluster: str,
            service: str,
            task_definition: str,
            **kwargs
    ):
        """
        Creates a new task set in the specified ECS service.

        Args:
            cluster (str): The short name or full Amazon Resource Name (ARN) of the cluster that hosts the service.
            service (str): The short name or full Amazon Resource Name (ARN) of the ECS service.
            task_definition (str): The task definition for the tasks in the task set.
            **kwargs: Optional additional parameters for the ECS API call.
                      For example: externalId, networkConfiguration, loadBalancers, launchType, serviceRegistries, etc.

        Returns:
            dict: API response containing details of the created task set or an error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.create_task_set
        """
        logger.info(f"Creating ECS task set for service '{service}' in cluster '{cluster}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.create_task_set,
                cluster=cluster,
                service=service,
                taskDefinition=task_definition,
                **kwargs
            )
            logger.info(f"Task set created successfully in service '{service}' of cluster '{cluster}'.")
            return response
        except ClientError as e:
            logger.error(f"Failed to create ECS task set in service '{service}': {e}")
            return {"error": str(e)}

    @tool
    async def update_capacity_provider(self, name: str, **kwargs):
        """
        Updates the specified capacity provider.

        Args:
            name (str): The name of the capacity provider to update.
            **kwargs: Optional additional parameters for the ECS API call.
                      For example: autoScalingGroupProvider.

        Returns:
            dict: API response containing details of the updated capacity provider or error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_capacity_provider
        """
        logger.info(f"Updating ECS capacity provider '{name}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_capacity_provider,
                name=name,
                **kwargs
            )
            logger.info(f"Capacity provider '{name}' updated successfully.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update ECS capacity provider '{name}': {e}")
            return {"error": str(e)}

    @tool
    async def update_cluster(self, cluster_name: str, **kwargs):
        """
        Updates the cluster settings such as service connect defaults.

        Args:
            cluster_name (str): The name of the ECS cluster to update.
            **kwargs: Optional additional parameters for the ECS API call.
                      For example: serviceConnectDefaults.

        Returns:
            dict: API response containing details of the updated ECS cluster or error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_cluster
        """
        logger.info(f"Updating ECS cluster '{cluster_name}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_cluster,
                cluster=cluster_name,
                **kwargs
            )
            logger.info(f"ECS cluster '{cluster_name}' updated successfully.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update ECS cluster '{cluster_name}': {e}")
            return {"error": str(e)}

    @tool
    async def update_cluster_settings(self, cluster_name: str, **kwargs):
        """
        Updates the settings for an ECS cluster (e.g., container insights).

        Args:
            cluster_name (str): The name of the ECS cluster to update.
            **kwargs: Additional optional parameters for the ECS API call.
                      For example: settings=[{'name': 'containerInsights', 'value': 'enabled'}]

        Returns:
            dict: API response containing details of the updated ECS cluster settings or error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_cluster_settings
        """
        logger.info(f"Updating settings for ECS cluster '{cluster_name}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_cluster_settings,
                cluster=cluster_name,
                **kwargs
            )
            logger.info(f"ECS cluster settings for '{cluster_name}' updated successfully.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update ECS cluster settings for '{cluster_name}': {e}")
            return {"error": str(e)}

    @tool
    async def update_container_agent(self, container_instance: str, cluster: str = None):
        """
        Updates the Amazon ECS container agent on a specified container instance.

        Args:
            container_instance (str): The container instance ID or ARN to update.
            cluster (str, optional): The cluster name or ARN that hosts the container instance.
                                     If not specified, the default cluster is assumed.

        Returns:
            dict: API response containing details of the update or error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_container_agent
        """
        logger.info(f"Updating container agent on instance '{container_instance}' (Cluster: '{cluster}')...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_container_agent,
                containerInstance=container_instance,
                cluster=cluster if cluster else "default"
            )
            logger.info(f"Container agent updated successfully on instance '{container_instance}'.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update container agent on instance '{container_instance}': {e}")
            return {"error": str(e)}

    @tool
    async def update_container_instances_state(
            self,
            cluster: str,
            container_instances: list,
            status: str
    ):
        """
        Updates the status of one or more container instances in an ECS cluster.

        Args:
            cluster (str): The name or ARN of the cluster containing the container instances.
            container_instances (list): A list of container instance IDs or ARNs to update.
            status (str): The new status for the container instances. Valid values: 'ACTIVE' | 'DRAINING'

        Returns:
            dict: API response containing details of the updated instances or an error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_container_instances_state
        """
        logger.info(f"Updating state of container instances in cluster '{cluster}' to '{status}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_container_instances_state,
                cluster=cluster,
                containerInstances=container_instances,
                status=status
            )
            logger.info(f"Container instances updated successfully in cluster '{cluster}'.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update container instances in cluster '{cluster}': {e}")
            return {"error": str(e)}

    @tool
    async def update_service(self, cluster: str, service: str, **kwargs):
        """
        Updates an existing Amazon ECS service.

        Args:
            cluster (str): The name or ARN of the cluster that hosts the service.
            service (str): The name of the service to update.
            **kwargs: Optional additional parameters for the ECS API call.
                      For example: desiredCount, taskDefinition, deploymentConfiguration, networkConfiguration, etc.

        Returns:
            dict: API response containing details of the updated service or error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_service
        """
        logger.info(f"Updating ECS service '{service}' in cluster '{cluster}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_service,
                cluster=cluster,
                service=service,
                **kwargs
            )
            logger.info(f"ECS service '{service}' updated successfully in cluster '{cluster}'.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update ECS service '{service}' in cluster '{cluster}': {e}")
            return {"error": str(e)}

    @tool
    async def update_service_primary_task_set(self, cluster: str, service: str, primary_task_set: str):
        """
        Updates the primary task set of a service.

        Args:
            cluster (str): The short name or full Amazon Resource Name (ARN) of the cluster.
            service (str): The name or ARN of the service that hosts the task set.
            primary_task_set (str): The ARN of the task set to set as the primary.

        Returns:
            dict: API response containing the updated service's task set info or error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_service_primary_task_set
        """
        logger.info(
            f"Updating primary task set for service '{service}' in cluster '{cluster}' to '{primary_task_set}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_service_primary_task_set,
                cluster=cluster,
                service=service,
                primaryTaskSet=primary_task_set
            )
            logger.info(f"Primary task set for service '{service}' updated successfully.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update primary task set for service '{service}': {e}")
            return {"error": str(e)}

    @tool
    async def update_task_protection(self, cluster: str, tasks: list, protection_enabled: bool, **kwargs):
        """
        Updates the protection status of a task to prevent it from being terminated during scale-in events.

        Args:
            cluster (str): The short name or full Amazon Resource Name (ARN) of the cluster.
            tasks (list): A list of task ARNs to update protection status.
            protection_enabled (bool): Whether to enable or disable protection for the specified tasks.
            **kwargs: Optional additional parameters such as 'expiresInMinutes'.

        Returns:
            dict: API response containing the result of the update or an error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_task_protection
        """
        logger.info(f"Updating task protection for tasks in cluster '{cluster}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_task_protection,
                cluster=cluster,
                tasks=tasks,
                protectionEnabled=protection_enabled,
                **kwargs
            )
            logger.info("Task protection updated successfully.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update task protection: {e}")
            return {"error": str(e)}

    @tool
    async def update_task_set(self, cluster: str, service: str, task_set: str, **kwargs):
        """
        Updates a specified task set in a service.

        Args:
            cluster (str): The short name or full Amazon Resource Name (ARN) of the cluster.
            service (str): The short name or full ARN of the service.
            task_set (str): The task set ID or full ARN of the task set to update.
            **kwargs: Optional parameters such as 'scale' with value dict:
                      {
                          'value': float,
                          'unit': 'PERCENT'
                      }

        Returns:
            dict: API response containing details of the updated task set or error message.

        Docs:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.update_task_set
        """
        logger.info(f"Updating task set '{task_set}' for service '{service}' in cluster '{cluster}'...")
        try:
            response = await sync_to_async(
                self.ecs_client.update_task_set,
                cluster=cluster,
                service=service,
                taskSet=task_set,
                **kwargs
            )
            logger.info(f"Task set '{task_set}' updated successfully.")
            return response
        except ClientError as e:
            logger.error(f"Failed to update task set '{task_set}': {e}")
            return {"error": str(e)}

