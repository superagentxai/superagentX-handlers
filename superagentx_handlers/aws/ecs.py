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
