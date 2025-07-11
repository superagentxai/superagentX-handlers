import asyncio
import logging
import os
from typing import Any

from google.cloud import run_v2
from google.oauth2 import service_account
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


def get_attr(obj: Any, attr: Any, default: Any = None) -> Any:
    """Safely get attribute, dict key, or list index with fallback."""
    if obj is None:
        return default
    try:
        if isinstance(attr, int):
            # treat as list/tuple index
            if isinstance(obj, (list, tuple)):
                return obj[attr]
            return default
        elif isinstance(obj, dict):
            return obj.get(attr, default)
        else:
            return getattr(obj, attr, default)
    except (IndexError, KeyError, AttributeError, TypeError):
        return default


def get_nested_attr(obj: Any, path: list[str], default: Any = None) -> Any:
    """Helper to navigate nested attributes."""
    for p in path:
        obj = get_attr(obj, p)
        if obj is None:
            return default
    return obj



class GCPCloudRunHandler(BaseHandler):
    def __init__(
            self,
            creds: str | dict | None = None
    ):
        super().__init__()

        # Load credentials from path or dict
        creds = creds or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if isinstance(creds, str):
            credentials: service_account.Credentials = service_account.Credentials.from_service_account_file(
                creds
            )
        elif isinstance(creds, dict):
            credentials: service_account.Credentials = service_account.Credentials.from_service_account_info(
                creds
            )
        else:
            raise ValueError("Invalid credentials: must be a file path or a dictionary.")

        self.credentials = credentials
        self.project_id = credentials.project_id
        if not self.project_id:
            raise ValueError("Project ID not found. Set GOOGLE_CLOUD_PROJECT or provide project_id in service account.")

        # Store credentials for lazy client initialization
        self._client = None
        self.locations = [
            'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
            'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6',
            'europe-central2', 'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2',
            'asia-northeast3', 'asia-south1', 'asia-southeast1', 'asia-southeast2'
        ]

    @property
    def client(self):
        """Lazy initialization of the async client within the current event loop."""
        if self._client is None:
            self._client = run_v2.ServicesAsyncClient(credentials=self.credentials)
        return self._client

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self):
        """Close the async client."""
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def _process_container_info(self, container) -> dict:
        """Process container information asynchronously."""
        container_info = {
            'name': get_attr(container, 'name', 'unnamed'),
            'image': get_attr(container, 'image', ''),
            'ports': [],
            'env_vars': {},
            'resources': {},
            'args': list(get_attr(container, 'args', [])),
            'command': list(get_attr(container, 'command', []))
        }

        # Process ports
        ports = get_attr(container, 'ports', [])
        for port in ports:
            container_info['ports'].append({
                'container_port': get_attr(port, 'container_port'),
                'name': get_attr(port, 'name')
            })

        # Process environment variables
        env_vars = get_attr(container, 'env', [])
        for env_var in env_vars:
            env_name = get_attr(env_var, 'name', '')
            if value := get_attr(env_var, 'value'):
                container_info['env_vars'][env_name] = value
            elif vs := get_attr(env_var, 'value_source'):
                container_info['env_vars'][env_name] = {
                    'source': 'secret_or_config',
                    'details': str(vs)
                }

        # Process resources
        resources = get_attr(container, 'resources', {})
        container_info['resources']['limits'] = dict(get_attr(resources, 'limits', {}))
        container_info['resources']['requests'] = dict(get_attr(resources, 'requests', {}))

        return container_info

    async def _process_service_info(self, service, location: str) -> dict:
        """Process service information asynchronously."""
        service_name = get_attr(service.name.split('/'), -1, 'unknown')

        containers = []
        template_spec = get_nested_attr(service, ['spec', 'template', 'spec'], None)
        if template_spec:
            container_list = get_attr(template_spec, 'containers', [])
            for container in container_list:
                container_info = await self._process_container_info(container)
                containers.append(container_info)

        # Build service info
        service_info = {
            'name': service_name,
            'location': location,
            'full_name': get_attr(service, 'name'),
            'uid': get_attr(service, 'uid', ''),
            'generation': get_attr(service, 'generation', 0),
            'labels': dict(get_attr(service, 'labels', {})),
            'annotations': dict(get_attr(service, 'annotations', {})),
            'create_time': None,
            'update_time': None,
            'delete_time': None,
            'containers': containers,
            'url': get_nested_attr(service, ['status', 'uri']),
            'traffic': [],
            'scaling': {},
            'ingress': get_nested_attr(service, ['spec', 'ingress']),
            'timeout': get_attr(template_spec, 'timeout_seconds'),
            'service_account': get_attr(template_spec, 'service_account')
        }

        # Handle datetime attributes safely
        create_time = get_attr(service, 'create_time')
        if create_time and hasattr(create_time, 'isoformat'):
            service_info['create_time'] = create_time.isoformat()

        update_time = get_attr(service, 'update_time')
        if update_time and hasattr(update_time, 'isoformat'):
            service_info['update_time'] = update_time.isoformat()

        delete_time = get_attr(service, 'delete_time')
        if delete_time and hasattr(delete_time, 'isoformat'):
            service_info['delete_time'] = delete_time.isoformat()

        # Process traffic
        traffic_list = get_nested_attr(service, ['status', 'traffic'], [])
        for traffic in traffic_list:
            service_info['traffic'].append({
                'type': get_attr(traffic, 'type_', 'UNKNOWN'),
                'percent': get_attr(traffic, 'percent', 0),
                'revision': get_attr(traffic, 'revision'),
                'tag': get_attr(traffic, 'tag'),
                'url': get_attr(traffic, 'url')
            })

        # Process scaling
        scaling = get_attr(template_spec, 'scaling')
        if scaling:
            service_info['scaling'] = {
                'min_instance_count': get_attr(scaling, 'min_instance_count', 0),
                'max_instance_count': get_attr(scaling, 'max_instance_count', 0)
            }

        return service_info

    async def _fetch_services_for_location(self, location: str) -> list[dict]:
        """Fetch services for a specific location."""
        services = []
        try:
            parent = f"projects/{self.project_id}/locations/{location}"
            request = await sync_to_async(run_v2.ListServicesRequest,parent=parent)

            # Use the lazy-initialized client
            page_result = await self.client.list_services(request=request)

            # Process services synchronously to avoid nested async issues
            async for service in page_result:
                service_info = await self._process_service_info(service, location)
                services.append(service_info)

        except Exception as e:
            msg = str(e).lower()
            if not any(err in msg for err in ["not found", "forbidden", "permission denied", "does not exist"]):
                logger.error(f"Error accessing location {location}: {e}")

        return services

    @tool
    async def get_gcp_cloud_run_details(self) -> dict:
        """
            List all Cloud Run services with their container images and return a comprehensive dictionary.

            **Prerequisites:**
            - Install required package: `pip install google-cloud-run`
            - Set up authentication with one of:
            - `export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"`
            - `export GOOGLE_CLOUD_PROJECT="your-project-id"` <<Optional>>

            **Required IAM permissions:**
            - `run.services.list`
            - `run.services.get`
            - `run.locations.list`
        """
        all_services = {}

        # Process locations concurrently but with controlled concurrency
        semaphore = asyncio.Semaphore(5)  # Limit concurrent requests

        async def fetch_location_with_semaphore(location: str):
            async with semaphore:
                return await self._fetch_services_for_location(location)

        # Create tasks for all locations
        tasks = [fetch_location_with_semaphore(location) for location in self.locations]

        # Wait for all tasks to complete
        location_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for location, services in zip(self.locations, location_results):
            if isinstance(services, Exception):
                logger.error(f"Error processing location {location}: {services}")
                continue

            for service_info in services:
                service_key = f"{location}/{service_info['name']}"
                all_services[service_key] = service_info

        # Calculate summary
        summary = {
            'total_services': len(all_services),
            'locations_with_services': len(set(info['location'] for info in all_services.values())),
            'unique_images': len(set(
                c['image']
                for s in all_services.values()
                for c in s['containers']
                if c.get('image') and c['image'] != 'unknown'
            )),
            'services_by_location': {}
        }

        for service_info in all_services.values():
            loc = service_info['location']
            summary['services_by_location'][loc] = summary['services_by_location'].get(loc, 0) + 1

        return {
            'services': all_services,
            'summary': summary,
            'project_id': self.project_id
        }
