import json
import logging
import os
from typing import Any, Optional, List, Dict

from google.cloud import run_v2
from google.oauth2 import service_account
from superagentx.utils.helper import sync_to_async, iter_to_aiter
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

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


def get_nested_attr(obj: Any, path: List[str], default: Any = None) -> Any:
    """Helper to navigate nested attributes."""
    for p in path:
        obj = get_attr(obj, p)
        if obj is None:
            return default
    return obj


class GCPCloudRunHandler(BaseHandler):
    def __init__(
            self,
            scope: Optional[List[str]] = None,
            creds: Optional[str | dict] = None
    ):
        super().__init__()
        self.scope = scope or ["https://www.googleapis.com/auth/cloud-platform"]

        creds = creds or os.getenv("GCP_AGENT_CREDENTIALS")
        if isinstance(creds, str):
            credentials = service_account.Credentials.from_service_account_file(
                creds, scopes=self.scope)
        elif isinstance(creds, dict):
            credentials = service_account.Credentials.from_service_account_info(
                creds, scopes=self.scope)
        else:
            raise ValueError("Invalid credentials")

        self.project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
        if not self.project_id:
            credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
            if credentials_path:
                with open(credentials_path, 'r') as f:
                    creds_info = json.load(f)
                    self.project_id = creds_info.get('project_id')
        if not self.project_id:
            raise ValueError("Project ID not found. Set GOOGLE_CLOUD_PROJECT or provide project_id in service account.")

        self.client = run_v2.ServicesClient(credentials=credentials)
        self.locations = [
            'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
            'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6',
            'europe-central2', 'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2',
            'asia-northeast3', 'asia-south1', 'asia-southeast1', 'asia-southeast2'
        ]

    @tool
    async def get_gcp_cloud_run_details(self) -> Dict[str, Any]:
        all_services = {}

        async for location in iter_to_aiter(self.locations):
            try:
                parent = f"projects/{self.project_id}/locations/{location}"
                request = await sync_to_async(run_v2.ListServicesRequest, parent=parent)
                page_result = await sync_to_async(self.client.list_services, request=request)

                async for service in iter_to_aiter(page_result):
                    service_name = get_attr(service.name.split('/'), -1, 'unknown')
                    service_key = f"{location}/{service_name}"

                    containers = []
                    template_spec = get_nested_attr(service, ['spec', 'template', 'spec'], None)
                    if template_spec:
                        async for container in iter_to_aiter(get_attr(template_spec, 'containers', [])):
                            container_info = {
                                'name': get_attr(container, 'name', 'unnamed'),
                                'image': get_attr(container, 'image', ''),
                                'ports': [],
                                'env_vars': {},
                                'resources': {},
                                'args': list(get_attr(container, 'args', [])),
                                'command': list(get_attr(container, 'command', []))
                            }

                            async for port in iter_to_aiter(get_attr(container, 'ports', [])):
                                container_info['ports'].append({
                                    'container_port': get_attr(port, 'container_port'),
                                    'name': get_attr(port, 'name')
                                })

                            async for env_var in iter_to_aiter(get_attr(container, 'env', [])):
                                env_name = get_attr(env_var, 'name', '')
                                if value := get_attr(env_var, 'value'):
                                    container_info['env_vars'][env_name] = value
                                elif vs := get_attr(env_var, 'value_source'):
                                    container_info['env_vars'][env_name] = {
                                        'source': 'secret_or_config',
                                        'details': str(vs)
                                    }

                            resources = get_attr(container, 'resources', {})
                            container_info['resources']['limits'] = dict(get_attr(resources, 'limits', {}))
                            container_info['resources']['requests'] = dict(get_attr(resources, 'requests', {}))

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
                        'create_time': get_attr(get_attr(service, 'create_time'), 'isoformat', lambda: None)(),
                        'update_time': get_attr(get_attr(service, 'update_time'), 'isoformat', lambda: None)(),
                        'delete_time': get_attr(get_attr(service, 'delete_time'), 'isoformat', lambda: None)(),
                        'containers': containers,
                        'url': get_nested_attr(service, ['status', 'uri']),
                        'traffic': [],
                        'scaling': {},
                        'ingress': get_nested_attr(service, ['spec', 'ingress']),
                        'timeout': get_attr(template_spec, 'timeout_seconds'),
                        'service_account': get_attr(template_spec, 'service_account')
                    }

                    async for traffic in iter_to_aiter(get_nested_attr(service, ['status', 'traffic'], [])):
                        service_info['traffic'].append({
                            'type': get_attr(traffic, 'type_', 'UNKNOWN'),
                            'percent': get_attr(traffic, 'percent', 0),
                            'revision': get_attr(traffic, 'revision'),
                            'tag': get_attr(traffic, 'tag'),
                            'url': get_attr(traffic, 'url')
                        })

                    scaling = get_attr(template_spec, 'scaling')
                    if scaling:
                        service_info['scaling'] = {
                            'min_instance_count': get_attr(scaling, 'min_instance_count', 0),
                            'max_instance_count': get_attr(scaling, 'max_instance_count', 0)
                        }

                    all_services[service_key] = service_info

            except Exception as e:
                msg = str(e).lower()
                if not any(err in msg for err in ["not found", "forbidden", "permission denied", "does not exist"]):
                    logger.error(f"Error accessing location {location}: {e}")
                continue

        # Summary
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
        async for service_info in iter_to_aiter(all_services.values()):
            loc = service_info['location']
            summary['services_by_location'][loc] = summary['services_by_location'].get(loc, 0) + 1

        return {
            'services': all_services,
            'summary': summary,
            'project_id': self.project_id
        }

