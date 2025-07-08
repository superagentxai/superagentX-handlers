import json
from google.cloud import run_v2
from google.oauth2 import service_account
import os


def main():
    """
    List all Cloud Run services with their container images and return a comprehensive dictionary.
    """
    try:
        # Initialize the Cloud Run client
        client = run_v2.ServicesClient()

        # Get the project ID from environment variable or service account
        project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
        if not project_id:
            # Try to get project ID from service account key file
            credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
            if credentials_path:
                with open(credentials_path, 'r') as f:
                    creds_info = json.load(f)
                    project_id = creds_info.get('project_id')

        if not project_id:
            raise ValueError(
                "Project ID not found. Set GOOGLE_CLOUD_PROJECT environment variable or ensure service account has project_id.")

        # Get all regions where Cloud Run is available
        locations = ['us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
                     'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6',
                     'europe-central2', 'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2',
                     'asia-northeast3', 'asia-south1', 'asia-southeast1', 'asia-southeast2']

        all_services = {}

        for location in locations:
            try:
                # Construct the parent path for the location
                parent = f"projects/{project_id}/locations/{location}"

                # List all services in this location
                request = run_v2.ListServicesRequest(parent=parent)
                page_result = client.list_services(request=request)

                for service in page_result:
                    service_name = service.name.split('/')[-1]
                    service_key = f"{location}/{service_name}"

                    # Extract container information safely
                    containers = []
                    try:
                        if (hasattr(service, 'spec') and service.spec and
                                hasattr(service.spec, 'template') and service.spec.template and
                                hasattr(service.spec.template, 'spec') and service.spec.template.spec):

                            template_spec = service.spec.template.spec

                            if hasattr(template_spec, 'containers') and template_spec.containers:
                                for container in template_spec.containers:
                                    container_info = {
                                        'name': getattr(container, 'name', 'unnamed'),
                                        'image': getattr(container, 'image', ''),
                                        'ports': [],
                                        'env_vars': {},
                                        'resources': {},
                                        'args': list(getattr(container, 'args', [])),
                                        'command': list(getattr(container, 'command', []))
                                    }

                                    # Extract ports safely
                                    if hasattr(container, 'ports') and container.ports:
                                        for port in container.ports:
                                            port_info = {
                                                'container_port': getattr(port, 'container_port', None),
                                                'name': getattr(port, 'name', None)
                                            }
                                            container_info['ports'].append(port_info)

                                    # Extract environment variables safely
                                    if hasattr(container, 'env') and container.env:
                                        for env_var in container.env:
                                            env_name = getattr(env_var, 'name', '')
                                            if hasattr(env_var, 'value') and env_var.value:
                                                container_info['env_vars'][env_name] = env_var.value
                                            elif hasattr(env_var, 'value_source') and env_var.value_source:
                                                container_info['env_vars'][env_name] = {
                                                    'source': 'secret_or_config',
                                                    'details': str(env_var.value_source)
                                                }

                                    # Extract resource limits/requests safely
                                    if hasattr(container, 'resources') and container.resources:
                                        if hasattr(container.resources, 'limits') and container.resources.limits:
                                            container_info['resources']['limits'] = dict(container.resources.limits)
                                        if hasattr(container.resources, 'requests') and container.resources.requests:
                                            container_info['resources']['requests'] = dict(container.resources.requests)

                                    containers.append(container_info)
                    except Exception as container_error:
                        print(f"Error extracting container info for {service_name}: {container_error}")
                        containers = [{'name': 'error', 'image': 'unknown', 'error': str(container_error)}]

                    # Service-level information
                    service_info = {
                        'name': service_name,
                        'location': location,
                        'full_name': service.name,
                        'uid': getattr(service, 'uid', ''),
                        'generation': getattr(service, 'generation', 0),
                        'labels': dict(service.labels) if hasattr(service, 'labels') and service.labels else {},
                        'annotations': dict(service.annotations) if hasattr(service,
                                                                            'annotations') and service.annotations else {},
                        'create_time': service.create_time.isoformat() if hasattr(service,
                                                                                  'create_time') and service.create_time else None,
                        'update_time': service.update_time.isoformat() if hasattr(service,
                                                                                  'update_time') and service.update_time else None,
                        'delete_time': service.delete_time.isoformat() if hasattr(service,
                                                                                  'delete_time') and service.delete_time else None,
                        'containers': containers,
                        'url': None,
                        'traffic': [],
                        'scaling': {},
                        'ingress': None,
                        'timeout': None,
                        'service_account': None
                    }

                    # Extract URL from status safely
                    try:
                        if hasattr(service, 'status') and service.status and hasattr(service.status, 'uri'):
                            service_info['url'] = service.status.uri
                    except Exception as url_error:
                        print(f"Error extracting URL for {service_name}: {url_error}")

                    # Extract traffic information safely
                    try:
                        if (hasattr(service, 'status') and service.status and
                                hasattr(service.status, 'traffic') and service.status.traffic):
                            for traffic in service.status.traffic:
                                traffic_info = {
                                    'type': getattr(traffic, 'type_', 'UNKNOWN'),
                                    'percent': getattr(traffic, 'percent', 0),
                                    'revision': getattr(traffic, 'revision', None),
                                    'tag': getattr(traffic, 'tag', None),
                                    'url': getattr(traffic, 'url', None)
                                }
                                service_info['traffic'].append(traffic_info)
                    except Exception as traffic_error:
                        print(f"Error extracting traffic info for {service_name}: {traffic_error}")

                    # Extract scaling and other template spec information safely
                    try:
                        if (hasattr(service, 'spec') and service.spec and
                                hasattr(service.spec, 'template') and service.spec.template and
                                hasattr(service.spec.template, 'spec') and service.spec.template.spec):

                            template_spec = service.spec.template.spec

                            # Scaling information
                            if hasattr(template_spec, 'scaling') and template_spec.scaling:
                                scaling = template_spec.scaling
                                service_info['scaling'] = {
                                    'min_instance_count': getattr(scaling, 'min_instance_count', 0),
                                    'max_instance_count': getattr(scaling, 'max_instance_count', 0)
                                }

                            # Other template spec fields
                            service_info['timeout'] = getattr(template_spec, 'timeout_seconds', None)
                            service_info['service_account'] = getattr(template_spec, 'service_account', None)

                        # Ingress settings
                        if (hasattr(service, 'spec') and service.spec and
                                hasattr(service.spec, 'ingress') and service.spec.ingress):
                            service_info['ingress'] = getattr(service.spec.ingress, 'name', str(service.spec.ingress))
                    except Exception as spec_error:
                        print(f"Error extracting spec info for {service_name}: {spec_error}")

                    all_services[service_key] = service_info

            except Exception as e:
                # Skip regions where we don't have access or services
                error_msg = str(e).lower()
                if ("not found" not in error_msg and
                        "forbidden" not in error_msg and
                        "permission denied" not in error_msg and
                        "does not exist" not in error_msg):
                    print(f"Error accessing location {location}: {e}")
                continue

        # Summary statistics
        summary = {
            'total_services': len(all_services),
            'locations_with_services': len(set(info['location'] for info in all_services.values())),
            'unique_images': len(set(
                container['image']
                for service in all_services.values()
                for container in service['containers']
                if container.get('image') and container['image'] != 'unknown'
            )),
            'services_by_location': {}
        }

        # Count services by location
        for service_info in all_services.values():
            location = service_info['location']
            if location not in summary['services_by_location']:
                summary['services_by_location'][location] = 0
            summary['services_by_location'][location] += 1

        # Prepare final result
        result = {
            'services': all_services,
            'summary': summary,
            'project_id': project_id
        }

        # Print summary for visibility
        print(f"\nCloud Run Services Summary:")
        print(f"Project ID: {project_id}")
        print(f"Total services found: {summary['total_services']}")
        print(f"Locations with services: {summary['locations_with_services']}")
        print(f"Unique container images: {summary['unique_images']}")
        print(f"Services by location: {summary['services_by_location']}")
        print(f"Results : {result}")
        return result

    except Exception as e:
        print(f"Error: {e}")
        return {
            'error': str(e),
            'services': {},
            'summary': {
                'total_services': 0,
                'locations_with_services': 0,
                'unique_images': 0,
                'services_by_location': {}
            }
        }


if __name__ == "__main__":
    result = main()

    # Optionally save to file
    with open('cloud_run_services.json', 'w') as f:
        json.dump(result, f, indent=2)

    print(f"\nResults saved to cloud_run_services.json")