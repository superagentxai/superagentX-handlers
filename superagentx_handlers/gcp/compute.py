import base64
import json
import logging  # Import the logging module
import os

from google.api_core import exceptions
from google.cloud import compute_v1
from google.oauth2 import service_account
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class GcpComputeHandler(BaseHandler):
    """
    A handler class to collect comprehensive information about GCP Compute Engine
    resources. This class extends BaseHandler and provides methods for retrieving
    details on VM instances, disks, networks, firewalls, images, and snapshots.
    It focuses on 'get' and 'list' operations for information collection.
    """

    def __init__(
            self,
            service_account_info : dict | str | None = None,
    ):
        super().__init__()
        if service_account_info:
            if isinstance(service_account_info, str):
                service_account_info = json.loads(service_account_info)
            credentials = service_account.Credentials.from_service_account_info(info=service_account_info)
        else:
            _creds_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
            credentials = service_account.Credentials.from_service_account_file(filename=_creds_path)

        self.credentials: service_account.Credentials = credentials

        # Initialize Compute Engine clients for different resource types.
        self.instances_client = compute_v1.InstancesClient(credentials=credentials)
        self.disks_client = compute_v1.DisksClient(credentials=credentials)
        self.networks_client = compute_v1.NetworksClient(credentials=credentials)
        self.subnetworks_client = compute_v1.SubnetworksClient(credentials=credentials)
        self.firewalls_client = compute_v1.FirewallsClient(credentials=credentials)
        self.images_client = compute_v1.ImagesClient(credentials=credentials)
        self.snapshots_client = compute_v1.SnapshotsClient(credentials=credentials)
        self.zones_client = compute_v1.ZonesClient(credentials=credentials)
        self.regions_client = compute_v1.RegionsClient(credentials=credentials)

    async def _get_all_zones(self, project_id: str) -> list:
        """
        Helper method to list all zones available in a given project.
        This is necessary for listing zonal resources like instances and disks.

        Args:
            project_id (str): The ID of the GCP project.

        Returns:
            list: A list of zone names (e.g., "us-central1-a").
        """
        zones = []
        try:
            # List all zones for the project.
            # This requires 'compute.zones.list' permission.
            request = compute_v1.ListZonesRequest(project=project_id)
            for zone in await sync_to_async(self.zones_client.list, request=request):
                zones.append(zone.name)
            logger.info(f"  Found {len(zones)} zones in project '{project_id}'.")
        except exceptions.Forbidden as e:
            logger.error(f"  Permission denied to list zones in project '{project_id}'. Error: {e}")
        except Exception as e:
            logger.error(f"  An unexpected error occurred while listing zones: {e}", exc_info=True)
        return zones

    async def _get_all_regions(self, project_id: str) -> list:
        """
        Helper method to list all regions available in a given project.
        This is necessary for listing regional resources.

        Args:
            project_id (str): The ID of the GCP project.

        Returns:
            list: A list of region names (e.g., "us-central1").
        """
        regions = []
        try:
            # List all regions for the project.
            # This requires 'compute.regions.list' permission.
            request = compute_v1.ListRegionsRequest(project=project_id)
            for region in await sync_to_async(self.regions_client.list, request=request):
                regions.append(region.name)
            logger.info(f"  Found {len(regions)} regions in project '{project_id}'.")
        except exceptions.Forbidden as e:
            logger.error(f"  Permission denied to list regions in project '{project_id}'. Error: {e}")
        except Exception as e:
            logger.error(f"  An unexpected error occurred while listing regions: {e}", exc_info=True)
        return regions

    async def _get_iam_policy_compute_resource(
            self,
            client,
            project_id: str,
            zone_or_region: str,
            resource_name: str,
            resource_type: str
    ) -> dict:
        """
        Helper method to fetch the IAM policy for a specific Compute Engine resource
        that supports direct IAM policy retrieval (e.g., Instance, Disk).

        Args:
            client: The specific Compute Engine client (e.g., self.instances_client, self.disks_client).
            project_id (str): The ID of the GCP project.
            zone_or_region (str): The zone or region of the resource.
            resource_name (str): The name of the resource.
            resource_type (str): The type of the resource (e.g., "instance", "disk").

        Returns:
            dict: The IAM policy as a dictionary if found, otherwise None.
        """
        policy_details = None
        try:
            if resource_type == "instance":
                policy = await sync_to_async(
                    client.get_iam_policy,
                    project=project_id,
                    zone=zone_or_region,
                    resource=resource_name
                )
            elif resource_type == "disk":
                policy = await sync_to_async(
                    client.get_iam_policy,
                    project=project_id,
                    zone=zone_or_region,
                    resource=resource_name
                )
            else:
                logger.info(f"IAM policy retrieval not supported directly for Compute resource type: {resource_type}")
                return {}

            etag_string = base64.b64encode(policy.etag).decode('utf-8') if policy.etag else ''
            policy_details = {
                "version": policy.version,
                "etag": etag_string,
                "bindings": []
            }
            for binding in policy.bindings:
                binding_info = {
                    "role": binding.role,
                    "members": list(binding.members),
                }
                if binding.condition:
                    binding_info["condition"] = {
                        "expression": binding.condition.expression,
                        "title": binding.condition.title,
                        "description": binding.condition.description
                    }
                policy_details["bindings"].append(binding_info)
            logger.info(f"Successfully retrieved IAM policy for {resource_type}: {resource_name}")
        except exceptions.NotFound:
            logger.warning(f"{resource_type.capitalize()} '{resource_name}' not found for IAM policy retrieval.")
        except exceptions.Forbidden as e:
            logger.error(f"Permission denied to get IAM policy for {resource_type} '{resource_name}'. Error: {e}")
        except Exception as e:
            logger.error(
                f"An unexpected error occurred while getting IAM policy for {resource_type} '{resource_name}'."
                f" Error: {e}",
                exc_info=True
            )
        return policy_details

    @tool
    async def collect_instances(self, project_id: str = None, zone: str = None) -> list:
        """
        Collects information about VM instances in a specific project and optionally a zone.
        If no zone is provided, it will collect instances from all accessible zones
        within the specified project.

        Args:
            project_id (str, optional): The ID of the GCP project. Defaults to the project ID
                                        from credentials if None.
            zone (str, optional): The specific zone to list instances from. If None,
                                  instances from all zones in the project will be collected.

        Returns:
            list: A list of dictionaries, each containing instance details.
        """
        target_project_id = project_id or self.credentials.project_id
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect instances.")
            return []

        instances_info = []
        if zone:
            logger.info(f"\n  Collecting VM instances in project '{target_project_id}', zone '{zone}'...")
            try:
                request = compute_v1.ListInstancesRequest(project=target_project_id, zone=zone)
                for instance in await sync_to_async(self.instances_client.list, request=request):
                    instance_details = {
                        "name": instance.name,
                        "id": instance.id,
                        "status": instance.status,
                        "zone": zone,
                        "machine_type": instance.machine_type.split('/')[-1] if instance.machine_type else None,
                        "creation_timestamp": instance.creation_timestamp,
                        "network_interfaces": [
                            {
                                "name": ni.name,
                                "network": ni.network.split('/')[-1] if ni.network else None,
                                "network_ip": ni.network_ip,
                                "access_configs": [
                                    {
                                        "name": ac.name,
                                        "nat_ip": ac.nat_ip,
                                        "type": ac.type_
                                    } for ac in ni.access_configs
                                ] if ni.access_configs else []
                            } for ni in instance.network_interfaces
                        ],
                        "disks": [
                            {
                                "device_name": disk.device_name,
                                "disk_type": disk.disk_type.split('/')[-1] if disk.disk_type else None,
                                "mode": disk.mode,
                                "boot": disk.boot
                            } for disk in instance.disks
                        ],
                        "iam_policy": await self._get_iam_policy_compute_resource(
                            self.instances_client, target_project_id, zone, instance.name, "instance"
                        )
                    }
                    instances_info.append(instance_details)
                logger.info(f"Successfully collected {len(instances_info)} instances in zone '{zone}'.")
            except exceptions.Forbidden as e:
                logger.error(f"Permission denied to list instances in zone '{zone}',"
                             f" project '{target_project_id}'. Error: {e}")
            except Exception as e:
                logger.error(f"An unexpected error occurred while collecting instances in zone '{zone}'. "
                             f"Error: {e}", exc_info=True)
        else:
            logger.info(f"\n  Collecting VM instances in project '{target_project_id}' across all zones...")
            zones = await self._get_all_zones(project_id=target_project_id)
            for z in zones:
                instances_info.extend(await self.collect_instances(project_id=target_project_id, zone=z)) # Recursive call with specific zone
        return instances_info

    @tool
    async def collect_disks(self, project_id: str = None, zone: str = None) -> list:
        """
        Collects information about persistent disks in a specific project and optionally a zone.
        If no zone is provided, it will collect disks from all accessible zones
        within the specified project.

        Args:
            project_id (str, optional): The ID of the GCP project. Defaults to the project ID
                                        from credentials if None.
            zone (str, optional): The specific zone to list disks from. If None,
                                  disks from all zones in the project will be collected.

        Returns:
            list: A list of dictionaries, each containing disk details.
        """
        target_project_id = project_id or self.credentials.project_id
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect disks.")
            return []

        disks_info = []
        if zone:
            logger.info(f"\n  Collecting persistent disks in project '{target_project_id}', zone '{zone}'...")
            try:
                request = compute_v1.ListDisksRequest(project=target_project_id, zone=zone)
                for disk in await sync_to_async(self.disks_client.list, request=request):
                    disk_details = {
                        "name": disk.name,
                        "id": disk.id,
                        "status": disk.status,
                        "zone": zone,
                        "type": disk.type_.split('/')[-1] if disk.type_ else None, # 'type_' to avoid conflict with Python's type()
                        "size_gb": disk.size_gb,
                        "creation_timestamp": disk.creation_timestamp,
                        "source_image": disk.source_image.split('/')[-1] if disk.source_image else None,
                        "users": [user.split('/')[-1] for user in disk.users] if disk.users else [], # VMs attached to this disk
                        "iam_policy": await self._get_iam_policy_compute_resource(
                            self.disks_client, target_project_id, zone, disk.name, "disk"
                        )
                    }
                    disks_info.append(disk_details)
                logger.info(f"Successfully collected {len(disks_info)} disks in zone '{zone}'.")
            except exceptions.Forbidden as e:
                logger.error(f"Permission denied to list disks in zone '{zone}',"
                             f" project '{target_project_id}'. Error: {e}")
            except Exception as e:
                logger.error(f"An unexpected error occurred while collecting disks in zone '{zone}'."
                             f" Error: {e}", exc_info=True)
        else:
            logger.info(f"Collecting persistent disks in project '{target_project_id}' across all zones...")
            zones = await self._get_all_zones(target_project_id)
            for z in zones:
                disks_info.extend(await self.collect_disks(target_project_id, z)) # Recursive call with specific zone
        return disks_info

    @tool
    async def collect_networks(self, project_id: str = None) -> list:
        """
        Collects information about VPC networks in a specific project.

        Args:
            project_id (str, optional): The ID of the GCP project. Defaults to the project ID
                                        from credentials if None.

        Returns:
            list: A list of dictionaries, each containing network details.
        """
        target_project_id = project_id or self.credentials.project_id
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect networks.")
            return []

        logger.info(f"\n  Collecting VPC networks in project '{target_project_id}'...")
        networks_info = []
        try:
            # List networks globally within the project.
            # This requires 'compute.networks.list' permission.
            request = compute_v1.ListNetworksRequest(project=target_project_id)
            for network in await sync_to_async(self.networks_client.list, request=request):
                network_details = {
                    "name": network.name,
                    "id": network.id,
                    "auto_create_subnetworks": network.auto_create_subnetworks,
                    "description": network.description,
                    "gateway_ipv4": network.gateway_ipv4,
                    "creation_timestamp": network.creation_timestamp,
                    # Note: Networks in compute_v1 do not have direct getIamPolicy methods.
                    # Their IAM is generally managed at the project level.
                }
                networks_info.append(network_details)
            logger.info(f"Successfully collected {len(networks_info)} networks.")
        except exceptions.Forbidden as e:
            logger.error(f"Permission denied to list networks in project '{target_project_id}'. Error: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while collecting networks. Error: {e}", exc_info=True)
        return networks_info

    @tool
    async def collect_subnetworks(self, project_id: str = None, region: str = None) -> list:
        """
        Collects information about subnetworks in a specific project and optionally a region.
        If no region is provided, it will collect subnetworks from all accessible regions
        within the specified project.

        Args:
            project_id (str, optional): The ID of the GCP project. Defaults to the project ID from credentials if None.
            region (str, optional): The specific region to list subnetworks from. If None,
             subnetworks from all regions in the project will be collected.

        Returns:
            list: A list of dictionaries, each containing subnetwork details.
        """
        target_project_id = project_id or self.credentials.project_id
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect subnetworks.")
            return []

        subnetworks_info = []
        if region:
            logger.info(f"\n  Collecting subnetworks in project '{target_project_id}', region '{region}'...")
            try:
                request = compute_v1.ListSubnetworksRequest(project=target_project_id, region=region)
                for subnetwork in await sync_to_async(
                        self.subnetworks_client.list,
                        request,
                        project=target_project_id,
                        region=region
                ):
                    subnetwork_details = {
                        "name": subnetwork.name,
                        "id": subnetwork.id,
                        "region": region,
                        "network": subnetwork.network.split('/')[-1] if subnetwork.network else None,
                        "ip_cidr_range": subnetwork.ip_cidr_range,
                        "stack_type": subnetwork.stack_type,
                        "purpose": subnetwork.purpose,
                        "private_ip_google_access": subnetwork.private_ip_google_access,
                        "creation_timestamp": subnetwork.creation_timestamp,
                        # Note: Subnetworks in compute_v1 do not have direct getIamPolicy methods.
                        # Their IAM is generally managed at the project level.
                    }
                    subnetworks_info.append(subnetwork_details)
                logger.info(f"Successfully collected {len(subnetworks_info)} subnetworks in region '{region}'.")
            except exceptions.Forbidden as e:
                logger.error(f"Permission denied to list subnetworks in region '{region}', project"
                             f" '{target_project_id}'. Error: {e}")
            except Exception as e:
                logger.error(f"An unexpected error occurred while collecting subnetworks in region"
                             f" '{region}'. Error: {e}", exc_info=True)
        else:
            logger.info(f"\n  Collecting subnetworks in project '{target_project_id}' across all regions...")
            regions = await self._get_all_regions(target_project_id)
            for r in regions:
                subnetworks_info.extend(await self.collect_subnetworks(target_project_id, r)) # Recursive call with specific region
        return subnetworks_info

    @tool
    async def collect_firewall_rules(self, project_id: str = None) -> list:
        """
        Collects information about firewall rules in a specific project.

        Args:
            project_id (str, optional): The ID of the GCP project. Defaults to the project ID
                                        from credentials if None.

        Returns:
            list: A list of dictionaries, each containing firewall rule details.
        """
        target_project_id = project_id or self.credentials.project_id
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect firewall rules.")
            return []

        logger.info(f"\n  Collecting firewall rules in project '{target_project_id}'...")
        firewall_rules_info = []
        try:
            # List firewall rules globally within the project.
            # This requires 'compute.firewalls.list' permission.
            request = compute_v1.ListFirewallsRequest(project=target_project_id)
            for firewall in await sync_to_async(self.firewalls_client.list, request=request):
                firewall_details = {
                    "name": firewall.name,
                    "id": firewall.id,
                    "direction": firewall.direction,
                    "priority": firewall.priority,
                    "target_tags": list(firewall.target_tags),
                    "source_ranges": list(firewall.source_ranges),
                    "destination_ranges": list(firewall.destination_ranges),
                    "allowed": [
                        {
                            "ip_protocol": allow.ip_protocol,
                            "ports": list(allow.ports)
                        } for allow in firewall.allowed
                    ],
                    "denied": [
                        {
                            "ip_protocol": deny.ip_protocol,
                            "ports": list(deny.ports)
                        } for deny in firewall.denied
                    ],
                    "disabled": firewall.disabled,
                    "network": firewall.network.split('/')[-1] if firewall.network else None,
                    "creation_timestamp": firewall.creation_timestamp,
                    "description": firewall.description,
                    "source_tags": list(firewall.source_tags),
                    "source_service_accounts": list(firewall.source_service_accounts),
                    "target_service_accounts": list(firewall.target_service_accounts)
                    # Note: Firewall rules in compute_v1 do not have direct getIamPolicy methods.
                    # Their IAM is generally managed at the project level.
                }
                firewall_rules_info.append(firewall_details)
            logger.info(f"Successfully collected {len(firewall_rules_info)} firewall rules.")
        except exceptions.Forbidden as e:
            logger.error(f"Permission denied to list firewall rules in project '{target_project_id}'. Error: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while collecting firewall rules. Error: {e}",
                         exc_info=True)
        return firewall_rules_info

    @tool
    async def collect_images(self, project_id: str = None) -> list:
        """
        Collects information about custom images in a specific project.

        Args:
            project_id (str, optional): The ID of the GCP project. Defaults to the project ID
                                        from credentials if None.

        Returns:
            list: A list of dictionaries, each containing image details.
        """
        target_project_id = project_id or self.credentials.project_id
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect images.")
            return []

        logger.info(f"\n  Collecting custom images in project '{target_project_id}'...")
        images_info = []
        try:
            # List images globally within the project.
            # This requires 'compute.images.list' permission.
            request = compute_v1.ListImagesRequest(project=target_project_id)
            for image in await sync_to_async(self.images_client.list, request=request):
                image_details = {
                    "name": image.name,
                    "id": image.id,
                    "status": image.status,
                    "family": image.family,
                    "description": image.description,
                    "creation_timestamp": image.creation_timestamp,
                    "disk_size_gb": image.disk_size_gb,
                    "source_disk": image.source_disk.split('/')[-1] if image.source_disk else None,
                    "source_snapshot": image.source_snapshot.split('/')[-1] if image.source_snapshot else None,
                    "storage_locations": list(image.storage_locations) if image.storage_locations else [],
                    "deprecated": image.deprecated.state.name if image.deprecated else None,
                    # Note: Images in compute_v1 do not have direct getIamPolicy methods.
                    # Their IAM is generally managed at the project level.
                }
                images_info.append(image_details)
            logger.info(f"Successfully collected {len(images_info)} custom images.")
        except exceptions.Forbidden as e:
            logger.error(f"Permission denied to list images in project '{target_project_id}'. Error: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while collecting images. Error: {e}", exc_info=True)
        return images_info

    @tool
    async def collect_snapshots(self, project_id: str = None) -> list:
        """
        Collects information about disk snapshots in a specific project.

        Args:
            project_id (str, optional): The ID of the GCP project. Defaults to the project ID
                                        from credentials if None.

        Returns:
            list: A list of dictionaries, each containing snapshot details.
        """
        target_project_id = project_id or self.credentials.project_id
        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect snapshots.")
            return []

        logger.info(f"\n  Collecting disk snapshots in project '{target_project_id}'...")
        snapshots_info = []
        try:
            # List snapshots globally within the project.
            # This requires 'compute.snapshots.list' permission.
            request = compute_v1.ListSnapshotsRequest(project=target_project_id)
            for snapshot in await sync_to_async(self.snapshots_client.list, request=request):
                snapshot_details = {
                    "name": snapshot.name,
                    "id": snapshot.id,
                    "status": snapshot.status,
                    "description": snapshot.description,
                    "creation_timestamp": snapshot.creation_timestamp,
                    "disk_size_gb": snapshot.disk_size_gb,
                    "source_disk": snapshot.source_disk.split('/')[-1] if snapshot.source_disk else None,
                    "storage_locations": list(snapshot.storage_locations) if snapshot.storage_locations else [],
                    # Note: Snapshots in compute_v1 do not have direct getIamPolicy methods.
                    # Their IAM is generally managed at the project level.
                }
                snapshots_info.append(snapshot_details)
            logger.info(f"Successfully collected {len(snapshots_info)} disk snapshots.")
        except exceptions.Forbidden as e:
            logger.error(f"Permission denied to list snapshots in project '{target_project_id}'. Error: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while collecting snapshots. Error: {e}", exc_info=True)
        return snapshots_info

    @tool
    async def collect_all_compute_info(self, project_id: str = None) -> dict: # project_id is now optional
        """
        Collects comprehensive information for various Compute Engine resources
        within a specified GCP project. This method is exposed as a tool for
        the SuperagentX framework.

        Args:
            project_id (str, optional): The ID of the GCP project to collect Compute info from.
                                        If None, the project ID from the service account credentials
                                        (if available) will be used as a default.

        Returns:
            dict: A dictionary containing lists of collected Compute Engine resource information.
        """
        # Use the provided project_id, or fall back to the one from credentials
        target_project_id = project_id or self.credentials.project_id

        if not target_project_id:
            logger.error("No project ID provided and could not determine from credentials. Cannot collect Compute info.")
            return {
                "instances": [], "disks": [], "networks": [], "subnetworks": [],
                "firewall_rules": [], "images": [], "snapshots": []
            }

        all_compute_info = {
            "instances": [],
            "disks": [],
            "networks": [],
            "subnetworks": [],
            "firewall_rules": [],
            "images": [],
            "snapshots": []
        }

        logger.info(f"\nStarting collection of Compute Engine information for project: '{target_project_id}'...")

        try:
            # Collect global resources (networks, firewalls, images, snapshots)
            all_compute_info["networks"] = await self.collect_networks(project_id=target_project_id)
            all_compute_info["firewall_rules"] = await self.collect_firewall_rules(project_id=target_project_id)
            all_compute_info["images"] = await self.collect_images(project_id=target_project_id)
            all_compute_info["snapshots"] = await self.collect_snapshots(project_id=target_project_id)

            # Collect regional resources (subnetworks)
            regions = await self._get_all_regions(target_project_id)
            for region in regions:
                all_compute_info["subnetworks"].extend(
                    await self.collect_subnetworks(project_id=target_project_id, region=region)
                )

            # Collect zonal resources (instances, disks)
            zones = await self._get_all_zones(target_project_id)
            for zone in zones:
                all_compute_info["instances"].extend(
                    await self.collect_instances(project_id=target_project_id, zone=zone)
                )
                all_compute_info["disks"].extend(
                    await self.collect_disks(project_id=target_project_id, zone=zone)
                )

        except Exception as e:
            logger.error(f"An unexpected error occurred during comprehensive Compute info collection: {e}",
                         exc_info=True)
        return all_compute_info
