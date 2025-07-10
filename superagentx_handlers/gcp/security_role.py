import base64
import json
import logging
import os

from google.api_core import exceptions
from google.cloud import iam_admin_v1
from google.cloud import resourcemanager_v3
from google.oauth2 import service_account
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class GcpSecurityRoleHandler(BaseHandler):
    """
    A handler class to collect comprehensive security-related information from GCP,
    focusing on Identity and Access Management (IAM) and related configurations.
    This class extends BaseHandler and provides methods for retrieving IAM policies
    for organizations, folders, and projects, as well as listing service accounts
    and custom roles.
    It focuses on 'get' and 'list' operations for information collection.
    """

    def __init__(
            self,
            creds: str | None = None,
            scope: list | None = None
    ):
        """
        Initializes the GCP Security Info Collector with authenticated clients for
        Resource Manager and IAM Admin services. It expects the path to a service account
        key file in the GCP_AGENT_CREDENTIALS environment variable.
        """
        super().__init__()
        if not scope:
            # Broad 'cloud-platform' scope for general access, or more specific scopes
            # like 'https://www.googleapis.com/auth/cloud-platform'
            # 'https://www.googleapis.com/auth/cloud-platform' is generally recommended
            # for broad read access needed by this collector.
            scope = ["https://www.googleapis.com/auth/cloud-platform"]
        try:
            creds_path = creds or os.getenv("GCP_AGENT_CREDENTIALS")
            if not creds_path:
                raise ValueError(
                    "GCP_AGENT_CREDENTIALS environment variable is not set. "
                    "Please set it to the path of your service account key file."
                )

            # Load credentials file to extract project_id (if available)
            with open(creds_path, 'r') as f:
                creds_dict = json.load(f)
                self.project_from_creds = creds_dict.get("project_id")

            # Load credentials from file path with appropriate scopes.
            credentials = service_account.Credentials.from_service_account_file(
                creds_path,
                scopes=scope
            )

            # Initialize clients for Resource Manager (for Org/Folder/Project IAM)
            self.organizations_client = resourcemanager_v3.OrganizationsClient(credentials=credentials)
            self.folders_client = resourcemanager_v3.FoldersClient(credentials=credentials)
            self.projects_client = resourcemanager_v3.ProjectsClient(credentials=credentials)

            # Initialize IAM Admin client (for Service Accounts and Custom Roles)
            self.iam_admin_client = iam_admin_v1.IAMClient(credentials=credentials)

            logger.info(
                "GCP Security clients (Resource Manager, IAM Admin) initialized with custom service account credentials.")
            if self.project_from_creds:
                logger.info(f"Default project ID from credentials: '{self.project_from_creds}'")
            else:
                logger.warning("Could not determine default project ID from credentials file.")

        except FileNotFoundError:
            logger.error(f"Credentials file not found at: {creds_path}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in credentials file: {creds_path}")
            raise
        except Exception as e:
            logger.error(
                f"Error initializing GCP Security clients: {e}\n"
                "Please ensure the GCP_AGENT_CREDENTIALS environment variable points to a valid service account key file, "
                "and that the service account has necessary permissions to list and get IAM-related resources."
            )
            raise

    def _get_resource_iam_policy(self, resource_name: str, resource_type: str):
        """
        Helper method to fetch the IAM policy for a given resource (Org, Folder, Project).

        Args:
            resource_name (str): The full resource name (e.g., "organizations/ORG_ID", "folders/FOLDER_ID", "projects/PROJECT_ID").
            resource_type (str): The type of the resource ("organization", "folder", "project").

        Returns:
            dict: The IAM policy as a dictionary if found, otherwise None.
        """
        policy_details = None
        try:
            if resource_type == "organization":
                policy = self.organizations_client.get_iam_policy(resource=resource_name)
            elif resource_type == "folder":
                policy = self.folders_client.get_iam_policy(resource=resource_name)
            elif resource_type == "project":
                policy = self.projects_client.get_iam_policy(resource=resource_name)
            else:
                logger.warning(f"  Unsupported resource type for IAM policy retrieval: {resource_type}")
                return None

            # etag is bytes, so encode it to base64 and then decode to string for safe representation.
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
            logger.info(f"  Successfully retrieved IAM policy for {resource_type}: {resource_name}")
        except exceptions.NotFound:
            logger.warning(f"  {resource_type.capitalize()} '{resource_name}' not found for IAM policy retrieval.")
        except exceptions.Forbidden as e:
            logger.error(f"  Permission denied to get IAM policy for {resource_type} '{resource_name}'. Error: {e}")
        except Exception as e:
            logger.error(
                f"  An unexpected error occurred while getting IAM policy for {resource_type} '{resource_name}'. Error: {e}",
                exc_info=True)
        return policy_details

    @tool
    async def collect_organization_iam(self) -> list:
        """
        Collects IAM policies for all accessible organizations.

        Returns:
            list: A list of dictionaries, where each dictionary contains
                  organization details and its IAM policy.
        """
        logger.info("\nCollecting IAM policies for Organizations...")
        organization_policies = []
        try:
            # Use search_organizations with an empty request to list all accessible organizations.
            # This requires the 'resourcemanager.organizations.search' permission.
            organizations_response = self.organizations_client.search_organizations()
            for org in organizations_response:
                org_name = org.name  # Format: organizations/ORGANIZATION_ID
                logger.info(f"Processing Organization: {org.display_name} ({org_name})")
                iam_policy = self._get_resource_iam_policy(org_name, "organization")
                if iam_policy:
                    organization_policies.append({
                        "resource_type": "organization",
                        "organization_id": org.name.split('/')[-1],
                        "display_name": org.display_name,
                        "iam_policy": iam_policy
                    })
        except exceptions.Forbidden as e:
            logger.error(f"Permission denied to search organizations. Error: {e}")
            logger.error("Ensure the service account/user has 'resourcemanager.organizations.search' permission.")
        except Exception as e:
            logger.error(f"An error occurred while collecting organization IAM evidence: {e}", exc_info=True)
        return organization_policies

    @tool
    async def collect_folder_iam(self, parent_resource: str = None, organization_id: str = None) -> list:
        """
        Collects IAM policies for all accessible folders under a given parent (organization or folder).
        If no parent_resource is provided, it will attempt to discover folders by first listing
        organizations (if organization_id is provided or discoverable).

        Args:
            parent_resource (str, optional): The full resource name of the parent
                                             (e.g., "organizations/ORG_ID" or "folders/FOLDER_ID").
            organization_id (str, optional): The ID of the GCP organization to start folder discovery from.
                                             Used if parent_resource is None.

        Returns:
            list: A list of dictionaries, where each dictionary contains
                  folder details and its IAM policy.
        """
        folder_policies = []
        if parent_resource:
            logger.info(f"\nCollecting IAM policies for Folders under {parent_resource}...")
            try:
                folders_response = self.folders_client.list_folders(parent=parent_resource)
                for folder in folders_response:
                    folder_name = folder.name
                    logger.info(f"  Processing Folder: {folder.display_name} ({folder_name})")
                    iam_policy = self._get_resource_iam_policy(folder_name, "folder")
                    if iam_policy:
                        folder_policies.append({
                            "resource_type": "folder",
                            "folder_id": folder.name.split('/')[-1],
                            "display_name": folder.display_name,
                            "parent": folder.parent,
                            "iam_policy": iam_policy
                        })
                    # Recursively collect folders nested under this folder
                    folder_policies.extend(await self.collect_folder_iam(parent_resource=folder_name))
            except exceptions.Forbidden as e:
                logger.error(f"Permission denied to list folders under {parent_resource}. Error: {e}")
                logger.error(
                    "Ensure the service account/user has 'resourcemanager.folders.list' permission on the parent.")
            except Exception as e:
                logger.error(f"An error occurred while collecting folder IAM evidence under {parent_resource}: {e}",
                             exc_info=True)
        else:
            logger.info(
                f"\nCollecting IAM policies for Folders (discovering via organizations, starting from {organization_id or 'all accessible'})...")
            organizations = []
            if organization_id:
                # If a specific organization ID is given, try to get just that organization
                try:
                    org = self.organizations_client.get_organization(name=f"organizations/{organization_id}")
                    organizations.append(org)
                except exceptions.NotFound:
                    logger.warning(f"Organization '{organization_id}' not found. Cannot collect folders.")
                except exceptions.Forbidden as e:
                    logger.error(f"Permission denied to get organization '{organization_id}'. Error: {e}")
            else:
                # Otherwise, collect all accessible organizations
                organizations = await self.collect_organization_iam()  # Use the tool to get organizations

            for org in organizations:
                org_name = f"organizations/{org['organization_id']}" if isinstance(org, dict) else org.name
                org_display_name = org['display_name'] if isinstance(org, dict) else org.display_name
                logger.info(f"  Listing folders under Organization: {org_display_name} ({org_name})")
                folder_policies.extend(await self.collect_folder_iam(
                    parent_resource=org_name))  # Recursive call with organization as parent
        return folder_policies

    @tool
    async def collect_project_iam(self, parent_resource: str = None, project_id: str = None) -> list:
        """
        Collects IAM policies for all accessible projects under a given parent (organization or folder),
        or for a specific project ID, or all accessible projects if no parent/project_id is specified.

        Args:
            parent_resource (str, optional): The full resource name of the parent
                                             (e.g., "organizations/ORG_ID" or "folders/FOLDER_ID").
            project_id (str, optional): The ID of a specific GCP project to collect IAM for.
                                        Defaults to the project ID from credentials if no
                                        parent_resource is provided.

        Returns:
            list: A list of dictionaries, where each dictionary contains
                  project details and its IAM policy.
        """
        logger.info(f"\nCollecting IAM policies for Projects...")
        project_policies = []
        query_string = ""
        target_project_id = project_id or self.project_from_creds

        if parent_resource:
            try:
                parent_type, parent_id = parent_resource.split('/')
                if parent_type not in ["organizations", "folders"]:
                    logger.warning(
                        f"⚠️ Invalid parent_resource type: {parent_type}. Expected 'organizations' or 'folders'.")
                    return []
                query_string = f'parent.type:{parent_type} parent.id:{parent_id}'
                logger.info(f"  Searching projects under parent: {parent_resource}")
            except ValueError:
                logger.warning(
                    f"⚠️ Invalid parent_resource format: {parent_resource}. Expected 'organizations/ORG_ID' or 'folders/FOLDER_ID'")
                return []
        elif target_project_id:
            # If a specific project_id is provided or derived from creds, search for that project directly
            query_string = f'id:{target_project_id}'
            logger.info(f"  Searching for specific project ID: {target_project_id}")
        else:
            logger.info("  Searching all accessible projects (no parent or specific project ID provided).")
            # An empty query string for search_projects will list all accessible projects.

        try:
            projects_response = self.projects_client.search_projects(query=query_string)

            for project in projects_response:
                project_name = project.name  # Format: projects/PROJECT_ID
                logger.info(f"Processing Project: {project.display_name} ({project_name})")
                iam_policy = self._get_resource_iam_policy(project_name, "project")
                if iam_policy:
                    project_policies.append({
                        "resource_type": "project",
                        "project_id": project.project_id,
                        "display_name": project.display_name,
                        "parent": project.parent,
                        "state": project.state.name,
                        "iam_policy": iam_policy
                    })
        except exceptions.Forbidden as e:
            logger.error(f"Permission denied to search projects. Error: {e}")
            logger.error(
                "Ensure the service account/user has 'resourcemanager.projects.search' permission on the relevant resources.")
        except Exception as e:
            logger.error(f"An unexpected error occurred while collecting project IAM evidence: {e}", exc_info=True)
        return project_policies

    @tool
    async def collect_service_accounts(self, project_id: str = None) -> list:
        """
        Collects information about service accounts in a specific project.

        Args:
            project_id (str, optional): The ID of the GCP project. Defaults to the project ID
                                        from credentials if None.

        Returns:
            list: A list of dictionaries, each containing service account details.
        """
        target_project_id = project_id or self.project_from_creds
        if not target_project_id:
            logger.error(
                "No project ID provided and could not determine from credentials. Cannot collect service accounts.")
            return []

        logger.info(f"\nCollecting Service Accounts in project '{target_project_id}'...")
        service_accounts_info = []
        try:
            # List service accounts for the project.
            # This requires 'iam.serviceAccounts.list' permission.
            request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{target_project_id}")
            for sa in self.iam_admin_client.list_service_accounts(request=request):
                sa_details = {
                    "name": sa.name,
                    "email": sa.email,
                    "display_name": sa.display_name,
                    "description": sa.description,
                    "disabled": sa.disabled,
                    "unique_id": sa.unique_id,
                    "oauth2_client_id": sa.oauth2_client_id,
                    "create_time": sa.create_time.isoformat() if sa.create_time else None
                }
                service_accounts_info.append(sa_details)
            logger.info(
                f"  Successfully collected {len(service_accounts_info)} service accounts in project '{target_project_id}'.")
        except exceptions.Forbidden as e:
            logger.error(f"  Permission denied to list service accounts in project '{target_project_id}'. Error: {e}")
            logger.error("Ensure the service account/user has 'iam.serviceAccounts.list' permission.")
        except Exception as e:
            logger.error(f"  An unexpected error occurred while collecting service accounts. Error: {e}", exc_info=True)
        return service_accounts_info

    @tool
    async def collect_custom_roles(self, project_id: str = None, organization_id: str = None) -> list:
        """
        Collects information about custom IAM roles in a specific project or organization.
        One of project_id or organization_id must be provided.

        Args:
            project_id (str, optional): The ID of the GCP project.
            organization_id (str, optional): The ID of the GCP organization.

        Returns:
            list: A list of dictionaries, each containing custom role details.
        """
        parent_resource = ""
        if project_id:
            parent_resource = f"projects/{project_id}"
            logger.info(f"\nCollecting Custom Roles in project '{project_id}'...")
        elif organization_id:
            parent_resource = f"organizations/{organization_id}"
            logger.info(f"\nCollecting Custom Roles in organization '{organization_id}'...")
        else:
            logger.warning("Either project_id or organization_id must be provided to collect custom roles.")
            return []

        custom_roles_info = []
        try:
            # List custom roles for the specified parent.
            # This requires 'iam.roles.list' permission on the parent.
            request = iam_admin_v1.ListRolesRequest(parent=parent_resource, show_deleted=False)
            for role in self.iam_admin_client.list_roles(request=request):
                # Filter for custom roles (role.name contains 'projects/' or 'organizations/')
                # and exclude predefined roles (which don't have a parent in their name structure)
                if parent_resource in role.name:
                    role_details = {
                        "name": role.name,
                        "title": role.title,
                        "description": role.description,
                        "stage": role.stage.name,
                        "included_permissions": list(role.included_permissions),
                        "deleted": role.deleted,
                        "etag": base64.b64encode(role.etag).decode('utf-8') if role.etag else ''
                    }
                    custom_roles_info.append(role_details)
            logger.info(f"  Successfully collected {len(custom_roles_info)} custom roles for '{parent_resource}'.")
        except exceptions.Forbidden as e:
            logger.error(f"  Permission denied to list custom roles for '{parent_resource}'. Error: {e}")
            logger.error("Ensure the service account/user has 'iam.roles.list' permission on the parent.")
        except Exception as e:
            logger.error(f"  An unexpected error occurred while collecting custom roles. Error: {e}", exc_info=True)
        return custom_roles_info

    @tool
    async def collect_all_security_info(self, project_id: str = None, organization_id: str = None) -> dict:
        """
        Collects comprehensive security-related information for GCP, including IAM policies,
        service accounts, and custom roles within a specified project or organization.
        This method is exposed as a tool for the SuperagentX framework.

        Args:
            project_id (str, optional): The ID of the GCP project to collect security info from.
                                        If provided, will collect project-level IAM, service accounts,
                                        and project-level custom roles. Defaults to the project ID from credentials if
                                        organization_id is also None.
            organization_id (str, optional): The ID of the GCP organization to collect security info from.
                                             If provided, will collect organization-level IAM and custom roles.
                                             If both project_id and organization_id are None, it will attempt
                                             to collect organization-level IAM and then traverse to folders/projects.

        Returns:
            dict: A dictionary containing lists of collected security information.
        """
        all_security_info = {
            "organization_iam_policies": [],
            "folder_iam_policies": [],
            "project_iam_policies": [],
            "service_accounts": [],
            "custom_roles": []
        }

        logger.info(f"\nStarting comprehensive collection of GCP Security information...")

        try:
            target_project_id = project_id or self.project_from_creds

            if organization_id:
                logger.info(f"Collecting security info for organization: {organization_id}")
                # Collect organization-level IAM policies
                org_name = f"organizations/{organization_id}"
                iam_policy = self._get_resource_iam_policy(org_name, "organization")
                if iam_policy:
                    all_security_info["organization_iam_policies"].append({
                        "resource_type": "organization",
                        "organization_id": organization_id,
                        "iam_policy": iam_policy
                    })
                # Collect custom roles at the organization level
                all_security_info["custom_roles"].extend(
                    await self.collect_custom_roles(organization_id=organization_id))

                # Traverse folders and projects under this organization
                folders_in_org = await self.collect_folder_iam(organization_id=organization_id)  # Use tool function
                all_security_info["folder_iam_policies"].extend(folders_in_org)

                for folder in folders_in_org:
                    folder_name = f"folders/{folder['folder_id']}"
                    projects_in_folder = await self.collect_project_iam(
                        parent_resource=folder_name)  # Use tool function
                    all_security_info["project_iam_policies"].extend(projects_in_folder)
                    # Collect service accounts and custom roles for each project found
                    for proj in projects_in_folder:
                        all_security_info["service_accounts"].extend(
                            await self.collect_service_accounts(project_id=proj['project_id']))  # Use tool function
                        all_security_info["custom_roles"].extend(
                            await self.collect_custom_roles(project_id=proj['project_id']))  # Use tool function

                # Also collect projects directly under the organization
                projects_in_org = await self.collect_project_iam(parent_resource=org_name)  # Use tool function
                all_security_info["project_iam_policies"].extend(projects_in_org)
                for proj in projects_in_org:
                    all_security_info["service_accounts"].extend(
                        await self.collect_service_accounts(project_id=proj['project_id']))  # Use tool function
                    all_security_info["custom_roles"].extend(
                        await self.collect_custom_roles(project_id=proj['project_id']))  # Use tool function

            elif target_project_id:
                logger.info(f"Collecting security info for project: {target_project_id}")
                # Collect project-level IAM policies
                project_name = f"projects/{target_project_id}"
                iam_policy = self._get_resource_iam_policy(project_name, "project")
                if iam_policy:
                    all_security_info["project_iam_policies"].append({
                        "resource_type": "project",
                        "project_id": target_project_id,
                        "iam_policy": iam_policy
                    })
                # Collect service accounts for the project
                all_security_info["service_accounts"].extend(
                    await self.collect_service_accounts(project_id=target_project_id))  # Use tool function
                # Collect custom roles at the project level
                all_security_info["custom_roles"].extend(
                    await self.collect_custom_roles(project_id=target_project_id))  # Use tool function

            else:
                # If neither project_id nor organization_id is provided,
                # attempt to discover organizations and then traverse.
                logger.info(
                    "No specific project_id or organization_id provided. Attempting to discover and traverse hierarchy.")
                organizations = await self.collect_organization_iam()  # Use tool function
                all_security_info["organization_iam_policies"].extend(organizations)

                for org in organizations:
                    org_name = f"organizations/{org['organization_id']}"
                    all_security_info["custom_roles"].extend(
                        await self.collect_custom_roles(organization_id=org['organization_id']))  # Use tool function

                    folders_in_org = await self.collect_folder_iam(parent_resource=org_name)  # Use tool function
                    all_security_info["folder_iam_policies"].extend(folders_in_org)

                    for folder in folders_in_org:
                        folder_name = f"folders/{folder['folder_id']}"
                        projects_in_folder = await self.collect_project_iam(
                            parent_resource=folder_name)  # Use tool function
                        all_security_info["project_iam_policies"].extend(projects_in_folder)
                        # Collect service accounts and custom roles for each project found
                        for proj in projects_in_folder:
                            all_security_info["service_accounts"].extend(
                                await self.collect_service_accounts(project_id=proj['project_id']))  # Use tool function
                            all_security_info["custom_roles"].extend(
                                await self.collect_custom_roles(project_id=proj['project_id']))  # Use tool function

                    # Collect projects directly under the organization
                    projects_in_org = await self.collect_project_iam(parent_resource=org_name)  # Use tool function
                    all_security_info["project_iam_policies"].extend(projects_in_org)
                    for proj in projects_in_org:
                        all_security_info["service_accounts"].extend(
                            await self.collect_service_accounts(project_id=proj['project_id']))  # Use tool function
                        all_security_info["custom_roles"].extend(
                            await self.collect_custom_roles(project_id=proj['project_id']))  # Use tool function

                # Finally, collect any standalone projects not under an organization/folder
                logger.info("\nCollecting any remaining standalone project IAM policies...")
                standalone_projects = await self.collect_project_iam()  # Use tool function
                # Deduplicate projects
                existing_project_ids = {p['project_id'] for p in all_security_info["project_iam_policies"]}
                for proj in standalone_projects:
                    if proj['project_id'] not in existing_project_ids:
                        all_security_info["project_iam_policies"].append(proj)
                        existing_project_ids.add(proj['project_id'])
                        # Also collect SA and custom roles for these standalone projects
                        all_security_info["service_accounts"].extend(
                            await self.collect_service_accounts(project_id=proj['project_id']))  # Use tool function
                        all_security_info["custom_roles"].extend(
                            await self.collect_custom_roles(project_id=proj['project_id']))  # Use tool function


        except Exception as e:
            logger.error(f"An unexpected error occurred during comprehensive Security info collection: {e}",
                         exc_info=True)

        return all_security_info
