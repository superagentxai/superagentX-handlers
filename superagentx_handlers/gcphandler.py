import os
import base64
import asyncio
import json

from google.oauth2 import service_account
from google.cloud import resourcemanager_v3
from google.api_core import exceptions
from google.cloud.resourcemanager_v3.types import SearchOrganizationsRequest
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

class GcpIAMHandler(BaseHandler):
    def __init__(self,scope: list | None = None):
        super().__init__()
        self.scope=scope
        if not self.scope:
            self.scope = ["https://www.googleapis.com/auth/cloud-platform"]
        try:
            creds_path = os.getenv("GCP_AGENT_CREDENTIALS")
            if not creds_path:
                raise ValueError("GCP_AGENT_CREDENTIALS environment variable is not set.")

            credentials = service_account.Credentials.from_service_account_file(
                creds_path,
                scopes=scope
            )

            self.projects_client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            self.folders_client = resourcemanager_v3.FoldersClient(credentials=credentials)
            self.organizations_client = resourcemanager_v3.OrganizationsClient(credentials=credentials)

            print("✅ GCP clients initialized.")
        except Exception as e:
            print(f"Error initializing GCP clients: {e}")
            raise

    def _get_resource_iam_policy(self, resource_name: str, resource_type: str):
        policy_details = None
        try:
            if resource_type == "project":
                policy = self.projects_client.get_iam_policy(resource=resource_name)
            elif resource_type == "folder":
                policy = self.folders_client.get_iam_policy(resource=resource_name)
            elif resource_type == "organization":
                policy = self.organizations_client.get_iam_policy(resource=resource_name)
            else:
                print(f"Unsupported resource type: {resource_type}")
                return None

            etag_string = base64.b64encode(policy.etag).decode('utf-8') if policy.etag else ''
            policy_details = {
                "version": policy.version,
                "etag": etag_string,
                "bindings": [],
                "mfa_enforced": False
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
                    if "mfaPresent()" in binding.condition.expression:
                        policy_details["mfa_enforced"] = True
                policy_details["bindings"].append(binding_info)
            print(f"  ✅ IAM policy fetched for {resource_type}: {resource_name}")
        except exceptions.PermissionDenied as e:
            print(f"  ❌ Permission denied: {resource_name}. {e}")
        except exceptions.NotFound as e:
            print(f"  ❌ Resource not found: {resource_name}. {e}")
        except Exception as e:
            print(f"  ❌ Error fetching IAM policy: {resource_name}. {e}")
        return policy_details

    @tool
    async def collect_organization_iam_evidence(self) -> list:
        """
        Collects IAM policy details for all accessible GCP organizations.
        Includes binding roles, members, and MFA enforcement if found.
        Returns a list of organization IAM policy summaries.
        """
        print("\n📁 Collecting Organizations IAM Evidence")
        organization_evidence = []
        try:
            organizations_response = self.organizations_client.search_organizations(
                request=SearchOrganizationsRequest()
            )
            for org in organizations_response:
                org_name = org.name
                print(f"- {org.display_name} ({org_name})")
                iam_policy = self._get_resource_iam_policy(org_name, "organization")
                if iam_policy:
                    org_entry = {
                        "resource_type": "organization",
                        "organization_id": org.name.split('/')[-1],
                        "display_name": org.display_name,
                        "iam_policy": iam_policy
                    }
                    organization_evidence.append(org_entry)
                    print(json.dumps(org_entry, indent=2))
        except Exception as e:
            print(f"❌ Failed to collect organization evidence: {e}")
        return organization_evidence

    @tool
    async def collect_folder_iam_evidence(self, parent_resource: str = None) -> list:
        """
        Collects IAM policy details for all folders under the given parent resource.
        If no parent is provided, it defaults to collecting from all organizations.
        Detects MFA enforcement and prints each folder IAM configuration.
        """
        print(f"\n📂 Collecting Folder IAM Evidence under: {parent_resource or 'all accessible organizations'}")
        folder_evidence = []
        try:
            if parent_resource:
                folders_response = self.folders_client.list_folders(parent=parent_resource)
                for folder in folders_response:
                    folder_name = folder.name
                    print(f"- Folder: {folder.display_name} ({folder_name})")
                    iam_policy = self._get_resource_iam_policy(folder_name, "folder")
                    if iam_policy:
                        folder_entry = {
                            "resource_type": "folder",
                            "folder_id": folder.name.split('/')[-1],
                            "display_name": folder.display_name,
                            "parent": folder.parent,
                            "iam_policy": iam_policy
                        }
                        folder_evidence.append(folder_entry)
                        print(json.dumps(folder_entry, indent=2))
                    folder_evidence.extend(
                        await self.collect_folder_iam_evidence(parent_resource=folder_name)
                    )
            else:
                orgs = await self.collect_organization_iam_evidence()
                for org in orgs:
                    org_name = f"organizations/{org['organization_id']}"
                    folder_evidence.extend(
                        await self.collect_folder_iam_evidence(parent_resource=org_name)
                    )
        except Exception as e:
            print(f"❌ Failed to collect folder evidence: {e}")
        return folder_evidence

    @tool
    async def collect_project_iam_evidence(self, parent_resource: str = None) -> list:
        """
        Collects IAM policy details for all projects under the given parent resource.
        If no parent is specified, collects all accessible projects.
        MFA checks are included in condition expressions.
        """
        print(f"\n📦 Collecting Project IAM Evidence under: {parent_resource or 'all accessible'}")
        project_evidence = []
        try:
            query_string = ""
            if parent_resource:
                try:
                    parent_type, parent_id = parent_resource.split('/')
                    if parent_type not in ["organizations", "folders"]:
                        print(f"Invalid parent: {parent_resource}")
                        return []
                    query_string = f"parent.type:{parent_type} parent.id:{parent_id}"
                except ValueError:
                    print(f"Invalid parent format: {parent_resource}")
                    return []

            projects_response = self.projects_client.search_projects(query=query_string)
            for project in projects_response:
                project_name = project.name
                print(f"- Project: {project.display_name} ({project_name})")
                iam_policy = self._get_resource_iam_policy(project_name, "project")
                if iam_policy:
                    project_entry = {
                        "resource_type": "project",
                        "project_id": project.project_id,
                        "display_name": project.display_name,
                        "parent": project.parent,
                        "state": project.state.name,
                        "iam_policy": iam_policy
                    }
                    project_evidence.append(project_entry)
                    print(json.dumps(project_entry, indent=2))
        except Exception as e:
            print(f"❌ Failed to collect project evidence: {e}")
        return project_evidence

    @tool
    async def collect_all_iam_evidence(self) -> dict:
        """
        Collects complete IAM policy evidence for the whole profile and enterprise
        Includes roles, members, and whether MFA is enforced for each binding.
        """
        print("\n📦 Collecting ALL IAM Evidence")
        all_evidence = {
            "organizations": [],
            "folders": [],
            "projects": []
        }

        orgs = await self.collect_organization_iam_evidence()
        all_evidence["organizations"].extend(orgs)

        for org in orgs:
            org_name = f"organizations/{org['organization_id']}"
            folders = await self.collect_folder_iam_evidence(parent_resource=org_name)
            all_evidence["folders"].extend(folders)

            projects = await self.collect_project_iam_evidence(parent_resource=org_name)
            all_evidence["projects"].extend(projects)

            for folder in folders:
                folder_name = f"folders/{folder['folder_id']}"
                folder_projects = await self.collect_project_iam_evidence(parent_resource=folder_name)
                all_evidence["projects"].extend(folder_projects)

        standalone = await self.collect_project_iam_evidence()
        existing = {p["project_id"] for p in all_evidence["projects"]}
        for proj in standalone:
            if proj["project_id"] not in existing:
                all_evidence["projects"].append(proj)

        return all_evidence
