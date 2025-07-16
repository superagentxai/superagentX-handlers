import asyncio
import logging
import os
from datetime import datetime
from typing import Any, Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class SnykHandler(BaseHandler):
    """
    Snyk API client handler for vulnerability scanning and management.
    Based on Snyk API v2024-10-15 documentation.
    """

    def __init__(
            self,
            api_token: str | None = None,
            base_url: str = "https://api.snyk.io/rest",
            version: str = "2024-10-15",
            timeout: int = 30
    ):
        super().__init__()
        self.api_token = api_token or os.getenv("SNYK_API_TOKEN")
        self.base_url = base_url
        self.version = version
        self.timeout = timeout

        self.headers = {
            "Authorization": f"token {self.api_token}",
            "Content-Type": "application/vnd.api+json",
            "User-Agent": "SuperAgentX-Snyk-Handler/1.0"
        }
        self.timeout_config = ClientTimeout(total=self.timeout)

    async def _make_request(
            self,
            method: str,
            endpoint: str,
            params: Optional[dict] = None,
            data: Optional[dict] = None
    ) -> Any:
        """
        Make an HTTP request to the Snyk API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            params: Query parameters
            data: Request body data

        Returns:
            Any: API response data
        """
        url = f"{self.base_url}/{endpoint}"

        async with ClientSession(
                timeout=self.timeout_config,
                headers=self.headers
        ) as session:
            try:
                async with session.request(
                        method=method,
                        url=url,
                        params=params or {},
                        json=data
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientResponseError as e:
                logger.error(f"HTTP error {e.status}: {e.message}")
            except aiohttp.ClientError as e:
                logger.error(f"Request error: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}")

    @tool
    async def get_organizations(self) -> list[dict]:
        """
        Retrieve all organizations accessible to the user.

        Returns:
            list[dict]: List of organization details
        """
        logger.info("Fetching Snyk organizations...")
        try:
            response = await self._make_request(
                method="GET",
                endpoint="orgs"
            )
            orgs = response.get("data", [])
            logger.info(f"Retrieved {len(orgs)} organizations")
            return orgs
        except Exception as e:
            logger.error(f"Error fetching organizations: {e}")
            return []

    @tool
    async def get_projects(
            self,
            org_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve all projects for a specific organization.

        Args:
            org_id (str): Organization ID
            limit (int, optional): Maximum number of projects to retrieve

        Returns:
            list[dict]: List of project details
        """
        logger.info(f"Fetching projects for organization {org_id}...")
        try:
            params = {
                "limit": limit
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/projects",
                params=params
            )
            projects = response.get("data", [])
            logger.info(f"Retrieved {len(projects)} projects for organization {org_id}")
            return projects
        except Exception as e:
            logger.error(f"Error fetching projects for org {org_id}: {e}")
            return []

    @tool
    async def get_project_issues(
            self,
            org_id: str,
            project_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve all issues for a specific project.

        Args:
            org_id (str): Organization ID
            project_id (str): Project ID
            limit (int, optional): Maximum number of issues to retrieve

        Returns:
            list[dict]: List of issue details
        """
        logger.info(f"Fetching issues for project {project_id}...")
        try:
            params = {
                "limit": limit
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/projects/{project_id}/issues",
                params=params
            )
            issues = response.get("data", [])
            logger.info(f"Retrieved {len(issues)} issues for project {project_id}")
            return issues
        except Exception as e:
            logger.error(f"Error fetching issues for project {project_id}: {e}")
            return []

    @tool
    async def get_vulnerabilities(
            self,
            org_id: str,
            limit: int = 100,
            severity: Optional[str] = None
    ) -> list[dict]:
        """
        Retrieve vulnerabilities for an organization.

        Args:
            org_id (str): Organization ID
            limit (int, optional): Maximum number of vulnerabilities to retrieve
            severity (str, optional): Filter by severity (low, medium, high, critical)

        Returns:
            list[dict]: List of vulnerability details
        """
        logger.info(f"Fetching vulnerabilities for organization {org_id}...")
        try:
            params = {
                "limit": limit
            }
            if severity:
                params["severity"] = severity

            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/issues",
                params=params
            )
            vulnerabilities = response.get("data", [])
            logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities for organization {org_id}")
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities for org {org_id}: {e}")
            return []

    @tool
    async def get_licenses(
            self,
            org_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve license issues for an organization.

        Args:
            org_id (str): Organization ID
            limit (int, optional): Maximum number of license issues to retrieve

        Returns:
           list[dict]: List of license issue details
        """
        logger.info(f"Fetching license issues for organization {org_id}...")
        try:
            params = {
                "limit": limit,
                "type": "license"
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/issues",
                params=params
            )
            licenses = response.get("data", [])
            logger.info(f"Retrieved {len(licenses)} license issues for organization {org_id}")
            return licenses
        except Exception as e:
            logger.error(f"Error fetching license issues for org {org_id}: {e}")
            return []

    @tool
    async def get_dependencies(
            self,
            org_id: str,
            project_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve dependencies for a specific project.

        Args:
            org_id (str): Organization ID
            project_id (str, optional): Project ID
            limit (int, optional): Maximum number of dependencies to retrieve

        Returns:
            list[dict]: List of dependency details
        """
        logger.info(f"Fetching dependencies for project {project_id}...")
        try:
            params = {
                "limit": limit
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/projects/{project_id}/dependencies",
                params=params
            )
            dependencies = response.get("data", [])
            logger.info(f"Retrieved {len(dependencies)} dependencies for project {project_id}")
            return dependencies
        except Exception as e:
            logger.error(f"Error fetching dependencies for project {project_id}: {e}")
            return []

    @tool
    async def get_container_images(
            self,
            org_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve container images for an organization.

        Args:
            org_id (str): Organization ID
            limit (int, optional): Maximum number of container images to retrieve

        Returns:
            list[dict]: List of container image details
        """
        logger.info(f"Fetching container images for organization {org_id}...")
        try:
            params = {
                "limit": limit
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/container_images",
                params=params
            )
            container_images = response.get("data", [])
            logger.info(f"Retrieved {len(container_images)} container images for organization {org_id}")
            return container_images
        except Exception as e:
            logger.error(f"Error fetching container images for org {org_id}: {e}")
            return []

    @tool
    async def get_container_image(
            self,
            org_id: str,
            image_id: str
    ) -> dict:
        """
        Retrieve details for a specific container image.

        Args:
            org_id (str): Organization ID
            image_id (str): Container image ID

        Returns:
            dict: Container image details
        """
        logger.info(f"Fetching container image {image_id} for organization {org_id}...")
        try:
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/container_images/{image_id}"
            )
            container_image = response.get("data", {})
            logger.info(f"Retrieved container image {image_id} for organization {org_id}")
            return container_image
        except Exception as e:
            logger.error(f"Error fetching container image {image_id} for org {org_id}: {e}")
            return {}

    @tool
    async def get_container_image_target_refs(
            self,
            org_id: str,
            image_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve target references for a specific container image.

        Args:
            org_id (str): Organization ID
            image_id (str): Container image ID
            limit (int, optional): Maximum number of target references to retrieve

        Returns:
            list[dict]: List of target reference details
        """
        logger.info(f"Fetching target references for container image {image_id} in organization {org_id}...")
        try:
            params = {
                "limit": limit
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/container_images/{image_id}/relationships/image_target_refs",
                params=params
            )
            target_refs = response.get("data", [])
            logger.info(f"Retrieved {len(target_refs)} target references for container image {image_id}")
            return target_refs
        except Exception as e:
            logger.error(f"Error fetching target references for container image {image_id} in org {org_id}: {e}")
            return []

    @tool
    async def update_container_image_target_refs(
            self,
            org_id: str,
            image_id: str,
            target_refs_data: list
    ) -> dict:
        """
        Update target references for a specific container image.

        Args:
            org_id (str): Organization ID
            image_id (str): Container image ID
            target_refs_data (list): Target references data to update

        Returns:
            dict: Update response
        """
        logger.info(f"Updating target references for container image {image_id} in organization {org_id}...")
        try:
            data = {
                "data": target_refs_data
            }
            response = await self._make_request(
                method="PATCH",
                endpoint=f"orgs/{org_id}/container_images/{image_id}/relationships/image_target_refs",
                data=data
            )
            logger.info(f"Updated target references for container image {image_id}")
            return response.get("data", {})
        except Exception as e:
            logger.error(f"Error updating target references for container image {image_id} in org {org_id}: {e}")
            return {}

    @tool
    async def monitor_dep_graph(self, dep_graph_data: dict) -> dict:
        """
        Monitor a dependency graph for vulnerabilities.

        Args:
            dep_graph_data (dict): Dependency graph data to monitor

        Returns:
            dict: Monitoring results
        """
        logger.info("Monitoring dependency graph...")
        try:
            response = await self._make_request(
                method="POST",
                endpoint="monitor/dep-graph",
                data=dep_graph_data
            )
            logger.info("Dependency graph monitoring completed")
            return response.get("data", {})
        except Exception as e:
            logger.error(f"Error monitoring dependency graph: {e}")
            return {}

    @tool
    async def test_project(
            self,
            org_id: str,
            project_id: str
    ) -> dict:
        """
        Test a project for vulnerabilities.

        Args:
            org_id (str): Organization ID
            project_id (str): Project ID

        Returns:
            dict: Test results
        """
        logger.info(f"Testing project {project_id} for vulnerabilities...")
        try:
            response = await self._make_request(
                method="POST",
                endpoint=f"orgs/{org_id}/projects/{project_id}/test"
            )
            logger.info(f"Test completed for project {project_id}")
            return response.get("data", {})
        except Exception as e:
            logger.error(f"Error testing project {project_id}: {e}")
            return {}

    @tool
    async def get_users(
            self,
            org_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve users for an organization.

        Args:
            org_id (str): Organization ID
            limit (int, optional): Maximum number of users to retrieve

        Returns:
            list[dict]: List of user details
        """
        logger.info(f"Fetching users for organization {org_id}...")
        try:
            params = {
                "limit": limit
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/users",
                params=params
            )
            users = response.get("data", [])
            logger.info(f"Retrieved {len(users)} users for organization {org_id}")
            return users
        except Exception as e:
            logger.error(f"Error fetching users for org {org_id}: {e}")
            return []

    @tool
    async def get_integrations(self, org_id: str) -> list[dict]:
        """
        Retrieve integrations for an organization.

        Args:
            org_id (str): Organization ID

        Returns:
            list[dict]: List of integration details
        """
        logger.info(f"Fetching integrations for organization {org_id}...")
        try:
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/integrations"
            )
            integrations = response.get("data", [])
            logger.info(f"Retrieved {len(integrations)} integrations for organization {org_id}")
            return integrations
        except Exception as e:
            logger.error(f"Error fetching integrations for org {org_id}: {e}")
            return []

    @tool
    async def get_targets(
            self,
            org_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve targets for an organization.

        Args:
            org_id (str): Organization ID
            limit (int, optaionl): Maximum number of targets to retrieve

        Returns:
            list[dict]: List of target details
        """
        logger.info(f"Fetching targets for organization {org_id}...")
        try:
            params = {
                "limit": limit
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/targets",
                params=params
            )
            targets = response.get("data", [])
            logger.info(f"Retrieved {len(targets)} targets for organization {org_id}")
            return targets
        except Exception as e:
            logger.error(f"Error fetching targets for org {org_id}: {e}")
            return []

    @tool
    async def get_apps(
            self,
            org_id: str,
            limit: int = 100
    ) -> list[dict]:
        """
        Retrieve apps for an organization.

        Args:
            org_id (str): Organization ID
            limit (int, optional): Maximum number of apps to retrieve

        Returns:
            list[dict]: List of app details
        """
        logger.info(f"Fetching apps for organization {org_id}...")
        try:
            params = {
                "limit": limit
            }
            response = await self._make_request(
                method="GET",
                endpoint=f"orgs/{org_id}/apps",
                params=params
            )
            apps = response.get("data", [])
            logger.info(f"Retrieved {len(apps)} apps for organization {org_id}")
            return apps
        except Exception as e:
            logger.error(f"Error fetching apps for org {org_id}: {e}")
            return []

    @tool
    async def get_vulnerability_details(self, vuln_id: str) -> dict:
        """
        Get detailed information about a specific vulnerability.

        Args:
            vuln_id (str): Vulnerability ID

        Returns:
            dict: Vulnerability details
        """
        logger.info(f"Fetching details for vulnerability {vuln_id}...")
        try:
            response = await self._make_request(
                method="GET",
                endpoint=f"vulnerabilities/{vuln_id}"
            )
            vulnerability = response.get("data", {})
            logger.info(f"Retrieved details for vulnerability {vuln_id}")
            return vulnerability
        except Exception as e:
            logger.error(f"Error fetching vulnerability details for {vuln_id}: {e}")
            return {}

    @tool
    async def monitor_project(
            self,
            org_id: str,
            project_data: dict
    ) -> dict:
        """
        Monitor a project for vulnerabilities.

        Args:
            org_id (str): Organization ID
            project_data (dict): Project data to monitor

        Returns:
            dict: Monitoring results
        """
        logger.info(f"Monitoring project for organization {org_id}...")
        try:
            response = await self._make_request(
                method="POST",
                endpoint=f"orgs/{org_id}/projects",
                data=project_data
            )
            logger.info(f"Project monitoring initiated for organization {org_id}")
            return response.get("data", {})
        except Exception as e:
            logger.error(f"Error monitoring project for org {org_id}: {e}")
            return {}

    @tool
    async def collect_all_container_data(self, org_id: str) -> dict:
        """
        Collect all container-related data for an organization.

        Args:
            org_id (str): Organization ID

        Returns:
            dict: Comprehensive container data collection
        """
        logger.info(f"Starting comprehensive container data collection for organization {org_id}...")

        try:
            # Get container images
            container_images = await self.get_container_images(org_id=org_id)

            # Get detailed data for each container image
            container_details = []
            container_target_refs = []

            for image in container_images:
                image_id = image.get("id")
                if image_id:
                    image_detail = await self.get_container_image(org_id=org_id, image_id=image_id)
                    target_refs = await self.get_container_image_target_refs(org_id=org_id, image_id=image_id)

                    container_details.append(image_detail)
                    container_target_refs.extend(target_refs)

            logger.info(f"Finished comprehensive container data collection for organization {org_id}")

            return {
                'organization_id': org_id,
                'container_images': container_images,
                'container_details': container_details,
                'container_target_refs': container_target_refs,
                'collection_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error during comprehensive container data collection: {e}")
            return {}

    @tool
    async def collect_all_snyk_data(self, org_id: str) -> dict:
        """
        Collect all available Snyk data for a specific organization.

        Args:
            org_id (str): Organization ID

        Returns:
            dict: Comprehensive Snyk data collection
        """
        logger.info(f"Starting comprehensive Snyk data collection for organization {org_id}...")

        try:
            # Get basic organization data
            projects = await self.get_projects(org_id=org_id)
            project_ids = [project.get("id") for project in projects if project.get("id")]

            # Collect data for all projects
            all_issues = []
            all_dependencies = []

            for project_id in project_ids:
                issues = await self.get_project_issues(org_id=org_id, project_id=project_id)
                dependencies = await self.get_dependencies(org_id=org_id, project_id=project_id)
                all_issues.extend(issues)
                all_dependencies.extend(dependencies)

            # Collect other organization-level data
            (
                vulnerabilities,
                licenses,
                users,
                integrations,
                targets,
                apps,
                container_images
            ) = await asyncio.gather(
                self.get_vulnerabilities(org_id),
                self.get_licenses(org_id),
                self.get_users(org_id),
                self.get_integrations(org_id),
                self.get_targets(org_id),
                self.get_apps(org_id),
                self.get_container_images(org_id),
                return_exceptions=True
            )

            # Get detailed container data
            container_data = await self.collect_all_container_data(org_id=org_id)

            logger.info(f"Finished comprehensive Snyk data collection for organization {org_id}")

            return {
                'organization_id': org_id,
                'projects': projects if not isinstance(projects, Exception) else [],
                'issues': all_issues,
                'dependencies': all_dependencies,
                'vulnerabilities': vulnerabilities if not isinstance(vulnerabilities, Exception) else [],
                'licenses': licenses if not isinstance(licenses, Exception) else [],
                'users': users if not isinstance(users, Exception) else [],
                'integrations': integrations if not isinstance(integrations, Exception) else [],
                'targets': targets if not isinstance(targets, Exception) else [],
                'apps': apps if not isinstance(apps, Exception) else [],
                'container_images': container_images if not isinstance(container_images, Exception) else [],
                'container_data': container_data,
                'collection_timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error during comprehensive Snyk data collection: {e}")
            return {}
