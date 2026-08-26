import asyncio
import logging
import os
from typing import Optional

import aiohttp

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class BitbucketHandler(BaseHandler):
    """
    Asynchronous handler for interacting with the Bitbucket Cloud REST API.

    This handler provides tools for accessing Bitbucket account information,
    user email addresses, workspaces, projects, repositories, and pull requests.
    It also exposes issue-related methods that return an unsupported response
    because the Bitbucket Cloud Issue Tracker API is deprecated.

    Authentication:
        OAuth 2.0 Bearer Access Token.

    Args:
        api_base_url (str | None):
            Base URL for the Bitbucket REST API. If not provided, the value is
            read from the ``BITBUCKET_API_BASE_URL`` environment variable.
            Defaults to ``https://api.bitbucket.org/2.0``.
        access_token (str | None):
            OAuth 2.0 Bearer access token. If not provided, the value is read
            from the ``access_token`` environment variable.
        **kwargs:
            Additional keyword arguments passed to ``BaseHandler``.

    Raises:
        ValueError:
            If an access token is not provided through either the constructor
            or the environment variable.

    API Reference:
        https://api.bitbucket.org/2.0
    """

    def __init__(
        self,
        api_base_url: str | None = None,
        access_token: str | None = None,
        **kwargs
    ):
        """
        Initialize the Bitbucket handler and configure authentication.

        Args:
            api_base_url (str | None):
                Base URL for the Bitbucket REST API.
            access_token (str | None):
                OAuth 2.0 Bearer access token used for API authentication.
            **kwargs:
                Additional keyword arguments forwarded to ``BaseHandler``.

        Raises:
            ValueError:
                If no access token is provided.
        """
        super().__init__(**kwargs)

        self.api_base_url = (
            api_base_url
            or os.getenv("BITBUCKET_API_BASE_URL")
            or "https://api.bitbucket.org/2.0"
        ).rstrip("/")

        self.access_token = (
            access_token
            or os.getenv("access_token")
        )

        if not self.access_token:
            raise ValueError(
                "access_token is required. "
                "Pass access_token or set access_token."
            )

        self.access_token = self.access_token.strip()

        self._common_headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
        }

    # ============================================================
    # FETCH ALL PAGES
    # ============================================================

    async def fetch_all_pages(
        self,
        url: str,
        params: Optional[dict] = None
    ) -> list[dict]:
        """
        Fetch and aggregate results from all pages of a Bitbucket API endpoint.

        Bitbucket API responses may include a ``next`` URL when additional
        pages are available. This method follows the pagination links until
        all available results have been retrieved or an error occurs.

        Args:
            url (str):
                The initial Bitbucket API endpoint URL.
            params (Optional[dict]):
                Optional query parameters to include in the initial request.

        Returns:
            list[dict]:
                A combined list containing items retrieved from all available
                pages. Returns the data collected before an error occurs if
                pagination is interrupted.
        """

        all_data = []
        current_url = url
        current_params = params.copy() if params else {}

        async with aiohttp.ClientSession() as session:

            while current_url:

                try:
                    async with session.get(
                        url=current_url,
                        headers=self._common_headers,
                        params=current_params
                    ) as resp:

                        if resp.status >= 400:
                            error_text = await resp.text()

                            logger.error(
                                f"Bitbucket HTTP error: "
                                f"{resp.status} - {error_text}"
                            )
                            break

                        data = await resp.json()

                        if isinstance(data, dict):

                            values = data.get("values", [])

                            if isinstance(values, list):
                                all_data.extend(values)

                            current_url = data.get("next")

                        elif isinstance(data, list):

                            all_data.extend(data)
                            current_url = None

                        else:
                            current_url = None

                        # Bitbucket next URL already contains
                        # pagination parameters.
                        current_params = {}

                except aiohttp.ClientError as e:

                    logger.error(
                        f"Bitbucket client error: {e}"
                    )
                    break

                except Exception as e:

                    logger.error(
                        f"Unexpected pagination error: {e}"
                    )
                    break

        return all_data

    # ============================================================
    # CURRENT USER
    # Scope: account
    # ============================================================

    @tool
    async def user_details(self) -> dict:
        """
        Retrieve details of the currently authenticated Bitbucket user.

        Returns:
            dict:
                The Bitbucket user profile returned by the API. Returns an
                empty dictionary if the request fails.
        """

        url = f"{self.api_base_url}/user"

        async with aiohttp.ClientSession() as session:

            try:

                async with session.get(
                    url=url,
                    headers=self._common_headers
                ) as resp:

                    if resp.status >= 400:

                        error_text = await resp.text()

                        logger.error(
                            f"Error fetching Bitbucket user "
                            f"(HTTP {resp.status}): {error_text}"
                        )

                        return {}

                    return await resp.json()

            except aiohttp.ClientError as e:

                logger.error(
                    f"Network error fetching user: {e}"
                )

            except Exception as e:

                logger.error(
                    f"Unexpected error fetching user: {e}"
                )

        return {}

    # ============================================================
    # USER EMAIL
    # Scope: email
    # ============================================================

    @tool
    async def get_user_email(self) -> dict:
        """
        Retrieve all email addresses associated with the authenticated user.

        The returned result includes each email address along with its primary
        and confirmation status.

        Returns:
            dict:
                A dictionary containing the total number of email addresses
                and a list of normalized email details.
        """

        url = f"{self.api_base_url}/user/emails"

        emails = await self.fetch_all_pages(url)

        return {
            "total_emails": len(emails),
            "emails": [
                {
                    "email": email.get("email"),
                    "is_primary": email.get("is_primary"),
                    "is_confirmed": email.get("is_confirmed")
                }
                for email in emails
            ]
        }

    # ============================================================
    # WORKSPACES
    # Scope: account
    # ============================================================

    @tool
    async def get_workspaces(self) -> dict:
        """
        Retrieve all Bitbucket workspaces accessible to the authenticated user.

        Returns:
            dict:
                A dictionary containing the total number of accessible
                workspaces and their normalized metadata.
        """

        url = f"{self.api_base_url}/user/workspaces"

        workspaces = await self.fetch_all_pages(url)

        return {
            "total_workspaces": len(workspaces),
            "workspaces": [
                {
                    "uuid": workspace.get("workspace", {}).get("uuid"),
                    "name": workspace.get("workspace", {}).get("name"),
                    "slug": workspace.get("workspace", {}).get("slug"),
                    "is_private": workspace.get("workspace", {}).get("is_private"),
                    "display_name": workspace.get("workspace", {}).get("name"),
                    "administrator": workspace.get("administrator")
                }
                for workspace in workspaces
            ]
        }

    # ============================================================
    # PROJECTS
    # Scope: project
    # ============================================================

    @tool
    async def get_projects(
        self,
        workspace: str
    ) -> dict:
        """
        Retrieve all projects within the specified Bitbucket workspace.

        Args:
            workspace (str):
                The workspace slug or identifier.

        Returns:
            dict:
                A dictionary containing the workspace identifier, total project
                count, and a list of normalized project details.

        Raises:
            ValueError:
                If ``workspace`` is not provided.
        """

        if not workspace:
            raise ValueError("workspace is required")

        url = (
            f"{self.api_base_url}/workspaces/"
            f"{workspace}/projects"
        )

        projects = await self.fetch_all_pages(url)

        return {
            "workspace": workspace,
            "total_projects": len(projects),
            "projects": [
                {
                    "uuid": project.get("uuid"),
                    "key": project.get("key"),
                    "name": project.get("name"),
                    "description": project.get("description"),
                    "is_private": project.get("is_private"),
                    "state": project.get("state")
                }
                for project in projects
            ]
        }

    # ============================================================
    # REPOSITORIES
    # Scope: repository
    # ============================================================

    @tool
    async def repository_summary(
        self,
        workspace: str,
        project_key: Optional[str] = None
    ) -> dict:
        """
        Retrieve repositories from a Bitbucket workspace.

        When ``project_key`` is provided, repositories associated with the
        specified project are requested. Otherwise, repositories available in
        the workspace are retrieved.

        Args:
            workspace (str):
                The workspace slug or identifier.
            project_key (Optional[str]):
                Optional Bitbucket project key used to filter repositories.

        Returns:
            dict:
                A dictionary containing the workspace, project key, repository
                count, and normalized repository metadata.

        Raises:
            ValueError:
                If ``workspace`` is not provided.
        """

        if not workspace:
            raise ValueError("workspace is required")

        if project_key:

            url = (
                f"{self.api_base_url}/repositories/"
                f"{workspace}/{project_key}"
            )

        else:

            url = (
                f"{self.api_base_url}/repositories/"
                f"{workspace}"
            )

        repositories = await self.fetch_all_pages(url)

        result = []

        for repo in repositories:

            project = repo.get("project") or {}
            main_branch = repo.get("mainbranch") or {}

            result.append({
                "uuid": repo.get("uuid"),
                "name": repo.get("name"),
                "slug": repo.get("slug"),
                "full_name": repo.get("full_name"),
                "description": repo.get("description"),
                "is_private": repo.get("is_private"),
                "scm": repo.get("scm"),
                "project_key": project.get("key"),
                "project_name": project.get("name"),
                "main_branch": main_branch.get("name"),
                "created_on": repo.get("created_on"),
                "updated_on": repo.get("updated_on"),
                "url": (
                    repo.get("links") or {}
                ).get("html", {}).get("href")
            })

        return {
            "workspace": workspace,
            "project_key": project_key,
            "total_repositories": len(result),
            "repositories": result
        }

    # ============================================================
    # SINGLE REPOSITORY
    # Scope: repository
    # ============================================================

    @tool
    async def get_repository(
        self,
        workspace: str,
        repository_name: str
    ) -> dict:
        """
        Retrieve detailed information for a specific Bitbucket repository.

        Args:
            workspace (str):
                The workspace containing the repository.
            repository_name (str):
                The repository name or slug.

        Returns:
            dict:
                Repository details returned directly by the Bitbucket API.
                Returns an empty dictionary if the request fails.

        Raises:
            ValueError:
                If ``workspace`` or ``repository_name`` is not provided.
        """

        if not workspace:
            raise ValueError("workspace is required")

        if not repository_name:
            raise ValueError(
                "repository_name is required"
            )

        url = (
            f"{self.api_base_url}/repositories/"
            f"{workspace}/{repository_name}"
        )

        async with aiohttp.ClientSession() as session:

            try:

                async with session.get(
                    url=url,
                    headers=self._common_headers
                ) as resp:

                    if resp.status >= 400:

                        error_text = await resp.text()

                        logger.error(
                            f"Error fetching repository "
                            f"(HTTP {resp.status}): {error_text}"
                        )

                        return {}

                    return await resp.json()

            except aiohttp.ClientError as e:

                logger.error(
                    f"Network error fetching repository: {e}"
                )

            except Exception as e:

                logger.error(
                    f"Unexpected error fetching repository: {e}"
                )

        return {}

    # ============================================================
    # PULL REQUESTS
    # Scope: pullrequest
    # ============================================================

    @tool
    async def pull_requests(
        self,
        workspace: str,
        repository_name: str,
        state: Optional[str] = None
    ) -> dict:
        """
        Retrieve pull requests from a Bitbucket repository.

        Args:
            workspace (str):
                The workspace containing the repository.
            repository_name (str):
                The repository name or slug.
            state (Optional[str]):
                Optional pull request state used to filter results. Supported
                values include ``OPEN``, ``MERGED``, ``DECLINED``, and
                ``SUPERSEDED``.

        Returns:
            dict:
                A dictionary containing repository information, the requested
                state filter, total pull request count, and normalized pull
                request details.

        Raises:
            ValueError:
                If ``workspace`` or ``repository_name`` is not provided.
        """

        if not workspace:
            raise ValueError("workspace is required")

        if not repository_name:
            raise ValueError(
                "repository_name is required"
            )

        url = (
            f"{self.api_base_url}/repositories/"
            f"{workspace}/{repository_name}/pullrequests"
        )

        params = {}

        if state:
            params["state"] = state

        pull_requests = await self.fetch_all_pages(
            url=url,
            params=params
        )

        result = []

        for pr in pull_requests:

            author = pr.get("author") or {}
            source = pr.get("source") or {}
            destination = pr.get("destination") or {}

            result.append({
                "id": pr.get("id"),
                "title": pr.get("title"),
                "description": pr.get("description"),
                "state": pr.get("state"),
                "author": author.get("display_name"),
                "source_branch": (
                    source.get("branch") or {}
                ).get("name"),
                "destination_branch": (
                    destination.get("branch") or {}
                ).get("name"),
                "created_on": pr.get("created_on"),
                "updated_on": pr.get("updated_on"),
                "url": (
                    pr.get("links") or {}
                ).get("html", {}).get("href")
            })

        return {
            "workspace": workspace,
            "repository": repository_name,
            "state": state or "ALL",
            "total_pull_requests": len(result),
            "pull_requests": result
        }

    # ============================================================
    # CREATE PULL REQUEST
    # Scope: pullrequest:write
    # ============================================================

    @tool
    async def create_pull_request(
        self,
        workspace: str,
        repository_name: str,
        title: str,
        source_branch: str,
        destination_branch: str,
        description: Optional[str] = None
    ) -> dict:
        """
        Create a new pull request in a Bitbucket repository.

        Args:
            workspace (str):
                The workspace containing the repository.
            repository_name (str):
                The repository name or slug.
            title (str):
                Title of the pull request.
            source_branch (str):
                Name of the branch containing the proposed changes.
            destination_branch (str):
                Name of the branch into which the changes will be merged.
            description (Optional[str]):
                Optional description for the pull request.

        Returns:
            dict:
                A dictionary containing the creation status and the Bitbucket
                pull request response. If the request fails, an error response
                containing status information is returned.

        Raises:
            ValueError:
                If any required parameter is not provided.
        """

        if not workspace:
            raise ValueError("workspace is required")

        if not repository_name:
            raise ValueError(
                "repository_name is required"
            )

        if not title:
            raise ValueError("title is required")

        if not source_branch:
            raise ValueError(
                "source_branch is required"
            )

        if not destination_branch:
            raise ValueError(
                "destination_branch is required"
            )

        url = (
            f"{self.api_base_url}/repositories/"
            f"{workspace}/{repository_name}/pullrequests"
        )

        payload = {
            "title": title,
            "description": description or "",
            "source": {
                "branch": {
                    "name": source_branch
                }
            },
            "destination": {
                "branch": {
                    "name": destination_branch
                }
            }
        }

        headers = self._common_headers.copy()
        headers["Content-Type"] = "application/json"

        async with aiohttp.ClientSession() as session:

            try:

                async with session.post(
                    url=url,
                    headers=headers,
                    json=payload
                ) as resp:

                    response_data = await resp.json()

                    if resp.status >= 400:

                        logger.error(
                            f"Error creating pull request "
                            f"(HTTP {resp.status}): "
                            f"{response_data}"
                        )

                        return {
                            "status": "error",
                            "status_code": resp.status,
                            "details": response_data
                        }

                    return {
                        "status": "created",
                        "pull_request": response_data
                    }

            except aiohttp.ClientError as e:

                logger.error(
                    f"Network error creating pull request: {e}"
                )

                return {
                    "status": "error",
                    "message": str(e)
                }

    # ============================================================
    # ISSUES
    # Scope: issue
    # ============================================================

    @tool
    async def issues(
            self,
            workspace: str,
            repository_name: str,
            state: Optional[str] = None
    ) -> dict:
        """
        Return an unsupported response for Bitbucket Cloud issue retrieval.

        Bitbucket Cloud's Issue Tracker API is deprecated and is no longer
        available for repositories using the current API.

        Args:
            workspace (str):
                The workspace containing the repository.
            repository_name (str):
                The repository name or slug.
            state (Optional[str]):
                Optional issue state filter retained for interface consistency.

        Returns:
            dict:
                A dictionary indicating that issue retrieval is unsupported.

        Raises:
            ValueError:
                If ``workspace`` or ``repository_name`` is not provided.
        """

        if not workspace:
            raise ValueError("workspace is required")

        if not repository_name:
            raise ValueError("repository_name is required")

        return {
            "status": "unsupported",
            "workspace": workspace,
            "repository": repository_name,
            "state": state or "ALL",
            "message": (
                "Bitbucket Cloud Issue Tracker API is deprecated "
                "and is no longer available for this repository."
            )
        }

    # ============================================================
    # CREATE ISSUE
    # Scope: issue:write
    # ============================================================

    @tool
    async def create_issue(
            self,
            workspace: str,
            repository_name: str,
            title: str,
            content: Optional[str] = None
    ) -> dict:
        """
        Return an unsupported response for Bitbucket Cloud issue creation.

        Bitbucket Cloud's Issue Tracker API is deprecated, so new issues can
        no longer be created through this handler.

        Args:
            workspace (str):
                The workspace containing the repository.
            repository_name (str):
                The repository name or slug.
            title (str):
                Title of the issue to create.
            content (Optional[str]):
                Optional issue content or description.

        Returns:
            dict:
                A dictionary indicating that issue creation is unsupported.

        Raises:
            ValueError:
                If ``workspace``, ``repository_name``, or ``title`` is not
                provided.
        """

        if not workspace:
            raise ValueError("workspace is required")

        if not repository_name:
            raise ValueError("repository_name is required")

        if not title:
            raise ValueError("title is required")

        return {
            "status": "unsupported",
            "workspace": workspace,
            "repository": repository_name,
            "title": title,
            "message": (
                "Bitbucket Cloud Issue Tracker API is deprecated "
                "and issue creation is no longer available."
            )
        }

    # ============================================================
    # UPDATE ISSUE
    # Scope: issue:write
    # ============================================================

    @tool
    async def update_issue(
            self,
            workspace: str,
            repository_name: str,
            issue_id: int,
            title: Optional[str] = None,
            content: Optional[str] = None,
            state: Optional[str] = None
    ) -> dict:
        """
        Return an unsupported response for Bitbucket Cloud issue updates.

        Bitbucket Cloud's Issue Tracker API is deprecated, so existing issues
        can no longer be updated through this handler.

        Args:
            workspace (str):
                The workspace containing the repository.
            repository_name (str):
                The repository name or slug.
            issue_id (int):
                Identifier of the issue to update.
            title (Optional[str]):
                Optional updated issue title.
            content (Optional[str]):
                Optional updated issue content or description.
            state (Optional[str]):
                Optional updated issue state.

        Returns:
            dict:
                A dictionary indicating that issue updates are unsupported.

        Raises:
            ValueError:
                If ``workspace``, ``repository_name``, or ``issue_id`` is not
                provided, or if no update field is specified.
        """

        if not workspace:
            raise ValueError("workspace is required")

        if not repository_name:
            raise ValueError("repository_name is required")

        if issue_id is None:
            raise ValueError("issue_id is required")

        if (
                title is None
                and content is None
                and state is None
        ):
            raise ValueError(
                "At least one field is required"
            )

        return {
            "status": "unsupported",
            "workspace": workspace,
            "repository": repository_name,
            "issue_id": issue_id,
            "message": (
                "Bitbucket Cloud Issue Tracker API is deprecated "
                "and issue updates are no longer available."
            )
        }
