import logging
import os
from datetime import datetime
from typing import Optional

import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class GitHubHandler(BaseHandler):
    """
    A handler to collect GitHub GRC (Governance, Risk, and Compliance) evidence,
    focusing on MFA, organizational details, and repository data,
    and various GitHub Actions related data.
    """

    def __init__(
            self,
            api_base_url: str | None = None,
            github_token: str | None = None
    ):
        super().__init__()
        self.api_base_url = api_base_url or os.getenv('GITHUB_API_BASE_URL') or "https://api.github.com"
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self._common_headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    @tool
    async def fetch_all_pages(
            self,
            url: str,
            headers: dict,
            params: Optional[dict] = None
    ) -> list[dict]:
        """
        Fetches all pages from a paginated GitHub API endpoint.

        Args:
            url (str): Initial API endpoint URL.
            headers (dict): HTTP headers for the request.
            params (dict, optional): Query parameters.

        Returns:
            list: A list of dictionaries representing paginated API response items.
        """
        all_data: list[dict] = []
        current_url = url
        current_params = params.copy() if params is not None else {}

        page_data_keys = [
            "items", "workflow_runs", "jobs", "artifacts", "secrets", "repositories",
            "pull_requests", "branches", "caches", "runners", "runner_groups",
            "variables", "workflows", "collaborators"
        ]
        async with aiohttp.ClientSession() as session:
            while current_url:
                try:
                    async with session.get(
                            url=current_url,
                            headers=headers,
                            params=current_params
                    ) as resp:
                        resp.raise_for_status()
                        page_data = await resp.json()

                        if isinstance(page_data, list):
                            all_data.extend(page_data)
                        elif isinstance(page_data, dict):
                            found_list = False
                            for key in page_data_keys:
                                if key in page_data and isinstance(page_data[key], list):
                                    all_data.extend(page_data[key])
                                    found_list = True
                                    break
                            if not found_list and page_data:
                                all_data.append(page_data)
                        next_url = None
                        if 'link' in resp.headers:
                            links = resp.headers['link'].split(',')
                            for link in links:
                                if 'rel="next"' in link:
                                    next_url = link.split(';')[0].strip('<>').strip()
                                    break
                        current_url = next_url
                        current_params = {}

                except aiohttp.ClientResponseError as e:
                    logger.error(f"HTTP error fetching pages from {current_url}: {e.status} - {e.message}")
                    break
                except aiohttp.ClientError as e:
                    logger.error(f"Network or client error fetching pages from {current_url}: {e}")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error fetching pages from {current_url}: {e}")
                    break
        return all_data

    @tool
    async def organization_details(
            self,
            org_name: Optional[str] = None
    ) -> dict:
        """
        Retrieves details for a specific GitHub organization, or all organizations associated with the
         authenticated user if no org_name is provided. Requires 'read:org' scope.

        Args:
            org_name (str, optional): Name of the GitHub organization.

        Returns:
            dict: A dictionary with organization details (e.g., `login`, `id`, `name`) if `org_name` given otherwise
            a dictionary with `organizations` (list of org details) and `total_organizations_found` (int).
        """
        headers = self._common_headers
        async with aiohttp.ClientSession() as session:
            try:
                if org_name:
                    org_url = f"{self.api_base_url}/orgs/{org_name}"
                    logger.info(f"Fetching details for organization: {org_name}")
                    async with session.get(
                            url=org_url,
                            headers=headers
                    ) as resp:
                        resp.raise_for_status()
                        return await resp.json()
                else:
                    logger.info("Fetching details for all organizations associated with the authenticated user.")
                    orgs = await self.fetch_all_pages(
                        url=f"{self.api_base_url}/user/orgs",
                        headers=headers
                    )
                    all_org_details = [
                        await self.organization_details(org_name=org_data.get("login"))
                        for org_data in orgs
                    ]
                    return {
                        "organizations": all_org_details,
                        "total_organizations_found": len(all_org_details)
                    }
            except aiohttp.ClientResponseError as e:
                logger.error(f"Error fetching organization details (HTTP {e.status}): {e.message}")
            except aiohttp.ClientError as e:
                logger.error(f"Network or client error fetching organization details: {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching organization details: {e}")
            return {}

    @tool
    async def user_details(
            self,
            username: Optional[str] = None
    ) -> dict:
        """
        Retrieves profile information for a GitHub user.

        Args:
            username (str, optional): The GitHub username. If not provided by the user, it will default to `None`,
            and the function will attempt to fetch details for the currently authenticated user (if applicable) or
             indicate that a username is required.

        Returns:
            dict: A dictionary with user details (e.g., `login`, `id`, `name`).
        """
        headers = self._common_headers
        user_url = f"{self.api_base_url}/users/{username}" if username else f"{self.api_base_url}/user"
        async with aiohttp.ClientSession() as session:
            try:
                logger.info(f"Fetching user details for: {username if username else 'authenticated user'}")
                async with session.get(
                        url=user_url,
                        headers=headers
                ) as resp:
                    resp.raise_for_status()
                    return await resp.json()
            except aiohttp.ClientResponseError as e:
                logger.error(f"Error fetching user details (HTTP {e.status}): {e.message}")
            except aiohttp.ClientError as e:
                logger.error(f"Network or client error fetching user details: {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching user details: {e}")
            return {}

    async def single_mfa_evidence_internal(
            self,
            org_name: str,
            common_headers: dict
    ) -> dict:
        evidence = {
            "organization": org_name,
            "timestamp": datetime.now().isoformat(),
            "organization_details": {},
            "total_members": 0,
            "mfa_enforcement_detected": False,
            "members_with_mfa_enabled": [],
            "members_with_mfa_disabled": [],
            "all_members_details": [],
            "errors": []
        }
        logger.info(f"Collecting MFA evidence for organization: {org_name}")

        try:
            evidence["organization_details"] = await self.organization_details(org_name=org_name)

            disabled_members_basic = await self.fetch_all_pages(
                url=f"{self.api_base_url}/orgs/{org_name}/members?filter=2fa_disabled",
                headers=common_headers
            )
            if disabled_members_basic:
                evidence["mfa_enforcement_detected"] = True
                evidence["members_with_mfa_disabled"].extend(
                    [
                        {
                            "login": m["login"],
                            "id": m["id"]
                        }
                        for m in disabled_members_basic
                    ]
                )
                logger.info(f"{len(disabled_members_basic)} members with 2FA disabled in {org_name}.")

            all_members_basic = await self.fetch_all_pages(
                url=f"{self.api_base_url}/orgs/{org_name}/members",
                headers=common_headers
            )
            _total_members = len(all_members_basic)
            evidence["total_members"] = _total_members
            logger.info(f"Found {_total_members} total members in {org_name}.")

            disabled_logins = {
                member.get("login") for member in evidence["members_with_mfa_disabled"]
            }

            for member_basic in all_members_basic:
                user_detail = await self.user_details(username=member_basic["login"])
                detailed_info = {
                    "login": member_basic["login"],
                    "id": member_basic["id"],
                    "mfa_enabled": member_basic["login"] not in disabled_logins,
                    "name": user_detail.get("name"),
                    "type": user_detail.get("type"),
                    "company": user_detail.get("company"),
                    "email": user_detail.get("email"),
                    "created_at": user_detail.get("created_at"),
                    "updated_at": user_detail.get("updated_at"),
                    "public_repos": user_detail.get("public_repos"),
                    "followers": user_detail.get("followers"),
                }
                if detailed_info["mfa_enabled"]:
                    evidence["members_with_mfa_enabled"].append(
                        {
                            "login": member_basic["login"],
                            "id": member_basic["id"]  # Corrected from 'member["id"]'
                        }
                    )
                evidence["all_members_details"].append(detailed_info)
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error processing organization '{org_name}': {e.status} - {e.message}")
        except aiohttp.ClientError as e:
            logger.error(f"Network or client error processing organization '{org_name}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error processing organization '{org_name}': {e}")
        return evidence

    @tool
    async def mfa_evidence(
            self,
            org_name: Optional[str] = None
    ) -> dict:
        """
        Collects MFA compliance evidence and organizational details.

        Args:
            org_name (str, optional): Name of the GitHub organization.

        Returns:
            dict: A dictionary with MFA evidence for all accessible organizations or given organization.
        """
        headers = self._common_headers

        if org_name:
            return await self.single_mfa_evidence_internal(org_name, headers)
        else:
            logger.info("Collecting MFA evidence for all organizations.")
            all_orgs_response = await self.organization_details()
            if not all_orgs_response:
                return {}
            organizations_list = all_orgs_response.get("organizations", [])
            all_evidence = {
                "timestamp": datetime.now().isoformat(),
                "total_organizations_processed": len(organizations_list),
                "organizations_mfa_evidence": [],
                "errors": []
            }
            for org_detail in organizations_list:
                current_org_name = org_detail.get("login")
                if current_org_name:
                    org_evidence = await self.single_mfa_evidence_internal(current_org_name, headers)
                    all_evidence["organizations_mfa_evidence"].append(org_evidence)
            return all_evidence

    @staticmethod
    async def process_repositories_internal(
            repos: list[dict],
            source_type: str,
            source_name: str,
            processed_repo: set
    ) -> list:
        repos_summary = []
        for repo_data in repos:
            full_name = repo_data.get("full_name")
            if full_name and full_name not in processed_repo:
                status = "Public" if not repo_data.get("private") else "Private"
                if repo_data.get("archived"):
                    status = f"Archived ({status})"
                repos_summary.append({
                    "name": repo_data.get("name"), "full_name": full_name,
                    "status": status, "owner_type": source_type, "owner_name": source_name
                })
                processed_repo.add(full_name)
        return repos_summary

    @tool
    async def repository_summary(
            self,
            entity_name: Optional[str] = None
    ) -> dict:
        """
        Retrieves a summary of repositories for a specific user or organization.

        Args:
            entity_name (str, optional): GitHub username or organization name.

        Returns:
            dict: A dictionary with `total_repositories_found` (int), `repositories`
             (list of dicts with `name`, `status`, `owner_type`, `owner_name`).
        """
        headers = self._common_headers
        all_repos_summary: list[dict] = []
        processed_repo_full_names = set()
        try:
            if entity_name:
                logger.info(f"Fetching repository summary for entity: {entity_name}")
                user_details = await self.user_details(username=entity_name)
                if user_details and user_details.get("type") == "User":
                    logger.info(f"Entity '{entity_name}' identified as a user. Fetching user repositories.")
                    user_repos = await self.fetch_all_pages(
                        url=f"{self.api_base_url}/users/{entity_name}/repos",
                        headers=headers
                    )
                    all_repos_summary.extend(
                        await self.process_repositories_internal(
                            repos=user_repos,
                            source_type="User",
                            source_name=entity_name,
                            processed_repo=processed_repo_full_names
                        )
                    )
                else:
                    org_details = await self.organization_details(org_name=entity_name)
                    if org_details and org_details.get("type") == "Organization":
                        logger.info(
                            f"Entity '{entity_name}' identified as an organization. Fetching organization repositories."
                        )
                        org_repos = await self.fetch_all_pages(
                            url=f"{self.api_base_url}/orgs/{entity_name}/repos",
                            headers=headers
                        )
                        all_repos_summary.extend(
                            await self.process_repositories_internal(
                                repos=org_repos,
                                source_type="Organization",
                                source_name=entity_name,
                                processed_repo=processed_repo_full_names
                            )
                        )
                    else:
                        logger.warning(f"Entity '{entity_name}' not found as a user or organization.")
            else:
                logger.info("Fetching repository summary for the authenticated user and their organizations.")
                auth_user_details = await self.user_details()
                if auth_user_details:
                    auth_username = auth_user_details.get("login")
                    if auth_username:
                        logger.info(f"Fetching authenticated user's repositories: {auth_username}")
                        user_repos = await self.fetch_all_pages(
                            url=f"{self.api_base_url}/user/repos",
                            headers=headers
                        )
                        all_repos_summary.extend(
                            await self.process_repositories_internal(
                                repos=user_repos,
                                source_type="Authenticated User",
                                source_name=auth_username,
                                processed_repo=processed_repo_full_names
                            )
                        )
                    else:
                        logger.error("Could not retrieve login for authenticated user.")
                else:
                    logger.error(f"Error fetching authenticated user details: {auth_user_details['error']}")

                all_orgs_response = await self.organization_details()
                if all_orgs_response:
                    for org_data in all_orgs_response.get("organizations", []):
                        org_name_from_list = org_data.get("login")
                        if org_name_from_list:
                            logger.info(f"Fetching repositories for organization: {org_name_from_list}")
                            org_repos = await self.fetch_all_pages(
                                url=f"{self.api_base_url}/orgs/{org_name_from_list}/repos",
                                headers=headers
                            )
                            all_repos_summary.extend(
                                await self.process_repositories_internal(
                                    repos=org_repos,
                                    source_type="Organization",
                                    source_name=org_name_from_list,
                                    processed_repo=processed_repo_full_names
                                )
                            )
                        else:
                            logger.warning(f"Skipping organization entry with missing login: {org_data}")
                else:
                    logger.error(f"Error fetching organizations for authenticated user: {all_orgs_response['error']}")
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error during repository fetching: {e.status} - {e.message}")
        except aiohttp.ClientError as e:
            logger.error(f"Network or client error during repository fetching: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during repository fetching: {e}")

        return {
            "total_repositories_found": len(all_repos_summary),
            "repositories": all_repos_summary,
        }

    @tool
    async def list_organization_members(
            self,
            org_name: Optional[str] = None,
            role: Optional[str] = None,
            filter_2fa: bool = False
    ) -> dict:
        """
        Retrieves a list of members for a given GitHub organization(s).

        Args:
            org_name (str, optional): Name of the GitHub organization.
            role (str, optional): Filters members by role ('all', 'admin', 'member').
            filter_2fa (bool, optional): If True, returns only members with 2FA disabled.

        Returns:
            dict: A dictionary where keys are organization names and values contain `members.
        """
        headers = self._common_headers
        all_organization_members: dict[str, dict] = {}
        orgs_to_process: list[dict] = []

        if org_name:
            logger.info(f"Listing members for organization: {org_name}")
            org_details_response = await self.organization_details(org_name=org_name)
            if not org_details_response:
                return org_details_response
            orgs_to_process.append(org_details_response)
        else:
            logger.info("Listing members for all organizations accessible by the authenticated user.")
            orgs_response = await self.organization_details()
            if not orgs_response:
                return orgs_response
            orgs_to_process = orgs_response.get("organizations", [])

        _roles = [
            'all',
            'admin',
            'member'
        ]
        for org_data in orgs_to_process:
            current_org_name = org_data.get("login")
            if not current_org_name:
                logger.warning(f"Skipping organization entry with missing login: {org_data}")
                continue

            members_url = f"{self.api_base_url}/orgs/{current_org_name}/members"
            params = {}
            if role:
                if role not in _roles:
                    continue
                params['role'] = role

            try:
                members_full_data = await self.fetch_all_pages(
                    url=members_url,
                    headers=headers,
                    params=params
                )

                if filter_2fa:
                    members_to_process = [
                        member for member in members_full_data
                        if 'two_factor_authentication_enabled' in member and not member[
                            'two_factor_authentication_enabled']
                    ]
                    logger.info(
                        f"Filtered for 2FA disabled members in {current_org_name}: {len(members_to_process)} found."
                    )
                else:
                    members_to_process = members_full_data
                    logger.info(f"Found {len(members_to_process)} total members in {current_org_name}.")

                filtered_members = [
                    {
                        "member_id": member.get("id"),
                        "name": member.get("login")
                    }
                    for member in members_to_process
                ]

                all_organization_members[current_org_name] = {
                    "members": filtered_members,
                    "count": len(filtered_members)
                }

            except aiohttp.ClientResponseError as e:
                logger.error(f"HTTP error fetching members for {current_org_name}: {e.status} - {e.message}")
            except aiohttp.ClientError as e:
                logger.error(f"Network or client error fetching members for {current_org_name}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching members for {current_org_name}: {e}")

        return all_organization_members

    async def fetch_repo_branches_internal(
            self,
            owner: str,
            repo: str
    ) -> dict:
        headers = self._common_headers
        logger.info(f"Fetching branches for repository: {owner}/{repo}")
        try:
            branches_data = await self.fetch_all_pages(
                url=f"{self.api_base_url}/repos/{owner}/{repo}/branches",
                headers=headers
            )
            simplified_branches = [{
                "name": b["name"],
                "commit_sha": b["commit"]["sha"]
            } for b in branches_data]
            return {
                "owner": owner, "repository": repo,
                "total_branches": len(simplified_branches),
                "branches": simplified_branches, "errors": []
            }
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error fetching branches for {owner}/{repo}: {e.status} - {e.message}")
        except aiohttp.ClientError as e:
            logger.error(f"Network or client error fetching branches for {owner}/{repo}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching branches for {owner}/{repo}: {e}")

        return {
            "owner": owner,
            "repository": repo,
            "total_branches": 0,
            "branches": [],
        }

    @tool
    async def repository_branches(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ) -> dict:
        """
        Retrieves a list of branches for a specified GitHub repository.

        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.

        Returns:
            dict: A dictionary with `owner`, `repository`, `total_branches`, `branches` (list of dicts with `name`,
            `commit_sha`)
        """
        if username and repository_name:
            return await self.fetch_repo_branches_internal(
                owner=username,
                repo=repository_name
            )
        else:
            logger.info("Fetching branches for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            repositories_list = all_repos_summary_response.get("repositories", [])
            all_repositories_branches_data = []
            total_branches_found_overall = 0

            for repo_summary in repositories_list:
                owner_name = repo_summary.get("owner_name")
                repo_name = repo_summary.get("name")
                if owner_name and repo_name:
                    branch_result = await self.fetch_repo_branches_internal(
                        owner=owner_name,
                        repo=repo_name
                    )
                    all_repositories_branches_data.append(branch_result)
                    total_branches_found_overall += branch_result["total_branches"]
                else:
                    logger.warning(f"Skipping repository entry with missing owner or name: {repo_summary}")

            return {
                "total_repositories_processed": len(repositories_list),
                "total_branches_found_overall": total_branches_found_overall,
                "repositories_branches": all_repositories_branches_data,
            }

    async def single_branch_protection_internal(
            self,
            owner: str,
            repository: str,
            branch: str
    ) -> dict:
        headers = self._common_headers
        logger.info(f"Fetching branch protection for {owner}/{repository}/{branch}")
        async with aiohttp.ClientSession() as session:
            try:
                protection_url = f"{self.api_base_url}/repos/{owner}/{repository}/branches/{branch}/protection"
                async with session.get(
                        url=protection_url,
                        headers=headers
                ) as resp:
                    resp.raise_for_status()
                    return {
                        "branch": branch,
                        "protection_enabled": True,
                        "protection_details": await resp.json(),
                    }
            except aiohttp.ClientResponseError as e:
                logger.error(f"HTTP error fetching branch protection for "
                             f"{owner}/{repository}/{branch}: {e.status} - {e.message}")
            except aiohttp.ClientError as e:
                logger.error(f"Network or client error fetching branch protection for "
                             f"{owner}/{repository}/{branch}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching branch protection for "
                             f"{owner}/{repository}/{branch}: {e}")
            return {
                "branch": branch, "protection_enabled": False, "protection_details": None,
            }

    @tool
    async def branch_protection(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None,
            branch_name: Optional[str] = None
    ) -> dict:
        """
        Retrieves branch protection rules for a specific branch in a repository, for all branches in a specific
         repository, or for all branches across all accessible repositories for the authenticated user.

        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
            branch_name (str, optional): Specific branch name.

        Returns:
            dict: A dictionary with `timestamp`, `total_repositories_processed`, `total_branches_processed`,
            `repositories_with_branch_protection` (list of dicts with `owner`, `repository`, `branches_protection`
            (list of dicts for each branch))
        """
        all_protection_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_branches_processed": 0,
            "repositories_with_branch_protection": [],
            "overall_errors": []
        }

        repositories_to_process: list[dict] = []
        if username and repository_name:
            logger.info(f"Fetching branch protection for specific repository: {username}/{repository_name}")
            repositories_to_process.append({
                "owner_name": username,
                "name": repository_name
            })
            all_protection_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching branch protection for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_protection_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                logger.warning(f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            current_repo_entry = {
                "owner": owner_name,
                "repository": repo_name,
                "branches_protection": [],
                "repository_errors": []
            }

            if branch_name and owner_name == username and repo_name == repository_name:
                logger.info(f"Fetching protection for specific branch: {branch_name} in {owner_name}/{repo_name}")
                branches_list = [{"name": branch_name}]
            else:
                logger.info(f"Fetching all branches for {owner_name}/{repo_name} to check protection.")
                branches_response = await self.repository_branches(owner_name, repo_name)
                branches_list = branches_response.get("branches", [])

            for branch_info in branches_list:
                current_branch_name = branch_info.get("name")
                if current_branch_name:
                    protection_result = await self.single_branch_protection_internal(
                        owner=owner_name,
                        repository=repo_name,
                        branch=current_branch_name
                    )
                    current_repo_entry["branches_protection"].append(protection_result)
                    all_protection_data["total_branches_processed"] += 1
                else:
                    logger.warning(f"Skipping branch with missing name in {owner_name}/{repo_name}: {branch_info}")

            all_protection_data["repositories_with_branch_protection"].append(current_repo_entry)

        return all_protection_data

    async def _fetch_pull_requests_for_repo(
            self,
            owner: str,
            repo: str,
            pr_state: str
    ) -> dict:
        headers = self._common_headers
        logger.info(f"Fetching {pr_state} pull requests for repository: {owner}/{repo}")
        try:
            pulls_url = f"{self.api_base_url}/repos/{owner}/{repo}/pulls"
            params = {
                "state": pr_state
            }
            pulls_data = await self.fetch_all_pages(
                url=pulls_url,
                headers=headers,
                params=params
            )

            simplified_pulls = [
                {
                    "id": pr.get("id"),
                    "number": pr.get("number"),
                    "title": pr.get("title"),
                    "state": pr.get("state"),
                    "user_login": pr.get("user", {}).get("login"),
                    "created_at": pr.get("created_at"),
                    "html_url": pr.get("html_url")
                }
                for pr in pulls_data
            ]
            return {
                "owner": owner,
                "repository": repo,
                "state_requested": pr_state,
                "total_pull_requests": len(simplified_pulls),
                "pull_requests": simplified_pulls
            }
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error fetching pull requests for {owner}/{repo}: {e.status} - {e.message}")
        except aiohttp.ClientError as e:
            logger.error(f"Network or client error fetching pull requests for {owner}/{repo}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching pull requests for {owner}/{repo}: {e}")

        return {
            "owner": owner,
            "repository": repo,
            "state_requested": pr_state,
            "total_pull_requests": 0,
            "pull_requests": []
        }

    @tool
    async def pull_requests(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None,
            state: str = "all"
    ) -> dict:
        """
        Retrieves a list of pull requests for a specified GitHub repository.

        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
            state (str, optional): State of pull requests ('open', 'closed', 'all').

        Returns:
            dict: A dictionary with `owner`, `repository`, `state_requested`, `total_pull_requests`, `pull_requests`
                (list of dicts)
        """
        all_prs_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_pull_requests_found_overall": 0,
            "repositories_pull_requests": [],
            "overall_errors": []
        }

        repositories_to_process: list[dict] = []
        if username and repository_name:
            logger.info(f"Fetching pull requests for specific repository: {username}/{repository_name}")
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_prs_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching pull requests for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_prs_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                logger.warning(f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            pr_result = await self._fetch_pull_requests_for_repo(
                owner=owner_name,
                repo=repo_name,
                pr_state=state
            )
            all_prs_data["repositories_pull_requests"].append(pr_result)
            all_prs_data["total_pull_requests_found_overall"] += pr_result["total_pull_requests"]
        return all_prs_data

    async def _fetch_dependabot_alerts_for_repo(
            self,
            owner: str,
            repo: str,
            alert_state: str
    ) -> dict:
        headers = self._common_headers
        logger.info(f"Fetching Dependabot alerts for {owner}/{repo} with state: {alert_state}")
        try:
            alerts_url = f"{self.api_base_url}/repos/{owner}/{repo}/dependabot/alerts"
            params = {
                "state": alert_state
            }
            alerts_data = await self.fetch_all_pages(
                url=alerts_url,
                headers=headers,
                params=params
            )

            simplified_alerts = [
                {
                    "id": alert.get("number"),
                    "security_vulnerability_package_name": alert.get(
                        "security_vulnerability", {}
                    ).get("package", {}).get("name"),
                    "severity": alert.get("security_vulnerability", {}).get("severity"),
                    "state": alert.get("state"),
                    "created_at": alert.get("created_at"),
                    "updated_at": alert.get("updated_at"),
                    "dismissed_at": alert.get("dismissed_at"),
                    "url": alert.get("html_url")
                }
                for alert in alerts_data
            ]
            return {
                "owner": owner,
                "repository": repo,
                "state_requested": alert_state,
                "total_alerts": len(simplified_alerts),
                "alerts": simplified_alerts
            }
        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error fetching Dependabot alerts for '{owner}/{repo}': {e.status} - {e.message}")
        except aiohttp.ClientError as e:
            logger.error(f"Network or client error fetching Dependabot alerts for '{owner}/{repo}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching Dependabot alerts for '{owner}/{repo}': {e}")
        return {
            "owner": owner,
            "repository": repo,
            "state_requested": alert_state,
            "total_alerts": 0,
            "alerts": [],
        }

    @tool
    async def get_dependabot_alerts(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None,
            state: str = "open"
    ) -> dict:
        """
        Retrieves Dependabot alerts for a specified GitHub repository.

        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
            state (str, optional): State of alerts ('open', 'dismissed', 'fixed', 'all').

        Returns:
            dict: A dictionary with `timestamp`, `total_repositories_processed`,
            `total_dependabot_alerts_found_overall`, `repositories_dependabot_alerts`
        """
        all_alerts_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_dependabot_alerts_found_overall": 0,
            "repositories_dependabot_alerts": [],
            "overall_errors": []
        }

        repositories_to_process: list[dict] = []
        if username and repository_name:
            logger.info(f"Fetching Dependabot alerts for specific repository: {username}/{repository_name}")
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_alerts_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching Dependabot alerts for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_alerts_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                logger.warning(f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            alert_result = await self._fetch_dependabot_alerts_for_repo(
                owner=owner_name,
                repo=repo_name,
                alert_state=state
            )
            all_alerts_data["repositories_dependabot_alerts"].append(alert_result)
            all_alerts_data["total_dependabot_alerts_found_overall"] += alert_result["total_alerts"]
        return all_alerts_data

    async def _fetch_secrets_for_repo(
            self,
            owner: str,
            repo: str
    ) -> dict:
        headers = self._common_headers
        logger.info(f"Fetching secrets for repository: {owner}/{repo}")
        async with aiohttp.ClientSession() as session:
            try:
                secrets_url = f"{self.api_base_url}/repos/{owner}/{repo}/actions/secrets"
                async with session.get(
                        url=secrets_url,
                        headers=headers
                ) as response:
                    response.raise_for_status()

                    secrets_data = await response.json()
                    simplified_secrets = []
                    if "secrets" in secrets_data and isinstance(secrets_data["secrets"], list):
                        for secret in secrets_data["secrets"]:
                            simplified_secrets.append({
                                "name": secret.get("name"),
                                "created_at": secret.get("created_at"),
                                "updated_at": secret.get("updated_at")
                            })

                return {
                    "owner": owner,
                    "repository": repo,
                    "total_secrets": len(simplified_secrets),
                    "secrets": simplified_secrets
                }
            except aiohttp.ClientResponseError as e:
                logger.error(f"Error fetching secrets for '{owner}/{repo}': {e.status} - {e.message}")
            except aiohttp.ClientError as e:
                logger.error(f"Network or client error fetching secrets for '{owner}/{repo}': {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching secrets for '{owner}/{repo}': {e}")
            return {
                "owner": owner,
                "repository": repo,
                "total_secrets": 0,
                "secrets": []
            }

    @tool
    async def get_repository_secrets(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ) -> dict:
        """
        Retrieves a list of repository secrets (names and metadata, not values) for a specified GitHub repository.

        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.

        Returns:
            dict: A dictionary with `timestamp`, `total_repositories_processed`,
             `total_secrets_found_overall`, `repositories_secrets`
        """
        all_secrets_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_secrets_found_overall": 0,
            "repositories_secrets": []
        }

        repositories_to_process: list[dict] = []
        if username and repository_name:
            logger.info(f"Fetching secrets for specific repository: {username}/{repository_name}")
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_secrets_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching secrets for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_secrets_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                logger.warning(f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            secret_result = await self._fetch_secrets_for_repo(
                owner=owner_name,
                repo=repo_name
            )
            all_secrets_data["repositories_secrets"].append(secret_result)
            all_secrets_data["total_secrets_found_overall"] += secret_result["total_secrets"]
        return all_secrets_data

    async def _fetch_org_secrets(
            self,
            org_name: str
    ) -> dict:
        headers = self._common_headers
        logger.info(f"Fetching organization secrets for: {org_name}")
        async with aiohttp.ClientSession() as session:
            try:
                secrets_url = f"{self.api_base_url}/orgs/{org_name}/actions/secrets"
                async with session.get(
                        url=secrets_url,
                        headers=headers
                ) as response:
                    response.raise_for_status()
                    secrets_data = await response.json()
                    simplified_secrets = []
                    if "secrets" in secrets_data and isinstance(secrets_data["secrets"], list):
                        for secret in secrets_data["secrets"]:
                            simplified_secrets.append({
                                "name": secret.get("name"),
                                "created_at": secret.get("created_at"),
                                "updated_at": secret.get("updated_at")
                            })
                return {
                    "organization": org_name,
                    "total_secrets": len(simplified_secrets),
                    "secrets": simplified_secrets
                }
            except aiohttp.ClientResponseError as e:
                logger.error(f"Error fetching organization secrets for '{org_name}': {e.status} - {e.message}")
            except aiohttp.ClientError as e:
                logger.error(f"Network or client error fetching organization secrets for '{org_name}': {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching organization secrets for '{org_name}': {e}")
            return {
                "organization": org_name,
                "total_secrets": 0,
                "secrets": []
            }

    @tool
    async def get_organization_secrets(
            self,
            org_name: Optional[str] = None
    ) -> dict:
        """
        Retrieves a list of organization secrets (names and metadata, not values) for a specified GitHub organization
        or for all accessible organizations.

        Args:
            org_name (str, optional): Name of the GitHub organization.

        Returns:
            dict: A dictionary with `timestamp`, `total_organizations_processed`,
             `total_secrets_found_overall`, `organizations_secrets`
        """
        all_secrets_data = {
            "timestamp": datetime.now().isoformat(),
            "total_organizations_processed": 0,
            "total_secrets_found_overall": 0,
            "organizations_secrets": []
        }

        orgs_to_process: list[dict] = []
        if org_name:
            logger.info(f"Fetching secrets for specific organization: {org_name}")
            org_details_response = await self.organization_details(org_name=org_name)
            if org_details_response:
                orgs_to_process.append(org_details_response)
            all_secrets_data["total_organizations_processed"] = 1
        else:
            logger.info("Fetching secrets for all accessible organizations.")
            all_orgs_response = await self.organization_details()
            orgs_to_process = all_orgs_response.get("organizations", [])
            all_secrets_data["total_organizations_processed"] = len(orgs_to_process)

        for org_summary in orgs_to_process:
            current_org_name = org_summary.get("login")
            if not current_org_name:
                logger.warning(f"Skipping organization entry with missing login: {org_summary}")
                continue

            secret_result = await self._fetch_org_secrets(
                org_name=current_org_name
            )
            all_secrets_data["organizations_secrets"].append(secret_result)
            all_secrets_data["total_secrets_found_overall"] += secret_result["total_secrets"]
        return all_secrets_data

    async def _fetch_dependencies_for_repo(
            self,
            owner: str,
            repo: str
    ) -> dict:
        logger.info(f"Fetching dependencies for repository: {owner}/{repo}")
        async with aiohttp.ClientSession() as session:
            try:
                dependencies_url = f"{self.api_base_url}/repos/{owner}/{repo}/dependency-graph/sbom"
                sbom_headers = self._common_headers.copy()
                # GitHub's SBOM API requires a specific Accept header
                sbom_headers["Accept"] = "application/vnd.github.sbom+json"

                async with session.get(
                        url=dependencies_url,
                        headers=sbom_headers
                ) as response:
                    response.raise_for_status()
                    sbom_data = await response.json()

                dependencies_list = []
                if "sbom" in sbom_data and "packages" in sbom_data["sbom"] and isinstance(
                        sbom_data["sbom"]["packages"], list):
                    for package in sbom_data["sbom"]["packages"]:
                        dependencies_list.append({
                            "name": package.get("name"),
                            "version": package.get("version"),
                            "spdx_id": package.get("SPDXID"),
                            "license": package.get("licenseConcluded"),
                            "purl": package.get("externalRefs", [])[0].get("locator") if package.get(
                                "externalRefs") else None
                        })

                return {
                    "owner": owner,
                    "repository": repo,
                    "total_dependencies_found": len(dependencies_list),
                    "dependencies": dependencies_list
                }
            except aiohttp.ClientResponseError as e:
                logger.error(f"Error fetching dependencies for '{owner}/{repo}': {e.status} - {e.message}")
            except aiohttp.ClientError as e:
                logger.error(f"Network or client error fetching dependencies for '{owner}/{repo}': {e}")
            except Exception as e:
                logger.error(f"Unexpected error fetching dependencies for '{owner}/{repo}': {e}")
            return {
                "owner": owner,
                "repository": repo,
                "total_dependencies_found": 0,
                "dependencies": []
            }

    @tool
    async def list_repository_dependencies(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ) -> dict:
        """
        Retrieves a list of dependencies for a specified GitHub repository using the dependency manifests API.

        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.

        Returns:
            dict: A dictionary with `timestamp`, `total_repositories_processed`, `total_dependencies_found_overall`,
            `repositories_dependencies` (list of dicts for each repo's dependencies)
        """
        all_dependencies_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_dependencies_found_overall": 0,
            "repositories_dependencies": []
        }

        repositories_to_process: list[dict] = []
        if username and repository_name:
            logger.info(f"Fetching dependencies for specific repository: {username}/{repository_name}")
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_dependencies_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching dependencies for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_dependencies_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                logger.warning(f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            dependency_result = await self._fetch_dependencies_for_repo(
                owner=owner_name,
                repo=repo_name
            )
            all_dependencies_data["repositories_dependencies"].append(dependency_result)
            all_dependencies_data["total_dependencies_found_overall"] += dependency_result["total_dependencies_found"]
        return all_dependencies_data

    @tool
    async def get_packages(
            self,
            username: Optional[str] = None
    ):
        """
        Retrieves a list of packages for a specified GitHub user.

        Args:
            username (str, optional): GitHub username.

        Returns:
            dict: A dictionary with `timestamp`, `total_packages_found_overall`, `packages_data`
             (list of dicts with `id`, `name`, `package_type`, `visibility`, `created_at`, `updated_at`,
             `url`)
        """
        headers = self._common_headers
        all_packages_data = {
            "timestamp": datetime.now().isoformat(),
            "total_packages_found_overall": 0,
            "packages_data": [],
            "overall_errors": []
        }

        try:
            if username:
                logger.info(f"Fetching packages for user: {username}")
                packages_url = f"{self.api_base_url}/users/{username}/packages"
            else:
                logger.info("Fetching packages for the authenticated user.")
                packages_url = f"{self.api_base_url}/user/packages"

            packages = await self.fetch_all_pages(
                url=packages_url,
                headers=headers
            )

            simplified_packages = []
            for package in packages:
                simplified_packages.append({
                    "id": package.get("id"),
                    "name": package.get("name"),
                    "package_type": package.get("package_type"),
                    "visibility": package.get("visibility"),
                    "created_at": package.get("created_at"),
                    "updated_at": package.get("updated_at"),
                    "url": package.get("html_url")
                })

            all_packages_data["packages_data"] = simplified_packages
            all_packages_data["total_packages_found_overall"] = len(simplified_packages)

        except aiohttp.ClientResponseError as e:
            logger.error(f"HTTP error fetching packages: {e.status} - {e.message}")
        except aiohttp.ClientError as e:
            logger.error(f"Network or client error fetching packages: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching packages: {e}")
        return all_packages_data

    @tool
    async def get_repository_cache_usage(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ):
        """
        Retrieves GitHub Actions cache usage information for a specific repository
        or all accessible repositories.
        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
        Returns:
            dict: Cache usage grouped by repository.
        """
        headers = self._common_headers
        all_data = {
            "timestamp": datetime.now().isoformat(),
            "repositories_cache_usage": []
        }

        if (username and not repository_name) or (repository_name and not username):
            raise ValueError("Both 'username' and 'repository_name' must be provided together.")

        if username and repository_name:
            repos = [{"owner_name": username, "name": repository_name}]
        else:
            summary = await self.repository_summary()
            repos = summary.get("repositories", [])

        async with aiohttp.ClientSession() as session:
            for repo in repos:
                owner, name = repo.get("owner_name"), repo.get("name")
                if not owner or not name:
                    continue
                try:
                    url = f"{self.api_base_url}/repos/{owner}/{name}/actions/cache/usage"
                    async with session.get(url, headers=headers) as resp:
                        resp.raise_for_status()
                        usage = await resp.json()

                    all_data["repositories_cache_usage"].append({
                        "owner": owner,
                        "repository": name,
                        "usage": usage
                    })

                except Exception as e:
                    logger.error(f"Cache usage fetch failed for {owner}/{name}: {e}")
                    continue

        return all_data

    @tool
    async def get_github_hosted_runners(
            self,
            org_name: Optional[str] = None
    ):
        """
        Retrieves GitHub-hosted runners for a specific organization or all accessible organizations.
        Args:
            org_name (str, optional): The name of the GitHub organization.
        Returns:
            dict: GitHub-hosted runners grouped by organization.
        """
        headers = self._common_headers
        all_data = {
            "timestamp": datetime.now().isoformat(),
            "github_hosted_runners": []
        }
        if org_name:
            orgs = [org_name]
        else:
            orgs_summary = await self.organization_details()
            orgs = [org.get("login") for org in orgs_summary.get("organizations", []) if org.get("login")]

        for org in orgs:
            try:
                url = f"{self.api_base_url}/orgs/{org}/actions/runners"
                runners = await self.fetch_all_pages(url, headers)

                all_data["github_hosted_runners"].append({
                    "organization": org,
                    "total_runners": len(runners),
                    "runners": runners
                })

            except Exception as e:
                logger.error(f"GitHub-hosted runners fetch failed for org {org}: {e}")
                continue
        return all_data

    @tool
    async def get_organization_oidc_settings(
            self,
            org_name: Optional[str] = None
    ):
        """
        Retrieves OIDC subject customization settings for a specific organization or all accessible organizations.
        Args:
            org_name (str, optional): The name of the GitHub organization.
        Returns:
            dict: OIDC subject customization settings grouped by organization.
        """
        headers = self._common_headers
        all_data = {
            "timestamp": datetime.now().isoformat(),
            "organizations_oidc": []
        }

        if org_name:
            orgs = [org_name]
        else:
            org_summary = await self.organization_details()
            orgs = [org.get("login") for org in org_summary.get("organizations", []) if org.get("login")]

        async with aiohttp.ClientSession() as session:
            for org in orgs:
                try:
                    url = f"{self.api_base_url}/orgs/{org}/actions/oidc/customization/sub"
                    async with session.get(url, headers=headers) as resp:
                        resp.raise_for_status()
                        oidc = await resp.json()

                    all_data["organizations_oidc"].append({
                        "organization": org,
                        "oidc_sub": oidc
                    })

                except Exception as e:
                    logger.error(f"OIDC settings fetch failed for org {org}: {e}")
                    continue
        return all_data

    @tool
    async def get_repository_variables(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ):
        """
        Retrieves GitHub Actions variables (names and values) for a specific repository or all accessible repositories.
        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
        Returns:
            dict: Variables grouped by repository.
        """
        headers = self._common_headers
        all_data = {
            "timestamp": datetime.now().isoformat(),
            "repositories_variables": []
        }

        if (username and not repository_name) or (repository_name and not username):
            raise ValueError("Both 'username' and 'repository_name' must be provided together.")

        if username and repository_name:
            repos = [{"owner_name": username, "name": repository_name}]
        else:
            summary = await self.repository_summary()
            repos = summary.get("repositories", [])

        for repo in repos:
            owner, name = repo.get("owner_name"), repo.get("name")
            if not owner or not name:
                continue
            try:
                url = f"{self.api_base_url}/repos/{owner}/{name}/actions/variables"
                var = await self.fetch_all_pages(url, headers)
                all_data["repositories_variables"].append({
                    "owner": owner,
                    "repository": name,
                    "variables": var
                })
            except Exception as e:
                logger.error(f"Variable fetch failed for {owner}/{name}: {e}")
                continue
        return all_data

    @tool
    async def get_workflows(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ):
        """
        Retrieves GitHub Actions workflows for a specific repository or all accessible repositories.
        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
        Returns:
            dict: Workflows grouped by repository.
        """
        headers = self._common_headers
        all_data = {
            "timestamp": datetime.now().isoformat(),
            "repositories_workflows": [],
            "total_workflows_found_overall": 0
        }

        if username and repository_name:
            repositories = [{"owner_name": username, "name": repository_name}]
        else:
            summary = await self.repository_summary()
            repositories = summary.get("repositories", [])

        for repo in repositories:
            owner = repo.get("owner_name")
            name = repo.get("name")
            if not owner or not name:
                continue
            try:
                url = f"{self.api_base_url}/repos/{owner}/{name}/actions/workflows"
                workflows = await self.fetch_all_pages(url, headers)
                all_data["repositories_workflows"].append({
                    "owner": owner,
                    "repository": name,
                    "workflows": workflows
                })
                all_data["total_workflows_found_overall"] += len(workflows)
            except Exception as e:
                logger.error(f"Workflow fetch failed for {owner}/{name}: {e}")
        return all_data

    @tool
    async def get_workflow_runs(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ):
        """
        Retrieves the workflow runs for a specified GitHub repository, optionally filtered by a specific workflow.
        Args:
            username (str): The owner (user or organization) of the repository.
            repository_name (str): The name of the repository.
        Returns:
            dict: A dictionary containing:
                - 'total_count' (int): Total number of workflow runs.
                - 'workflow_runs' (list): A list of workflow run objects, each with details like 'id', 'status', 'conclusion', 'created_at', etc.
        """
        headers = self._common_headers
        repos = (
            [{"owner_name": username, "name": repository_name}]
            if username and repository_name
            else (await self.repository_summary()).get("repositories", [])
        )
        all_data = {"timestamp": datetime.now().isoformat(), "repositories_workflow_runs": []}
        for repo in repos:
            owner, name = repo.get("owner_name"), repo.get("name")
            if not owner or not name:
                continue
            try:
                url = f"{self.api_base_url}/repos/{owner}/{name}/actions/runs"
                runs = await self.fetch_all_pages(url, headers)
                all_data["repositories_workflow_runs"].append({
                    "owner": owner, "repository": name, "workflow_runs": runs
                })
            except Exception as e:
                logger.error(f"Workflow runs fetch failed for {owner}/{name}: {e}")
        return all_data

    @tool
    async def get_workflow_jobs_(
            self
    ):
        """
        Retrieves the runner groups configured for a specified GitHub user or organization.
        Returns:
            dict: A dictionary containing:
                - 'total_runner_groups' (int): The number of runner groups found.
                - 'runner_groups' (list): A list of runner group objects, each including details such as:
                    'id', 'name', 'visibility', 'default', 'selected_repositories_url', etc.
                - 'errors' (list, optional): Any errors encountered during the retrieval process.
        """
        headers = self._common_headers
        all_jobs_data = {
            "timestamp": datetime.now().isoformat(),
            "repositories_workflow_jobs": [],
        }
        repos = (await self.repository_summary()).get("repositories", [])

        for repo in repos:
            owner, name = repo.get("owner_name"), repo.get("name")
            if not owner or not name:
                continue
            try:
                run_ids = [r.get("id") for r in (
                    await self.fetch_all_pages(f"{self.api_base_url}/repos/{owner}/{name}/actions/runs", headers)
                )]
                for rid in run_ids:
                    if rid:
                        url = f"{self.api_base_url}/repos/{owner}/{name}/actions/runs/{rid}/jobs"
                        jobs = await self.fetch_all_pages(url, headers)
                        all_jobs_data["repositories_workflow_jobs"].append({
                            "owner": owner, "repository": name, "run_id": rid, "jobs": jobs
                        })
            except Exception as e:
                logger.error(f"Workflow jobs fetch failed for {owner}/{name}: {e}")
        return all_jobs_data

    @tool
    async def get_runner_groups(
            self,
            org_name: Optional[str] = None
    ):
        headers = self._common_headers

        if org_name:
            orgs = [org_name]
        else:
            orgs = [org.get("login") for org in (await self.organization_details()).get("organizations", [])]

        all_data = {
            "timestamp": datetime.now().isoformat(),
            "organizations_runner_groups": []
        }

        for org in orgs:
            try:
                url = f"{self.api_base_url}/orgs/{org}/actions/runner-groups"
                groups = await self.fetch_all_pages(url, headers)
                all_data["organizations_runner_groups"].append({
                    "organization": org,
                    "runner_groups": groups
                })
            except Exception as e:
                logger.error(f"Runner groups fetch failed for {org}: {e}")
        return all_data

    @tool
    async def get_self_hosted_runners(
            self,
            org_name: Optional[str] = None
    ):
        """
        Retrieves information about self-hosted GitHub Actions runners for a specified user, organization, or the authenticated user.

        Args:
            org_name (str, optional): GitHub username or organization name to fetch self-hosted runners for.
        Returns:
            dict: A dictionary containing:
                - 'total_runners' (int): Total number of self-hosted runners found.
                - 'runners' (list): List of self-hosted runner details, each as a dictionary with keys such as:
                    'id', 'name', 'os', 'status', 'busy', 'labels', 'created_at', etc.
                - 'errors' (list, optional): List of errors encountered during data retrieval, if any.
        """
        headers = self._common_headers
        orgs = [org_name] if org_name else [
            org.get("login") for org in (await self.organization_details()).get("organizations", [])
        ]

        all_data = {
            "timestamp": datetime.now().isoformat(),
            "organizations_self_hosted_runners": []
        }

        for org in orgs:
            try:
                url = f"{self.api_base_url}/orgs/{org}/actions/runners"
                runners = await self.fetch_all_pages(url, headers)
                self_hosted = [r for r in runners if r.get("os") and r.get("name")]

                all_data["organizations_self_hosted_runners"].append({
                    "organization": org,
                    "self_hosted_runners": self_hosted
                })
            except Exception as e:
                logger.error(f"Self-hosted runners fetch failed for {org}: {e}")
        return all_data

    @tool
    async def get_artifacts_for_repo(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ):
        """
        Retrieves GitHub Actions artifacts for a specific repository or all accessible repositories.
        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
        Returns:
            dict: Artifacts grouped by repository.
        """
        headers = self._common_headers
        all_data = {
            "timestamp": datetime.now().isoformat(),
            "repositories_artifacts": [],
            "total_artifacts_found_overall": 0
        }

        if (username and not repository_name) or (repository_name and not username):
            raise ValueError("Both 'username' and 'repository_name' must be provided together.")

        if username and repository_name:
            repositories = [{"owner_name": username, "name": repository_name}]
        else:
            summary = await self.repository_summary()
            repositories = summary.get("repositories", [])

        for repo in repositories:
            owner = repo.get("owner_name")
            name = repo.get("name")
            if not owner or not name:
                continue

            try:
                url = f"{self.api_base_url}/repos/{owner}/{name}/actions/artifacts"
                artifacts = await self.fetch_all_pages(url, headers)

                simplified = [
                    {
                        "id": a["id"],
                        "name": a["name"],
                        "size": a.get("size_in_bytes"),
                        "created_at": a.get("created_at"),
                        "expires_at": a.get("expires_at"),
                    }
                    for a in artifacts
                ]

                all_data["repositories_artifacts"].append({
                    "owner": owner,
                    "repository": name,
                    "artifacts": simplified
                })
                all_data["total_artifacts_found_overall"] += len(simplified)

            except Exception as e:
                logger.error(f"Artifact fetch failed for {owner}/{name}: {e}")
                continue
        return all_data

    @tool
    async def get_repository_permissions(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ):
        """
        Retrieves permission settings for a specific repository or all accessible repositories.
        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
        Returns:
            dict: Permissions grouped by repository.
        """
        headers = self._common_headers
        all_data = {
            "timestamp": datetime.now().isoformat(),
            "repositories_permissions": []
        }

        if (username and not repository_name) or (repository_name and not username):
            raise ValueError("Both 'username' and 'repository_name' must be provided together.")

        if username and repository_name:
            repositories = [{"owner_name": username, "name": repository_name}]
        else:
            summary = await self.repository_summary()
            repositories = summary.get("repositories", [])

        async with aiohttp.ClientSession() as session:
            for repo in repositories:
                owner = repo.get("owner_name")
                name = repo.get("name")
                if not owner or not name:
                    continue

                try:
                    url = f"{self.api_base_url}/repos/{owner}/{name}/actions/permissions"
                    async with session.get(url, headers=headers) as resp:
                        resp.raise_for_status()
                        permissions = await resp.json()

                    all_data["repositories_permissions"].append({
                        "owner": owner,
                        "repository": name,
                        "permissions": permissions
                    })

                except Exception as e:
                    logger.error(f"Permission fetch failed for {owner}/{name}: {e}")
                    continue

        return all_data

    @tool
    async def get_repository_secrets(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ):
        """
        Retrieves a list of repository secrets (names and metadata, not values) for a specific repository
        or for all accessible repositories.
        Args:
            username (str, optional): Repository owner's username.
            repository_name (str, optional): Repository name.
        Returns:
            dict: Secrets grouped by repository, with metadata only (not secret values).
        """
        headers = self._common_headers
        all_data = {
            "timestamp": datetime.now().isoformat(),
            "repositories_secrets": [],
            "total_secrets_found_overall": 0
        }

        if (username and not repository_name) or (repository_name and not username):
            raise ValueError("Both 'username' and 'repository_name' must be provided together.")

        if username and repository_name:
            repositories = [{"owner_name": username, "name": repository_name}]
        else:
            summary = await self.repository_summary()
            repositories = summary.get("repositories", [])

        async with aiohttp.ClientSession() as session:
            for repo in repositories:
                owner = repo.get("owner_name")
                name = repo.get("name")
                if not owner or not name:
                    continue

                try:
                    url = f"{self.api_base_url}/repos/{owner}/{name}/actions/secrets"
                    async with session.get(url, headers=headers) as resp:
                        resp.raise_for_status()
                        secrets_json = await resp.json()

                    simplified = [
                        {
                            "name": s.get("name"),
                            "created_at": s.get("created_at"),
                            "updated_at": s.get("updated_at")
                        }
                        for s in secrets_json.get("secrets", [])
                    ]

                    all_data["repositories_secrets"].append({
                        "owner": owner,
                        "repository": name,
                        "secrets": simplified
                    })
                    all_data["total_secrets_found_overall"] += len(simplified)

                except Exception as e:
                    logger.error(f"Secrets fetch failed for {owner}/{name}: {e}")
                    continue
        return all_data

    @tool
    async def get_all_action_data(
            self
    ):
        """
         Retrieves comprehensive GitHub Actions workflow run data for a specified user, organization, or the authenticated user.
        Returns:
            dict: A dictionary containing:
                - 'total_workflow_runs' (int): Total number of workflow runs found.
                - 'workflow_runs' (list): List of workflow run details, each as a dictionary containing keys like:
                    'repository', 'run_id', 'status', 'conclusion', 'created_at', etc.
                - 'errors' (list, optional): List of errors encountered during data fetching, if any.
        """
        return {
            "artifacts": await self.get_artifacts_for_repo(),
            "permissions": await self.get_repository_permissions(),
            "secrets": await self.get_repository_secrets(),
            "variables": await self.get_repository_variables(),
            "workflows": await self.get_workflows(),
            "workflow_runs": await self.get_workflow_runs(),
            "workflow_jobs": await self.get_workflow_jobs_(),
            "runners": await self.get_self_hosted_runners(),
            "runner_groups": await self.get_runner_groups(),
            "cache_usage": await self.get_repository_cache_usage(),
            "hosted_runners": await self.get_github_hosted_runners(),
            "oidc_settings": await self.get_organization_oidc_settings(),
        }

    @tool
    async def detect_ddos_risk(
            self,
            threshold: int = 1000
    ):
        """
        Detect potential DDoS risk by checking if the remaining rate limit is below a threshold.
        Args:
            threshold (int): The minimum remaining rate limit before flagging potential DDoS risk. Default is 1000.
        Returns:
            dict: Information about rate limit and potential DDoS risk.
        """
        headers = self._common_headers
        url = f"{self.api_base_url}/rate_limit"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    remaining = data.get("rate", {}).get("remaining", 0)
                    limit = data.get("rate", {}).get("limit", 0)
                    reset_time = data.get("rate", {}).get("reset", 0)
                    potential_ddos = remaining < threshold

                    return {
                        "timestamp": datetime.now().isoformat(),
                        "rate_limit": {
                            "limit": limit,
                            "remaining": remaining,
                            "reset_time": reset_time,
                        },
                        "potential_ddos_risk": potential_ddos,
                        "message": "Warning: High API usage detected, possible DDoS risk." if potential_ddos
                        else "API usage within safe limits."
                    }
        except Exception as e:
            logger.error(f"Failed to detect DDoS risk: {e}")
            return {"error": str(e)}

    @tool
    async def detect_sdos_risk(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None,
            run_count_threshold: int = 50
    ) -> dict:
        """
        Detect potential SDOS risk by analyzing workflow runs.
        Args:
            username (str, optional): GitHub username or org name.
            repository_name (str, optional): Repository name.
            run_count_threshold (int): Threshold of workflow runs to flag SDOS risk.
        Returns:
            dict: SDOS risk analysis.
        """
        headers = self._common_headers

        # Prepare repo list to check
        if username and repository_name:
            repos = [{"owner_name": username, "name": repository_name}]
        else:
            # Fetch all repos for authenticated user/orgs
            repo_summary = await self.repository_summary()
            repos = repo_summary.get("repositories", [])

        all_data = {"timestamp": datetime.now().isoformat(), "sdos_risk_analysis": []}

        for repo in repos:
            owner = repo.get("owner_name")
            name = repo.get("name")

            if not owner or not name:
                continue

            try:
                url = f"{self.api_base_url}/repos/{owner}/{name}/actions/runs?per_page=100"
                async with aiohttp.ClientSession as Session:
                    async with Session.get(url=url, headers=headers) as resp:
                        resp.raise_for_status()
                        runs_data = await resp.json()
                        runs = runs_data.get("workflow_runs", [])
                        total_runs = len(runs)
                        failed_runs = sum(1 for run in runs if run.get("conclusion") == "failure")
                        potential_sdos = total_runs > run_count_threshold

                    all_data["sdos_risk_analysis"].append({
                        "owner": owner,
                        "repository": name,
                        "total_recent_runs": total_runs,
                        "failed_runs": failed_runs,
                        "potential_sdos_risk": potential_sdos,
                        "message": "High workflow activity detected; possible SDOS risk." if potential_sdos
                        else "Workflow activity within expected limits."
                    })

            except aiohttp.ClientResponseError as e:
                all_data["sdos_risk_analysis"].append({
                    "owner": owner,
                    "repository": name,
                    "error": f"HTTP error {e.status}: {e.message}"
                })
            except aiohttp.ClientError as e:
                all_data["sdos_risk_analysis"].append({
                    "owner": owner,
                    "repository": name,
                    "error": f"Network error: {str(e)}"
                })
            except Exception as e:
                all_data["sdos_risk_analysis"].append({
                    "owner": owner,
                    "repository": name,
                    "error": f"Unexpected error: {str(e)}"
                })

        return all_data







