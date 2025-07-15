import logging
from datetime import datetime
from typing import Optional

import os
import aiohttp

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

GITHUB_API_BASE_URL = "https://api.github.com"


class GitHubHandler(BaseHandler):
    """
    A handler to collect GitHub GRC (Governance, Risk, and Compliance) evidence,
    focusing on MFA, organizational details, and repository data.
    """

    def __init__(
            self,
            github_token: str = None
    ):
        super().__init__()
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')

        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable not set. Please set it.")

    @tool
    async def common_headers(
            self
    )-> dict:
        """
            Returns common headers including Authorization.
            Args:
                None.
            Dict:
                `Authorization` (str): GitHub personal access token.
                `Accept` (str): GitHub API version.
        """

        if not self.github_token:
            logger.error("Attempted to get common headers without a GitHub token.")
            return {"error": "GitHub token not available."}
        return {
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
                `url` (str): Initial API endpoint URL.
                `headers` (dict): HTTP headers for the request.
                `params` (dict, optional): Query parameters.
            Dict:
                A list of dictionaries representing paginated API response items.
        """
        all_data: list[dict] = []
        current_url = url
        current_params = params.copy() if params is not None else {}
        page_data_keys = [
            "items", "workflow_runs", "jobs", "artifacts",
            "secrets", "repositories", "pull_requests", "branches"
        ]

        async with aiohttp.ClientSession() as session:
            while current_url:
                try:
                    async with session.get(
                            current_url,
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
                                    next_url = link.split(';')[0].strip('<>')
                                    break
                        current_url = next_url
                        current_params = {}  # Clear params for subsequent paginated requests
                except aiohttp.ClientResponseError as e:
                    http_error_message = f"HTTP error fetching pages from {current_url}: {e.status} - {e.message}"
                    logger.error(http_error_message)
                    raise
                except aiohttp.ClientError as e:
                    client_error_message = f"Network or client error fetching pages from {current_url}: {e}"
                    logger.error(client_error_message)
                    raise
                except Exception as e:
                    unexpected_error_message = f"Unexpected error fetching pages from {current_url}: {e}"
                    logger.error(unexpected_error_message)
                    raise
        return all_data

    @tool
    async def organization_details(
            self,
            org_name: Optional[str] = None
    ) -> dict:
        """
            Retrieves details for a specific GitHub organization, or all organizations
            associated with the authenticated user if no org_name is provided.
            Requires 'read:org' scope.
            Args:
                `org_name` (str, optional): Name of the GitHub organization.
            Dict:
                If `org_name` is provided:
                    A dictionary with organization details (e.g., `login`, `id`, `name`).
                If `org_name` is None:
                    A dictionary with `organizations` (list of org details) and `total_organizations_found` (int).
                Error dictionary if an issue occurs.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Error in Organisation_details: {headers['error']}")
            return {}

        async with aiohttp.ClientSession() as session:
            try:
                if org_name:
                    org_url = f"{GITHUB_API_BASE_URL}/orgs/{org_name}"
                    logger.info(f"Fetching details for organization: {org_name}")
                    async with session.get(
                            org_url,
                            headers=headers
                    ) as resp:
                        resp.raise_for_status()
                        return await resp.json()
                else:
                    logger.info("Fetching details for all organizations associated with the authenticated user.")
                    orgs = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/user/orgs", headers)
                    all_org_details = []
                    for org_data in orgs:
                        details = await self.organization_details(org_name=org_data.get("login"))
                        all_org_details.append(details)
                    return {"organizations": all_org_details,
                            "total_organizations_found": len(all_org_details)}
            except aiohttp.ClientResponseError as e:
                org_http_error_msg = f"Error fetching organization details (HTTP {e.status}): {e.message}"
                logger.error(org_http_error_msg)
                return {}
            except aiohttp.ClientError as e:
                org_client_error_msg = f"Network or client error fetching organization details: {e}"
                logger.error(org_client_error_msg)
                return {}
            except Exception as e:
                org_unexpected_error_msg = f"Unexpected error fetching organization details: {e}"
                logger.error(org_unexpected_error_msg)
                return {}

    @tool
    async def user_details(
            self,
            username: Optional[str] = None
    ) -> dict:
        """
            Retrieves profile information for a GitHub user.
            If no username is provided, retrieves details for the authenticated user.
            Requires 'read:user' scope.
            Args:
                `username`: The GitHub username. This parameter is **optional**.
                            If not provided by the user, it will default to `None`,
                            and the function will attempt to fetch details for the
                            currently authenticated user (if applicable) or indicate
                            that a username is required.

            Returns:
                A dictionary with user details (e.g., `login`, `id`, `name`).
                Returns an empty dictionary `{}` if an issue occurs.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Error fetching common headers for user details: {headers['error']}")
            return {}

        user_url = f"{GITHUB_API_BASE_URL}/users/{username}" if username else f"{GITHUB_API_BASE_URL}/user"
        async with aiohttp.ClientSession() as session:
            try:
                logger.info(f"Fetching user details for: {username if username else 'authenticated user'}")
                async with session.get(
                        user_url,
                        headers=headers
                ) as resp:
                    resp.raise_for_status()
                    return await resp.json()
            except aiohttp.ClientResponseError as e:
                user_http_error_msg = f"Error fetching user details (HTTP {e.status}): {e.message}"
                logger.error(user_http_error_msg)
                return {}
            except aiohttp.ClientError as e:
                user_client_error_msg = f"Network or client error fetching user details: {e}"
                logger.error(user_client_error_msg)
                return {}
            except Exception as e:
                user_unexpected_error_msg = f"Unexpected error fetching user details: {e}"
                logger.error(user_unexpected_error_msg)
                return {}

    @tool
    async def mfa_evidence(
            self,
            org_name: Optional[str] = None
    ) -> dict:
        """
            Collects MFA compliance evidence and organizational details.
            If org_name is not provided, it collects evidence for all organizations
            associated with the authenticated user.
            Requires 'read:org' and 'read:user' scopes.
            Args:
                `org_name` (str, optional): Name of the GitHub organization.
            Dict:
                If `org_name` is provided:
                    A dictionary with MFA enforcement status, member MFA status, and organization details.
                If `org_name` is None:
                    A dictionary with MFA evidence for all accessible organizations.
                Error dictionary if an issue occurs.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Error fetching for get_mfa: {headers['error']}")
            return {}

        async def single_mfa_evidence_internal(
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
                org_details = await self.organization_details(org_name=org_name)
                if "error" in org_details:
                    evidence["errors"].append(f"Organization details error: {org_details['error']}")
                    logger.warning(f"Could not fetch organization details for {org_name}: {org_details['error']}")
                else:
                    evidence["organization_details"] = org_details

                disabled_members_basic = await self.fetch_all_pages(
                    f"{GITHUB_API_BASE_URL}/orgs/{org_name}/members?filter=2fa_disabled", common_headers
                )
                if disabled_members_basic:
                    evidence["mfa_enforcement_detected"] = True
                    evidence["members_with_mfa_disabled"].extend(
                        [{"login": m["login"], "id": m["id"]} for m in disabled_members_basic])
                    logger.info(f"{len(disabled_members_basic)} members with 2FA disabled in {org_name}.")

                all_members_basic = await self.fetch_all_pages(
                    f"{GITHUB_API_BASE_URL}/orgs/{org_name}/members", common_headers)
                evidence["total_members"] = len(all_members_basic)
                logger.info(f"Found {len(all_members_basic)} total members in {org_name}.")

                disabled_logins = {member["login"] for member in evidence["members_with_mfa_disabled"]}

                for member_basic in all_members_basic:
                    user_detail = await self.user_details(username=member_basic["login"])
                    detailed_info = {
                        "login": member_basic["login"],
                        "id": member_basic["id"],
                        "mfa_enabled": member_basic["login"] not in disabled_logins
                    }
                    if "error" in user_detail:
                        detailed_info["details_error"] = user_detail["error"]
                        evidence["errors"].append(
                            f"User details error for {member_basic['login']}: {user_detail['error']}")
                        logger.warning(
                            f"Could not fetch user details for {member_basic['login']}: {user_detail['error']}")
                    else:
                        detailed_info.update({
                            "name": user_detail.get("name"), "type": user_detail.get("type"),
                            "company": user_detail.get("company"), "email": user_detail.get("email"),
                            "created_at": user_detail.get("created_at"), "updated_at": user_detail.get("updated_at"),
                            "public_repos": user_detail.get("public_repos"), "followers": user_detail.get("followers"),
                        })
                    if detailed_info["mfa_enabled"]:
                        evidence["members_with_mfa_enabled"].append(
                            {"login": member_basic["login"], "id": member_basic["id"]})
                    evidence["all_members_details"].append(detailed_info)

            except aiohttp.ClientResponseError as e:
                mfa_http_error_msg = f"HTTP error processing organization '{org_name}': {e.status} - {e.message}"
                logger.error(mfa_http_error_msg)
                evidence["errors"].append(mfa_http_error_msg)
            except aiohttp.ClientError as e:
                mfa_client_error_msg = f"Network or client error processing organization '{org_name}': {e}"
                logger.error(mfa_client_error_msg)
                evidence["errors"].append(mfa_client_error_msg)
            except Exception as e:
                mfa_unexpected_error_msg = f"Unexpected error processing organization '{org_name}': {e}"
                logger.error(mfa_unexpected_error_msg)
                evidence["errors"].append(mfa_unexpected_error_msg)

            return evidence

        if org_name:
            return await single_mfa_evidence_internal(org_name, headers)
        else:
            logger.info("Collecting MFA evidence for all organizations.")
            all_orgs_response = await self.organization_details()
            if "error" in all_orgs_response:
                logger.error({"error": f"Failed to retrieve organizations: {all_orgs_response['error']}"})
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
                    org_evidence = await single_mfa_evidence_internal(current_org_name, headers)
                    all_evidence["organizations_mfa_evidence"].append(org_evidence)
                    if org_evidence["errors"]:
                        all_evidence["errors"].extend(org_evidence["errors"])
                else:
                    missing_login_error_msg = f"Skipping organization entry with missing login: {org_detail}"
                    all_evidence["errors"].append(missing_login_error_msg)
                    logger.warning(missing_login_error_msg)
            return all_evidence

    @tool
    async def repository_summary(
            self,
            entity_name: Optional[str] = None
    ) -> dict:
        """
            Retrieves a summary of repositories for a specific user or organization.
            If no entity_name is provided, it fetches repositories for the authenticated user
            and all organizations they belong to.
            Requires 'repo' scope for private repositories, 'read:org' for organization repos.
            Args:
                `entity_name` (str, optional): GitHub username or organization name.
            Dict:
                A dictionary with `total_repositories_found` (int), `repositories` (list of dicts with `name`, `status`,
                 `owner_type`, `owner_name`), and `errors` (list or "None").
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Error fetching for repository summary: {headers['error']}")
            return {}

        all_repos_summary: list[dict] = []
        errors: list[str] = []
        processed_repo_full_names = set()

        async def process_repositories_internal(
                repos_list: list[dict],
                source_type: str,
                source_name: str
        ):
            for repo_data in repos_list:
                full_name = repo_data.get("full_name")
                if full_name and full_name not in processed_repo_full_names:
                    status = "Public" if not repo_data.get("private") else "Private"
                    if repo_data.get("archived"):
                        status = f"Archived ({status})"
                    all_repos_summary.append({
                        "name": repo_data.get("name"), "full_name": full_name,
                        "status": status, "owner_type": source_type, "owner_name": source_name
                    })
                    processed_repo_full_names.add(full_name)

        try:
            if entity_name:
                logger.info(f"Fetching repository summary for entity: {entity_name}")
                user_details = await self.user_details(username=entity_name)
                if "error" not in user_details and user_details.get("type") == "User":
                    logger.info(f"Entity '{entity_name}' identified as a user. Fetching user repositories.")
                    user_repos = await self.fetch_all_pages(
                        f"{GITHUB_API_BASE_URL}/users/{entity_name}/repos",
                        headers
                    )
                    await process_repositories_internal(user_repos, "User", entity_name)
                else:
                    org_details = await self.organization_details(org_name=entity_name)
                    if "error" not in org_details and org_details.get("type") == "Organization":
                        logger.info(
                            f"Entity '{entity_name}' identified as an organization. Fetching organization repositories."
                        )
                        org_repos = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/orgs/{entity_name}/repos",
                                                               headers)
                        await process_repositories_internal(org_repos, "Organization", entity_name)
                    else:
                        entity_not_found_error_msg = f"Entity '{entity_name}' not found as a user or organization."
                        errors.append(entity_not_found_error_msg)
                        logger.warning(entity_not_found_error_msg)
            else:
                logger.info("Fetching repository summary for the authenticated user and their organizations.")
                auth_user_details = await self.user_details()
                if "error" not in auth_user_details:
                    auth_username = auth_user_details.get("login")
                    if auth_username:
                        logger.info(f"Fetching authenticated user's repositories: {auth_username}")
                        user_repos = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/user/repos", headers)
                        await process_repositories_internal(user_repos, "Authenticated User", auth_username)
                    else:
                        auth_user_login_error_msg = "Could not retrieve login for authenticated user."
                        errors.append(auth_user_login_error_msg)
                        logger.error(auth_user_login_error_msg)
                else:
                    auth_user_details_error_msg = (f"Error fetching authenticated user details: "
                                                   f"{auth_user_details['error']}")
                    errors.append(auth_user_details_error_msg)
                    logger.error(auth_user_details_error_msg)

                all_orgs_response = await self.organization_details()
                if "error" not in all_orgs_response:
                    for org_data in all_orgs_response.get("organizations", []):
                        org_name_from_list = org_data.get("login")
                        if org_name_from_list:
                            logger.info(f"Fetching repositories for organization: {org_name_from_list}")
                            org_repos = await self.fetch_all_pages(
                                f"{GITHUB_API_BASE_URL}/orgs/{org_name_from_list}/repos", headers)
                            await process_repositories_internal(
                                org_repos,
                                "Organization", org_name_from_list
                            )
                        else:
                            org_list_missing_login_error_msg = (f"Skipping organization entry with missing "
                                                                f"login: {org_data}")
                            errors.append(org_list_missing_login_error_msg)
                            logger.warning(org_list_missing_login_error_msg)
                else:
                    auth_orgs_fetch_error_msg = (f"Error fetching organizations for authenticated user: "
                                                 f"{all_orgs_response['error']}")
                    errors.append(auth_orgs_fetch_error_msg)
                    logger.error(auth_orgs_fetch_error_msg)
        except aiohttp.ClientResponseError as e:
            repo_summary_http_error_msg = f"HTTP error during repository fetching: {e.status} - {e.message}"
            errors.append(repo_summary_http_error_msg)
            logger.error(repo_summary_http_error_msg)
        except aiohttp.ClientError as e:
            repo_summary_client_error_msg = f"Network or client error during repository fetching: {e}"
            errors.append(repo_summary_client_error_msg)
            logger.error(repo_summary_client_error_msg)
        except Exception as e:
            repo_summary_unexpected_error_msg = f"Unexpected error during repository fetching: {e}"
            errors.append(repo_summary_unexpected_error_msg)
            logger.error(repo_summary_unexpected_error_msg)

        return {
            "total_repositories_found": len(all_repos_summary),
            "repositories": all_repos_summary,
            "errors": errors if errors else "None"
        }

    @tool
    async def list_organization_members(
            self,
            org_name: Optional[str] = None,
            role: Optional[str] = None,
            filter_2fa: bool = False
    ) -> dict[str, dict]:
        """
            Retrieves a list of members for a given GitHub organization(s),
            returning only member ID, name (login), and total count per organization.
            If no org_name is provided, it fetches members for all organizations
            the authenticated user belongs to.
            Requires 'read:org' scope.
            Args:
                `org_name` (str, optional): Name of the GitHub organization.
                `role` (str, optional): Filters members by role ('all', 'admin', 'member').
                `filter_2fa` (bool, optional): If True, returns only members with 2FA disabled.
            Dict:
                A dictionary where keys are organization names and values contain `members` (list of dicts with
                `member_id`, `name`) and `count` (int).
                Error dictionary if an issue occurs.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Error fetching for list_organization_members: {headers['error']}")
            return {}

        all_organization_members: dict[str, dict] = {}
        orgs_to_process: list[dict] = []

        if org_name:
            logger.info(f"Listing members for organization: {org_name}")
            org_details_response = await self.organization_details(org_name=org_name)
            if "error" in org_details_response:
                return org_details_response
            orgs_to_process.append(org_details_response)
        else:
            logger.info("Listing members for all organizations accessible by the authenticated user.")
            orgs_response = await self.organization_details()
            if "error" in orgs_response:
                return orgs_response
            orgs_to_process = orgs_response.get("organizations", [])

        for org_data in orgs_to_process:
            current_org_name = org_data.get("login")
            if not current_org_name:
                logger.warning(f"Skipping organization entry with missing login: {org_data}")
                continue

            members_url = f"{GITHUB_API_BASE_URL}/orgs/{current_org_name}/members"
            params = {}
            if role:
                if role not in ['all', 'admin', 'member']:
                    invalid_role_error_msg = (f"Invalid role specified for {current_org_name}. Must be 'all', "
                                              f"'admin', or 'member'.")
                    all_organization_members[current_org_name] = {"error": invalid_role_error_msg}
                    logger.error(invalid_role_error_msg)
                    continue
                params['role'] = role

            try:
                members_full_data = await self.fetch_all_pages(members_url, headers, params=params)

                if filter_2fa:
                    members_to_process = [
                        member for member in members_full_data
                        if 'two_factor_authentication_enabled' in member and not member[
                            'two_factor_authentication_enabled']
                    ]
                    logger.info(
                        f"Filtered for 2FA disabled members in {current_org_name}: {len(members_to_process)} found.")
                else:
                    members_to_process = members_full_data
                    logger.info(f"Found {len(members_to_process)} total members in {current_org_name}.")

                filtered_members = [
                    {"member_id": member.get("id"), "name": member.get("login")}
                    for member in members_to_process
                ]

                all_organization_members[current_org_name] = {
                    "members": filtered_members,
                    "count": len(filtered_members)
                }

            except aiohttp.ClientResponseError as e:
                members_http_error_msg = f"HTTP error fetching members for {current_org_name}: {e.status} - {e.message}"
                logger.error(members_http_error_msg)
                all_organization_members[current_org_name] = {"error": members_http_error_msg}
            except aiohttp.ClientError as e:
                members_client_error_msg = f"Network or client error fetching members for {current_org_name}: {e}"
                logger.error(members_client_error_msg)
                all_organization_members[current_org_name] = {"error": members_client_error_msg}
            except Exception as e:
                members_unexpected_error_msg = f"Unexpected error fetching members for {current_org_name}: {e}"
                logger.error(members_unexpected_error_msg)
                all_organization_members[current_org_name] = {"error": members_unexpected_error_msg}

        if not all_organization_members and not orgs_to_process:
            logging.error("No organizations found or the provided organization does not exist.")
            return {}
        return all_organization_members

    @tool
    async def repository_branches(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ) -> dict:
        """
            Retrieves a list of branches for a specified GitHub repository.
            If no username and repository_name are provided, it fetches branches for all
            repositories associated with the authenticated user (and their organizations).
            Requires 'public_repo' or 'repo' scope.
            Args:
                `username` (str, optional): Repository owner's username.
                `repository_name` (str, optional): Repository name.
            Dict:
                If specific repo:
                    A dictionary with `owner`, `repository`, `total_branches`, `branches` (list of dicts with `name`,
                    `commit_sha`), and `errors`.
                If all accessible repos:
                    A dictionary with `total_repositories_processed`, `total_branches_found_overall`,
                    `repositories_branches` (list of dicts), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Error fetching repository_branches: {headers['error']}")
            return {}

        async def fetch_repo_branches_internal(
                owner: str,
                repo: str
        ) -> dict:
            logger.info(f"Fetching branches for repository: {owner}/{repo}")
            try:
                branches_data = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/branches",
                                                           headers)
                simplified_branches = [{"name": b["name"], "commit_sha": b["commit"]["sha"]} for b in branches_data]
                return {
                    "owner": owner, "repository": repo,
                    "total_branches": len(simplified_branches),
                    "branches": simplified_branches, "errors": []
                }
            except aiohttp.ClientResponseError as e:
                branches_http_error_msg = f"HTTP error fetching branches for {owner}/{repo}: {e.status} - {e.message}"
                logger.error(branches_http_error_msg)
                return {
                    "owner": owner, "repository": repo, "total_branches": 0, "branches": [],
                    "errors": [branches_http_error_msg]
                }
            except aiohttp.ClientError as e:
                branches_client_error_msg = f"Network or client error fetching branches for {owner}/{repo}: {e}"
                logger.error(branches_client_error_msg)
                return {
                    "owner": owner, "repository": repo, "total_branches": 0, "branches": [],
                    "errors": [branches_client_error_msg]
                }
            except Exception as e:
                branches_unexpected_error_msg = f"Unexpected error fetching branches for {owner}/{repo}: {e}"
                logger.error(branches_unexpected_error_msg)
                return {
                    "owner": owner, "repository": repo, "total_branches": 0, "branches": [],
                    "errors": [branches_unexpected_error_msg]
                }

        if username and repository_name:
            return await fetch_repo_branches_internal(username, repository_name)
        else:
            logger.info("Fetching branches for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                summary_fetch_error_msg = (f"Failed to retrieve repository summary: "
                                           f"{all_repos_summary_response['errors']}")
                return {"error": summary_fetch_error_msg}

            repositories_list = all_repos_summary_response.get("repositories", [])
            all_repositories_branches_data = []
            total_branches_found_overall = 0
            overall_errors = []

            for repo_summary in repositories_list:
                owner_name = repo_summary.get("owner_name")
                repo_name = repo_summary.get("name")
                if owner_name and repo_name:
                    branch_result = await fetch_repo_branches_internal(owner_name, repo_name)
                    all_repositories_branches_data.append(branch_result)
                    total_branches_found_overall += branch_result["total_branches"]
                    if branch_result["errors"]:
                        overall_errors.extend(branch_result["errors"])
                else:
                    missing_owner_name_error_msg = (f"Skipping repository entry with missing owner or name: "
                                                    f"{repo_summary}")
                    overall_errors.append(missing_owner_name_error_msg)
                    logger.warning(missing_owner_name_error_msg)

            return {
                "total_repositories_processed": len(repositories_list),
                "total_branches_found_overall": total_branches_found_overall,
                "repositories_branches": all_repositories_branches_data,
                "overall_errors": overall_errors if overall_errors else "None"
            }

    @tool
    async def branch_protection(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None,
            branch_name: Optional[str] = None
    ) -> dict:
        """
            Retrieves branch protection rules for a specific branch in a repository,
            for all branches in a specific repository, or for all branches across
            all accessible repositories for the authenticated user.
            Requires 'repo' or 'public_repo' scope.
            Args:
                `username` (str, optional): Repository owner's username.
                `repository_name` (str, optional): Repository name.
                `branch_name` (str, optional): Specific branch name.
            Dict:
                A dictionary with `timestamp`, `total_repositories_processed`, `total_branches_processed`,
                `repositories_with_branch_protection` (list of dicts with `owner`, `repository`, `branches_protection`
                (list of dicts for each branch)), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Failed to retrieve branch protection: {headers['errors']}")
            return {}

        async def single_branch_protection_internal(
                owner: str,
                repository: str,
                branch: str
        ) -> dict:
            logger.info(f"Fetching branch protection for {owner}/{repository}/{branch}")
            async with aiohttp.ClientSession() as session:
                try:
                    protection_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repository}/branches/{branch}/protection"
                    async with session.get(protection_url, headers=headers) as resp:
                        if resp.status == 404:
                            logger.info(f"No branch protection enabled for {owner}/{repository}/{branch}.")
                            return {"branch": branch, "protection_enabled": False, "protection_details": None,
                                    "errors": []}
                        resp.raise_for_status()
                        return {"branch": branch, "protection_enabled": True, "protection_details": await resp.json(),
                                "errors": []}
                except aiohttp.ClientResponseError as e:
                    protection_http_error_msg = (f"HTTP error fetching branch protection for "
                                                 f"{owner}/{repository}/{branch}: {e.status} - {e.message}")
                    logger.error(protection_http_error_msg)
                    return {
                        "branch": branch, "protection_enabled": False, "protection_details": None,
                        "errors": [protection_http_error_msg]
                    }
                except aiohttp.ClientError as e:
                    protection_client_error_msg = (f"Network or client error fetching branch protection for "
                                                   f"{owner}/{repository}/{branch}: {e}")
                    logger.error(protection_client_error_msg)
                    return {
                        "branch": branch, "protection_enabled": False, "protection_details": None,
                        "errors": [protection_client_error_msg]
                    }
                except Exception as e:
                    protection_unexpected_error_msg = (f"Unexpected error fetching branch protection for "
                                                       f"{owner}/{repository}/{branch}: {e}")
                    logger.error(protection_unexpected_error_msg)
                    return {
                        "branch": branch, "protection_enabled": False, "protection_details": None,
                        "errors": [protection_unexpected_error_msg]
                    }

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
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_protection_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching branch protection for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                summary_error_for_protection_msg = (f"Failed to retrieve repository summary: "
                                                    f"{all_repos_summary_response['errors']}")
                all_protection_data["overall_errors"].append(summary_error_for_protection_msg)
                logger.error(summary_error_for_protection_msg)
                return all_protection_data
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_protection_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                missing_owner_name_protection_msg = (f"Skipping repository entry with missing owner or name: "
                                                     f"{repo_summary}")
                all_protection_data["overall_errors"].append(missing_owner_name_protection_msg)
                logger.warning(missing_owner_name_protection_msg)
                continue

            current_repo_entry = {
                "owner": owner_name, "repository": repo_name,
                "branches_protection": [], "repository_errors": []
            }

            branches_list: list[dict] = []
            if branch_name and owner_name == username and repo_name == repository_name:
                logger.info(f"Fetching protection for specific branch: {branch_name} in {owner_name}/{repo_name}")
                branches_list = [{"name": branch_name}]
            else:
                logger.info(f"Fetching all branches for {owner_name}/{repo_name} to check protection.")
                branches_response = await self.repository_branches(owner_name, repo_name)
                if "error" in branches_response and branches_response.get("errors") != "None":
                    branches_fetch_error_msg = (f"Could not fetch branches for {owner_name}/{repo_name}: "
                                                f"{branches_response['errors']}")
                    current_repo_entry["repository_errors"].append(branches_fetch_error_msg)
                    all_protection_data["overall_errors"].append(branches_fetch_error_msg)
                    logger.error(branches_fetch_error_msg)
                else:
                    branches_list = branches_response.get("branches", [])

            for branch_info in branches_list:
                current_branch_name = branch_info.get("name")
                if current_branch_name:
                    protection_result = await single_branch_protection_internal(owner_name, repo_name,
                                                                                current_branch_name)
                    current_repo_entry["branches_protection"].append(protection_result)
                    if protection_result["errors"]:
                        all_protection_data["overall_errors"].extend(protection_result["errors"])
                    all_protection_data["total_branches_processed"] += 1
                else:
                    missing_branch_name_msg = (f"Skipping branch with missing name in {owner_name}/{repo_name}: "
                                               f"{branch_info}")
                    current_repo_entry["repository_errors"].append(missing_branch_name_msg)
                    logger.warning(missing_branch_name_msg)

            all_protection_data["repositories_with_branch_protection"].append(current_repo_entry)

        all_protection_data["overall_errors"] = all_protection_data["overall_errors"] if all_protection_data[
            "overall_errors"] else "None"
        return all_protection_data

    @tool
    async def pull_requests(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None,
            state: str = "all"
    ) -> dict:
        """
            Retrieves a list of pull requests for a specified GitHub repository.
            If no username and repository_name are provided, it fetches pull requests for all
            repositories associated with the authenticated user (and their organizations).
            Requires 'public_repo' or 'repo' scope.
            Args:
                `username` (str, optional): Repository owner's username.
                `repository_name` (str, optional): Repository name.
                `state` (str, optional): State of pull requests ('open', 'closed', 'all').
            Dict:
                If specific repo:
                    A dictionary with `owner`, `repository`, `state_requested`, `total_pull_requests`, `pull_requests`
                    (list of dicts), and `errors`.
                If all accessible repos:
                    A dictionary with `timestamp`, `total_repositories_processed`, `total_pull_requests_found_overall`,
                    `repositories_pull_requests` (list of dicts), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Failed to retrieve pull_requests: {headers['errors']}")
            return {}

        async def _fetch_pull_requests_for_repo(
                owner: str,
                repo: str,
                pr_state: str
        ) -> dict:
            logger.info(f"Fetching {pr_state} pull requests for repository: {owner}/{repo}")
            try:
                pulls_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/pulls"
                params = {"state": pr_state}
                pulls_data = await self.fetch_all_pages(pulls_url, headers, params=params)

                simplified_pulls = [
                    {"id": pr.get("id"), "number": pr.get("number"), "title": pr.get("title"),
                     "state": pr.get("state"), "user_login": pr.get("user", {}).get("login"),
                     "created_at": pr.get("created_at"), "html_url": pr.get("html_url")}
                    for pr in pulls_data
                ]
                return {
                    "owner": owner, "repository": repo, "state_requested": pr_state,
                    "total_pull_requests": len(simplified_pulls),
                    "pull_requests": simplified_pulls, "errors": []
                }
            except aiohttp.ClientResponseError as e:
                pull_request_http_error_msg = (f"HTTP error fetching pull requests for {owner}/{repo}: {e.status} - "
                                               f"{e.message}")
                logger.error(pull_request_http_error_msg)
                return {
                    "owner": owner, "repository": repo, "state_requested": pr_state,
                    "total_pull_requests": 0, "pull_requests": [],
                    "errors": [pull_request_http_error_msg]
                }
            except aiohttp.ClientError as e:
                pull_request_client_error_msg = (f"Network or client error fetching pull requests for "
                                                 f"{owner}/{repo}: {e}")
                logger.error(pull_request_client_error_msg)
                return {
                    "owner": owner, "repository": repo, "state_requested": pr_state,
                    "total_pull_requests": 0, "pull_requests": [],
                    "errors": [pull_request_client_error_msg]
                }
            except Exception as e:
                pull_request_unexpected_error_msg = f"Unexpected error fetching pull requests for {owner}/{repo}: {e}"
                logger.error(pull_request_unexpected_error_msg)
                return {
                    "owner": owner, "repository": repo, "state_requested": pr_state,
                    "total_pull_requests": 0, "pull_requests": [],
                    "errors": [pull_request_unexpected_error_msg]
                }

        all_prs_data = {
            "timestamp": datetime.now().isoformat(), "total_repositories_processed": 0,
            "total_pull_requests_found_overall": 0, "repositories_pull_requests": [], "overall_errors": []
        }

        repositories_to_process: list[dict] = []
        if username and repository_name:
            logger.info(f"Fetching pull requests for specific repository: {username}/{repository_name}")
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_prs_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching pull requests for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                summary_error_for_prs_msg = (f"Failed to retrieve repository summary: "
                                             f"{all_repos_summary_response['errors']}")
                all_prs_data["overall_errors"].append(summary_error_for_prs_msg)
                logger.error(summary_error_for_prs_msg)
                return all_prs_data
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_prs_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                missing_owner_name_pr_msg = f"Skipping repository entry with missing owner or name: {repo_summary}"
                all_prs_data["overall_errors"].append(missing_owner_name_pr_msg)
                logger.warning(missing_owner_name_pr_msg)
                continue

            pr_result = await _fetch_pull_requests_for_repo(owner_name, repo_name, state)
            all_prs_data["repositories_pull_requests"].append(pr_result)
            all_prs_data["total_pull_requests_found_overall"] += pr_result["total_pull_requests"]
            if pr_result["errors"]:
                all_prs_data["overall_errors"].extend(pr_result["errors"])

        all_prs_data["overall_errors"] = all_prs_data["overall_errors"] if all_prs_data["overall_errors"] else "None"
        return all_prs_data

    @tool
    async def get_dependabot_alerts(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None,
            state: str = "open") -> dict:
        """
            Retrieves Dependabot alerts for a specified GitHub repository.
            If no username and repository_name are provided, it fetches alerts for all
            accessible repositories (from the authenticated user and their organizations).
            Requires 'security_events' or 'repo' scope for private repositories, 'public_repo' for public ones.
            Args:
                `username` (str, optional): Repository owner's username.
                `repository_name` (str, optional): Repository name.
                `state` (str, optional): State of alerts ('open', 'dismissed', 'fixed', 'all').
            Dict:
                A dictionary with `timestamp`, `total_repositories_processed`, `total_dependabot_alerts_found_overall`,
                `repositories_dependabot_alerts` (list of dicts for each repo's alerts), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Failed to retrieve get_dependabot alerts: {headers['errors']}")
            return {}

        async def _fetch_dependabot_alerts_for_repo(owner: str, repo: str, alert_state: str) -> dict:
            logger.info(f"Fetching Dependabot alerts for {owner}/{repo} with state: {alert_state}")
            try:
                alerts_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependabot/alerts"
                params = {"state": alert_state}
                alerts_data = await self.fetch_all_pages(alerts_url, headers, params=params)

                simplified_alerts = [
                    {
                        "id": alert.get("number"),
                        "security_vulnerability_package_name": alert.get("security_vulnerability", {}).get("package",
                                                                                                           {}).get(
                            "name"),
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
                    "owner": owner, "repository": repo, "state_requested": alert_state,
                    "total_alerts": len(simplified_alerts),
                    "alerts": simplified_alerts, "errors": []
                }
            except aiohttp.ClientResponseError as e:
                dependabot_http_error_msg = (f"HTTP error fetching Dependabot alerts for '{owner}/{repo}': "
                                             f"{e.status} - {e.message}")
                logger.error(dependabot_http_error_msg)
                return {
                    "owner": owner, "repository": repo, "state_requested": alert_state,
                    "total_alerts": 0, "alerts": [],
                    "errors": [dependabot_http_error_msg]
                }
            except aiohttp.ClientError as e:
                dependabot_client_error_msg = (f"Network or client error fetching Dependabot alerts for "
                                               f"'{owner}/{repo}': {e}")
                logger.error(dependabot_client_error_msg)
                return {
                    "owner": owner, "repository": repo, "state_requested": alert_state,
                    "total_alerts": 0, "alerts": [],
                    "errors": [dependabot_client_error_msg]
                }
            except Exception as e:
                dependabot_unexpected_error_msg = (f"Unexpected error fetching Dependabot alerts for '{owner}/{repo}': "
                                                   f"{e}")
                logger.error(dependabot_unexpected_error_msg)
                return {
                    "owner": owner, "repository": repo, "state_requested": alert_state,
                    "total_alerts": 0, "alerts": [],
                    "errors": [dependabot_unexpected_error_msg]
                }

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
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                summary_error_for_alerts_msg = (f"Failed to retrieve repository summary: "
                                                f"{all_repos_summary_response['errors']}")
                all_alerts_data["overall_errors"].append(summary_error_for_alerts_msg)
                logger.error(summary_error_for_alerts_msg)
                return all_alerts_data
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_alerts_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                missing_owner_name_alert_msg = f"Skipping repository entry with missing owner or name: {repo_summary}"
                all_alerts_data["overall_errors"].append(missing_owner_name_alert_msg)
                logger.warning(missing_owner_name_alert_msg)
                continue

            alert_result = await _fetch_dependabot_alerts_for_repo(owner_name, repo_name, state)
            all_alerts_data["repositories_dependabot_alerts"].append(alert_result)
            all_alerts_data["total_dependabot_alerts_found_overall"] += alert_result["total_alerts"]
            if alert_result["errors"]:
                all_alerts_data["overall_errors"].extend(alert_result["errors"])

        all_alerts_data["overall_errors"] = all_alerts_data["overall_errors"] if all_alerts_data[
            "overall_errors"] else "None"
        return all_alerts_data

    @tool
    async def get_repository_dependabot_secrets(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ) -> dict:
        """
            Retrieves a list of Dependabot secrets (names and metadata, not values) for a specified GitHub repository.
            If no username and repository_name are provided, it fetches secrets for all
            accessible repositories (from the authenticated user and their organizations).
            Requires 'repo' scope.
            Args:
                `username` (str, optional): Repository owner's username.
                `repository_name` (str, optional): Repository name.
            Dict:
                A dictionary with `timestamp`, `total_repositories_processed`, `total_dependabot_secrets_found_overall`,
                `repositories_dependabot_secrets` (list of dicts for each repo's secrets), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Failed to retrieve repository summary: {headers['errors']}")
            return {}

        async def _fetch_secrets_for_repo(owner: str, repo: str) -> dict:
            logger.info(f"Fetching Dependabot secrets for repository: {owner}/{repo}")
            # Create a new session for this operation
            async with aiohttp.ClientSession() as session:
                try:
                    secrets_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependabot/secrets"
                    async with session.get(secrets_url, headers=headers) as response:
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
                            "owner": owner, "repository": repo,
                            "total_secrets": len(simplified_secrets),
                            "secrets": simplified_secrets, "errors": []
                        }
                except aiohttp.ClientResponseError as e:
                    secrets_http_error_msg = f"Error fetching Dependabot secrets for '{owner}/{repo}': {e.status} - {e.message}"
                    logger.error(secrets_http_error_msg)
                    if e.status == 404:
                        return {
                            "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                            "errors": [
                                f"No Dependabot secrets found or repository '{owner}/{repo}' does not exist or is inaccessible."]
                        }
                    elif e.status == 403:
                        return {
                            "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                            "errors": [
                                f"Permission denied to access Dependabot secrets for '{owner}/{repo}'. Check token scopes (requires 'repo' scope)."]
                        }
                    else:
                        return {
                            "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                            "errors": [secrets_http_error_msg]
                        }
                except aiohttp.ClientError as e:
                    secrets_client_error_msg = f"Network or client error fetching Dependabot secrets for '{owner}/{repo}': {e}"
                    logger.error(secrets_client_error_msg)
                    return {
                        "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                        "errors": [secrets_client_error_msg]
                    }
                except Exception as e:
                    secrets_unexpected_error_msg = f"Unexpected error fetching Dependabot secrets for '{owner}/{repo}': {e}"
                    logger.error(secrets_unexpected_error_msg)
                    return {
                        "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                        "errors": [secrets_unexpected_error_msg]
                    }

        all_secrets_data = {
            "timestamp": datetime.now().isoformat(), "total_repositories_processed": 0,
            "total_dependabot_secrets_found_overall": 0, "repositories_dependabot_secrets": [], "overall_errors": []
        }

        repositories_to_process: list[dict] = []
        if username and repository_name:
            logger.info(f"Fetching Dependabot secrets for specific repository: {username}/{repository_name}")
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_secrets_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching Dependabot secrets for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                summary_error_for_secrets_msg = f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}"
                all_secrets_data["overall_errors"].append(summary_error_for_secrets_msg)
                logger.error(summary_error_for_secrets_msg)
                return all_secrets_data
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_secrets_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                missing_owner_name_secret_msg = f"Skipping repository entry with missing owner or name: {repo_summary}"
                all_secrets_data["overall_errors"].append(missing_owner_name_secret_msg)
                logger.warning(missing_owner_name_secret_msg)
                continue

            secret_result = await _fetch_secrets_for_repo(owner_name, repo_name)
            all_secrets_data["repositories_dependabot_secrets"].append(secret_result)
            all_secrets_data["total_dependabot_secrets_found_overall"] += secret_result["total_secrets"]
            if secret_result["errors"]:
                all_secrets_data["overall_errors"].extend(secret_result["errors"])

        all_secrets_data["overall_errors"] = all_secrets_data["overall_errors"] if all_secrets_data[
            "overall_errors"] else "None"
        return all_secrets_data

    @tool
    async def list_repository_dependencies(
            self,
            username: Optional[str] = None,
            repository_name: Optional[str] = None
    ) -> dict:
        """
            Retrieves a list of dependencies for a specified GitHub repository using the dependency manifests API.
            If no username and repository_name are provided, it fetches dependencies for all
            accessible repositories (from the authenticated user and their organizations).
            Requires 'repo' scope.
            Args:
                `username` (str, optional): Repository owner's username.
                `repository_name` (str, optional): Repository name.
            Dict:
                A dictionary with `timestamp`, `total_repositories_processed`, `total_dependencies_found_overall`,
                `repositories_dependencies` (list of dicts for each repo's dependencies), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Failed to retrieve repository summary: {headers['errors']}")
            return {}

        async def _fetch_dependencies_for_repo(owner: str, repo: str) -> dict:
            logger.info(f"Fetching dependencies for repository: {owner}/{repo}")
            async with aiohttp.ClientSession() as session:
                try:
                    dependencies_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependency-graph/sbom"
                    sbom_headers = headers.copy()
                    # GitHub's SBOM API requires a specific Accept header
                    sbom_headers["Accept"] = "application/vnd.github.sbom+json"

                    async with session.get(dependencies_url, headers=sbom_headers) as response:
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
                        "owner": owner, "repository": repo,
                        "total_dependencies_found": len(dependencies_list),
                        "dependencies": dependencies_list, "errors": []
                    }
                except aiohttp.ClientResponseError as e:
                    dependencies_http_error_msg = f"Error fetching dependencies for '{owner}/{repo}': {e.status} - {e.message}"
                    logger.error(dependencies_http_error_msg)
                    if e.status == 404:
                        return {
                            "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                            "errors": [
                                f"Dependency graph for '{owner}/{repo}' not found or feature not enabled. Enable Dependency Graph on the repository settings."]
                        }
                    elif e.status == 403:
                        return {
                            "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                            "errors": [
                                f"Permission denied to access dependency graph for '{owner}/{repo}'. Check token scopes (requires 'repo' scope)."]
                        }
                    else:
                        return {
                            "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                            "errors": [dependencies_http_error_msg]
                        }
                except aiohttp.ClientError as e:
                    dependencies_client_error_msg = f"Network or client error fetching dependencies for '{owner}/{repo}': {e}"
                    logger.error(dependencies_client_error_msg)
                    return {
                        "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                        "errors": [dependencies_client_error_msg]
                    }
                except Exception as e:
                    dependencies_unexpected_error_msg = f"Unexpected error fetching dependencies for '{owner}/{repo}': {e}"
                    logger.error(dependencies_unexpected_error_msg)
                    return {
                        "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                        "errors": [dependencies_unexpected_error_msg]
                    }

        all_dependencies_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_dependencies_found_overall": 0,
            "repositories_dependencies": [],
            "overall_errors": []
        }

        repositories_to_process: list[dict] = []
        if username and repository_name:
            logger.info(f"Fetching dependencies for specific repository: {username}/{repository_name}")
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_dependencies_data["total_repositories_processed"] = 1
        else:
            logger.info("Fetching dependencies for all accessible repositories.")
            all_repos_summary_response = await self.repository_summary()
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                summary_error_for_dependencies_msg = f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}"
                all_dependencies_data["overall_errors"].append(summary_error_for_dependencies_msg)
                logger.error(summary_error_for_dependencies_msg)
                return all_dependencies_data
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_dependencies_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                missing_owner_name_dependency_msg = f"Skipping repository entry with missing owner or name: {repo_summary}"
                all_dependencies_data["overall_errors"].append(missing_owner_name_dependency_msg)
                logger.warning(missing_owner_name_dependency_msg)
                continue

            dependency_result = await _fetch_dependencies_for_repo(owner_name, repo_name)
            all_dependencies_data["repositories_dependencies"].append(dependency_result)
            all_dependencies_data["total_dependencies_found_overall"] += dependency_result["total_dependencies_found"]
            if dependency_result["errors"]:
                all_dependencies_data["overall_errors"].extend(dependency_result["errors"])

        all_dependencies_data["overall_errors"] = all_dependencies_data["overall_errors"] if all_dependencies_data[
            "overall_errors"] else "None"
        return all_dependencies_data

    @tool
    async def get_packages(
            self,
            username: Optional[str] = None
    ) -> dict:
        """
        Retrieves a list of packages for a specified GitHub user.
        If no username is provided, it fetches packages for the authenticated user.
        This function retrieves only general package information (name, type, visibility, creation/update times).
        Requires 'read:packages' scope.
        Args:
            `username` (str, optional): GitHub username.
        Dict:
            A dictionary with `timestamp`, `total_packages_found_overall`,
            `packages_data` (list of dicts with `id`, `name`, `package_type`, `visibility`, `created_at`, `updated_at`,
             `url`), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            logging.error(f"Failed to retrieve repository summary: {headers['errors']}")
            return {}

        all_packages_data = {
            "timestamp": datetime.now().isoformat(),
            "total_packages_found_overall": 0,
            "packages_data": [],
            "overall_errors": []
        }

        try:
            if username:
                logger.info(f"Fetching packages for user: {username}")
                packages_url = f"{GITHUB_API_BASE_URL}/users/{username}/packages"
            else:
                logger.info("Fetching packages for the authenticated user.")
                packages_url = f"{GITHUB_API_BASE_URL}/user/packages"

            packages = await self.fetch_all_pages(packages_url, headers)

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
            packages_http_error_message = f"HTTP error fetching packages: {e.status} - {e.message}"
            if e.status == 404:
                packages_http_error_message = f"User '{username}' not found or no packages available for this user."
            elif e.status == 403:
                packages_http_error_message = (f"Permission denied to access packages. Check token scopes (requires "
                                               f"'read:packages' scope).")
            logger.error(packages_http_error_message)
            all_packages_data["overall_errors"].append(packages_http_error_message)
        except aiohttp.ClientError as e:
            packages_client_error_message = f"Network or client error fetching packages: {e}"
            logger.error(packages_client_error_message)
            all_packages_data["overall_errors"].append(packages_client_error_message)
        except Exception as e:
            packages_unexpected_error_message = f"Unexpected error fetching packages: {e}"
            logger.error(packages_unexpected_error_message)
            all_packages_data["overall_errors"].append(packages_unexpected_error_message)

        all_packages_data["overall_errors"] = all_packages_data["overall_errors"] if all_packages_data[
            "overall_errors"] else "None"
        return all_packages_data
