import os
from datetime import datetime
from typing import List, Dict

import aiohttp
import requests
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

GITHUB_API_BASE_URL = "https://api.github.com"


class GitHubHandler(BaseHandler):
    """
    A handler to collect GitHub GRC (Governance, Risk, and Compliance) evidence,
    focusing on MFA, organizational details, and repository data.
    """

    def __init__(self, github_token: str = None):
        super().__init__()
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')

    @tool
    async def common_headers(self) -> dict:
        """Returns common headers including Authorization."""
        if not self.github_token:
            return {"error": "GitHub token not available."}
        return {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    @tool
    async def fetch_all_pages(self, url: str, headers: dict, params: dict = None):
        """Fetches all pages from a paginated GitHub API endpoint."""
        all_data: List[Dict] = []
        current_url = url
        current_params = params if params is not None else {}

        while current_url:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url=current_url,
                    headers=headers,
                    params=current_params
                ) as resp:
                    await resp.raise_for_status()
                    page_data = await resp.json()

                    # Handle different API response structures
                    if isinstance(page_data, list):
                        all_data.extend(page_data)
                    elif isinstance(page_data, dict):
                        # Check common keys for lists within dicts
                        found_list = False
                        for key in ["items", "workflow_runs", "jobs", "artifacts", "secrets", "repositories", "packages"]:
                            if key in page_data and isinstance(page_data[key], list):
                                all_data.extend(page_data[key])
                                found_list = True
                                break
                        if not found_list and page_data:  # If it's a single object response
                            all_data.append(page_data)

                    # Get next page URL from 'link' header
                    next_url = None
                    _link = resp.headers.get('link')
                    if _link:
                        links = _link.split(',')
                        for link in links:
                            if 'rel="next"' in link:
                                next_url = link.split(';')[0].strip('<>')
                                break
                    current_url = next_url
                    current_params = {}  # Clear params for subsequent paginated requests
        return all_data

    @tool
    async def organization_details(self, org_name: str = None):
        """
        Retrieves details for a specific GitHub organization, or all organizations
        associated with the authenticated user if no org_name is provided.
        Requires 'read:org' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        try:
            async with aiohttp.ClientSession() as session:
                if org_name:
                    org_url = f"{GITHUB_API_BASE_URL}/orgs/{org_name}"
                    async with session.get(org_url, headers=headers) as resp:
                        resp.raise_for_status()
                        return await resp.json()
                else:
                    orgs = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/user/orgs", headers)
                    all_org_details = []
                    for org_data in orgs:
                        # Reusing the same session for performance
                        details = await self.organization_details(org_name=org_data.get("login"), session=session)
                        all_org_details.append(details)
                    return {
                        "organizations": all_org_details,
                        "total_organizations_found": len(all_org_details)
                    }
        except aiohttp.ClientResponseError as e:
            return {
                "error": f"Error fetching organization details: {e.status} - {e.message}"
            }
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}"
            }

    @tool
    async def user_details(self, username: str = None):
        """
        Retrieves profile information for a GitHub user.
        If no username is provided, retrieves details for the authenticated user.
        Requires 'read:user' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        user_url = f"{GITHUB_API_BASE_URL}/users/{username}" if username else f"{GITHUB_API_BASE_URL}/user"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(user_url, headers=headers) as resp:
                    resp.raise_for_status()
                    return await resp.json()

        except aiohttp.ClientResponseError as e:
            return {
                "error": f"Error fetching user details: {e.status} - {e.message}"
            }
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}"
            }

    @tool
    async def mfa_evidence(self, org_name: str = None):
        """
        Collects MFA compliance evidence and organizational details.
        If org_name is not provided, it collects evidence for all organizations
        associated with the authenticated user.
        Requires 'read:org' and 'read:user' scopes.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        @tool
        async def single_mfa_evidence(current_org_name: str = None, common_headers: dict = None):
            evidence = {
                "organization": current_org_name,
                "timestamp": datetime.now().isoformat(),
                "organization_details": {},
                "total_members": 0,
                "mfa_enforcement_detected": False,
                "members_with_mfa_enabled": [],
                "members_with_mfa_disabled": [],
                "all_members_details": [],
                "errors": []
            }

            try:
                org_details = await self.organization_details(org_name=current_org_name)
                if "error" in org_details:
                    evidence["errors"].append(org_details["error"])
                else:
                    evidence["organization_details"] = org_details

                disabled_members_basic = await self.fetch_all_pages(
                    f"{GITHUB_API_BASE_URL}/orgs/{current_org_name}/members?filter=2fa_disabled", common_headers
                )
                if disabled_members_basic:
                    evidence["mfa_enforcement_detected"] = True
                    evidence["members_with_mfa_disabled"].extend(
                        [{"login": m["login"], "id": m["id"]} for m in disabled_members_basic])

                all_members_basic = await self.fetch_all_pages(
                    f"{GITHUB_API_BASE_URL}/orgs/{current_org_name}/members", common_headers)
                evidence["total_members"] = len(all_members_basic)

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
                        evidence["errors"].append(user_detail["error"])
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
                evidence["errors"].append(
                    f"Error processing organization '{current_org_name}': {e.status} - {e.message}"
                )
            except Exception as e:
                evidence["errors"].append(
                    f"Error processing organization '{current_org_name}': {str(e)}"
                )

            return evidence

        if org_name:
            return await single_mfa_evidence(org_name, headers)
        else:
            all_orgs_response = await self.organization_details(org_name=None)
            if "error" in all_orgs_response:
                return {"error": f"Failed to retrieve organizations: {all_orgs_response['error']}"}

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
                    org_evidence = await single_mfa_evidence(current_org_name, headers)
                    all_evidence["organizations_mfa_evidence"].append(org_evidence)
                    if org_evidence["errors"]:
                        all_evidence["errors"].extend(org_evidence["errors"])
                else:
                    all_evidence["errors"].append(f"Skipping organization entry with missing login: {org_detail}")
            return all_evidence

    @tool
    async def repository_summary(self, entity_name: str= None):
        """
        Retrieves a summary of repositories for a specific user or organization.
        If no entity_name is provided, it fetches repositories for the authenticated user
        and all organizations they belong to.
        Requires 'repo' scope for private repositories, 'read:org' for organization repos.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        all_repos_summary: List[Dict] = []
        errors: List[str] = []
        processed_repo_full_names = set()

        @tool
        async def process_repositories(repos_list: List[Dict], source_type: str, source_name: str=None):
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
                user_details = await self.user_details(username=entity_name)
                if "error" not in user_details and user_details.get("type") == "User":
                    user_repos = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/users/{entity_name}/repos",
                                                            headers)
                    await process_repositories(user_repos, "User", entity_name)
                else:
                    org_details = await self.organization_details(org_name=entity_name)
                    if "error" not in org_details and org_details.get("type") == "Organization":
                        org_repos = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/orgs/{entity_name}/repos",
                                                               headers)
                        await process_repositories(org_repos, "Organization", entity_name)
                    else:
                        errors.append(f"Entity '{entity_name}' not found as a user or organization.")
            else:
                auth_user_details = await self.user_details()
                if "error" not in auth_user_details:
                    auth_username = auth_user_details.get("login")
                    if auth_username:
                        user_repos = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/user/repos", headers)
                        await process_repositories(user_repos, "Authenticated User", auth_username)
                    else:
                        errors.append("Could not retrieve login for authenticated user.")
                else:
                    errors.append(f"Error fetching authenticated user details: {auth_user_details['error']}")

                all_orgs_response = await self.organization_details(org_name=None)
                if "error" not in all_orgs_response:
                    for org_data in all_orgs_response.get("organizations", []):
                        org_name_from_list = org_data.get("login")
                        if org_name_from_list:
                            org_repos = await self.fetch_all_pages(
                                f"{GITHUB_API_BASE_URL}/orgs/{org_name_from_list}/repos", headers)
                            await process_repositories(org_repos, "Organization", org_name_from_list)
                        else:
                            errors.append(f"Skipping organization entry with missing login: {org_data}")
                else:
                    errors.append(f"Error fetching organizations for authenticated user: {all_orgs_response['error']}")
        except aiohttp.clientRequestException as e:
            errors.append(
                f"Network or API error during repository fetching: {e.response.status_code if hasattr(e.response, 'status_code') else 'N/A'} - {e.response.text if hasattr(e.response, 'text') else str(e)}")

        return {
            "total_repositories_found": len(all_repos_summary),
            "repositories": all_repos_summary,
            "errors": errors if errors else "None"
        }

    @tool
    async def list_organization_members(self, org_name: str = None, role: str= None,
                                        filter_2fa: bool = False):
        """
        Retrieves a list of members for a given GitHub organization(s),
        returning only member ID, name (login), and total count per organization.
        If no org_name is provided, it fetches members for all organizations
        the authenticated user belongs to.
        Requires 'read:org' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        all_organization_members: Dict[str, Dict] = {}

        orgs_to_process: List[Dict] = []
        if org_name:
            org_details_response = await self.organization_details(org_name=org_name)
            if "error" in org_details_response:
                return org_details_response
            orgs_to_process.append(org_details_response)
        else:
            orgs_response = await self.organization_details()
            if "error" in orgs_response:
                return orgs_response
            orgs_to_process = orgs_response.get("organizations", [])

        for org_data in orgs_to_process:
            current_org_name = org_data.get("login")
            if not current_org_name:
                continue

            members_url = f"{GITHUB_API_BASE_URL}/orgs/{current_org_name}/members"
            params = {}
            if role:
                if role not in ['all', 'admin', 'member']:
                    all_organization_members[current_org_name] = {
                        "error": f"Invalid role specified. Must be 'all', 'admin', or 'member'."
                    }
                    continue
                params['role'] = role

            try:
                members_full_data = await self.fetch_all_pages(members_url, headers, params=params)

                # Filter for 2FA if requested
                if filter_2fa:
                    members_to_process = [
                        member for member in members_full_data
                        if 'two_factor_authentication_enabled' in member and not member[
                            'two_factor_authentication_enabled']
                    ]
                else:
                    members_to_process = members_full_data

                # Extract only id and login
                filtered_members = [
                    {"member_id": member.get("id"), "name": member.get("login")}
                    for member in members_to_process
                ]

                all_organization_members[current_org_name] = {
                    "members": filtered_members,
                    "count": len(filtered_members)
                }

            except aiohttp.ClientRequestException as e:
                all_organization_members[current_org_name] = {
                    "error": f"Error fetching members for {current_org_name}: {e.response.status_code if hasattr(e.response, 'status_code') else 'N/A'} - {e.response.text if hasattr(e.response, 'text') else str(e)}"
                }

        if not all_organization_members and not orgs_to_process:
            return {
                "error": "No organizations found for the authenticated user, or the provided organization does not exist."
            }
        return all_organization_members

    @tool
    async def repository_branches(self, username: str= None,
                                  repository_name: str = None) -> dict:
        """
        Retrieves a list of branches for a specified GitHub repository.
        If no username and repository_name are provided, it fetches branches for all
        repositories associated with the authenticated user (and their organizations).
        Requires 'public_repo' or 'repo' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        @tool
        async def fetch_repo_branches(owner: str, repo: str) -> dict:
            try:
                branches_data = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/branches",
                                                           headers)
                simplified_branches = [{"name": b["name"], "commit_sha": b["commit"]["sha"]} for b in branches_data]
                return {
                    "owner": owner, "repository": repo,
                    "total_branches": len(simplified_branches),
                    "branches": simplified_branches, "errors": []
                }
            except aiohttp.clientRequestException as e:
                return {
                    "owner": owner, "repository": repo, "total_branches": 0, "branches": [],
                    "errors": [
                        f"Error fetching branches: {e.response.status_code if hasattr(e.response, 'status_code') else 'N/A'} - {e.response.text if hasattr(e.response, 'text') else str(e)}"]
                }

        if username and repository_name:
            return await fetch_repo_branches(username, repository_name)
        else:
            all_repos_summary_response = await self.repository_summary(entity_name=None)
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                return {"error": f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}"}

            repositories_list = all_repos_summary_response.get("repositories", [])
            all_repositories_branches_data = []
            total_branches_found_overall = 0
            overall_errors = []

            for repo_summary in repositories_list:
                owner_name = repo_summary.get("owner_name")
                repo_name = repo_summary.get("name")
                if owner_name and repo_name:
                    branch_result = await fetch_repo_branches(owner_name, repo_name)
                    all_repositories_branches_data.append(branch_result)
                    total_branches_found_overall += branch_result["total_branches"]
                    if branch_result["errors"]:
                        overall_errors.extend(branch_result["errors"])
                else:
                    overall_errors.append(f"Skipping repository entry with missing owner or name: {repo_summary}")

            return {
                "total_repositories_processed": len(repositories_list),
                "total_branches_found_overall": total_branches_found_overall,
                "repositories_branches": all_repositories_branches_data,
                "overall_errors": overall_errors if overall_errors else "None"
            }

    @tool
    async def branch_protection(self, username: str = None, repository_name: str = None,
                                branch_name: str = None):
        """
        Retrieves branch protection rules for a specific branch in a repository,
        for all branches in a specific repository, or for all branches across
        all accessible repositories for the authenticated user.
        Requires 'repo' or 'public_repo' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        @tool
        async def single_branch_protection(owner: str, repository: str, branch: str):
            try:
                protection_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repository}/branches/{branch}/protection"
                response = requests.get(protection_url, headers=headers)
                if response.status_code == 404:  # Protection not enabled
                    return {"branch": branch, "protection_enabled": False, "protection_details": None, "errors": []}
                response.raise_for_status()
                return {"branch": branch, "protection_enabled": True, "protection_details": response.json(),
                        "errors": []}
            except aiohttp.clientRequestException as e:
                return {
                    "branch": branch, "protection_enabled": False, "protection_details": None,
                    "errors": [
                        f"Error fetching protection: {e.response.status_code if hasattr(e.response, 'status_code') else 'N/A'} - {e.response.text if hasattr(e.response, 'text') else str(e)}"]
                }

        all_protection_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_branches_processed": 0,
            "repositories_with_branch_protection": [],
            "overall_errors": []
        }

        repositories_to_process = []
        if username and repository_name:
            # Specific repository scenario
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_protection_data["total_repositories_processed"] = 1
        else:
            # All accessible repositories scenario
            all_repos_summary_response = await self.repository_summary(entity_name=None)
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                all_protection_data["overall_errors"].append(
                    f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}")
                return all_protection_data
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_protection_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                all_protection_data["overall_errors"].append(
                    f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            current_repo_entry = {
                "owner": owner_name, "repository": repo_name,
                "branches_protection": [], "repository_errors": []
            }

            branches_list = []
            if branch_name and owner_name == username and repo_name == repository_name:  # If specific branch was requested in the first place
                branches_list = [{"name": branch_name}]
            else:  # Fetch all branches for this repo
                branches_response = await self.repository_branches(owner_name, repo_name)
                if "error" in branches_response and branches_response.get("errors") != "None":
                    current_repo_entry["repository_errors"].append(
                        f"Could not fetch branches for {owner_name}/{repo_name}: {branches_response['errors']}")
                    all_protection_data["overall_errors"].extend(current_repo_entry["repository_errors"])
                else:
                    branches_list = branches_response.get("branches", [])

            for branch_info in branches_list:
                current_branch_name = branch_info.get("name")
                if current_branch_name:
                    protection_result = await single_branch_protection(owner_name, repo_name, current_branch_name)
                    current_repo_entry["branches_protection"].append(protection_result)
                    if protection_result["errors"]:
                        all_protection_data["overall_errors"].extend(protection_result["errors"])
                    all_protection_data["total_branches_processed"] += 1
                else:
                    current_repo_entry["repository_errors"].append(
                        f"Skipping branch with missing name in {owner_name}/{repo_name}: {branch_info}")

            all_protection_data["repositories_with_branch_protection"].append(current_repo_entry)

        all_protection_data["overall_errors"] = all_protection_data["overall_errors"] if all_protection_data[
            "overall_errors"] else "None"
        return all_protection_data

    @tool
    async def pull_requests(self, username: str = None, repository_name: str = None,
                            state: str = "all") -> dict:
        """
        Retrieves a list of pull requests for a specified GitHub repository.
        If no username and repository_name are provided, it fetches pull requests for all
        repositories associated with the authenticated user (and their organizations).
        Requires 'public_repo' or 'repo' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        @tool
        async def _fetch_pull_requests_for_repo(owner: str, repo: str, pr_state: str):
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
            except aiohttp.clientRequestException as e:
                return {
                    "owner": owner, "repository": repo, "state_requested": pr_state,
                    "total_pull_requests": 0, "pull_requests": [],
                    "errors": [
                        f"Error fetching pull requests: {e.response.status_code if hasattr(e.response, 'status_code') else 'N/A'} - {e.response.text if hasattr(e.response, 'text') else str(e)}"]
                }

        all_prs_data = {
            "timestamp": datetime.now().isoformat(), "total_repositories_processed": 0,
            "total_pull_requests_found_overall": 0, "repositories_pull_requests": [], "overall_errors": []
        }

        repositories_to_process = []
        if username and repository_name:
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_prs_data["total_repositories_processed"] = 1
        else:
            all_repos_summary_response = await self.repository_summary(entity_name=None)
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                all_prs_data["overall_errors"].append(
                    f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}")
                return all_prs_data
            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_prs_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                all_prs_data["overall_errors"].append(
                    f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            pr_result = await _fetch_pull_requests_for_repo(owner_name, repo_name, state)
            all_prs_data["repositories_pull_requests"].append(pr_result)
            all_prs_data["total_pull_requests_found_overall"] += pr_result["total_pull_requests"]
            if pr_result["errors"]:
                all_prs_data["overall_errors"].extend(pr_result["errors"])

        all_prs_data["overall_errors"] = all_prs_data["overall_errors"] if all_prs_data["overall_errors"] else "None"
        return all_prs_data

    @tool
    async def get_dependabot_alerts(self, username: str = None, repository_name: str = None,
                                    state: str = "open"):
        """
        Retrieves Dependabot alerts for a specified GitHub repository.
        If no username and repository_name are provided, it fetches alerts for all
        accessible repositories (from the authenticated user and their organizations).
        Requires 'security_events' or 'repo' scope for private repositories, 'public_repo' for public ones.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        async def _fetch_dependabot_alerts_for_repo(owner: str, repo: str, alert_state: str):
            try:
                alerts_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependabot/alerts"
                params = {"state": alert_state}
                alerts_data = await self.fetch_all_pages(alerts_url, headers, params=params)

                simplified_alerts = [
                    {
                        "id": alert.get("number"),
                        "security_vulnerability": alert.get("security_vulnerability", {}).get("package", {}).get(
                            "name"),
                        "severity": alert.get("security_vulnerability", {}).get("severity"),
                        "state": alert.get("state"),
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
            except aiohttp.clientRequestException as e:
                status_code = getattr(e.response, 'status_code', 'N/A')
                error_text = getattr(e.response, 'text', str(e))
                return {
                    "owner": owner, "repository": repo, "state_requested": alert_state,
                    "total_alerts": 0, "alerts": [],
                    "errors": [f"Error fetching Dependabot alerts for '{owner}/{repo}': {status_code} - {error_text}"]
                }

        all_alerts_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_dependabot_alerts_found_overall": 0,
            "repositories_dependabot_alerts": [],
            "overall_errors": []
        }

        if username and repository_name:
            repositories_to_process = [{"owner_name": username, "name": repository_name}]
        else:
            all_repos_summary_response = await self.repository_summary(entity_name=None)
            if all_repos_summary_response.get("error") and all_repos_summary_response["errors"] != "None":
                all_alerts_data["overall_errors"].append(
                    f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}")
                return all_alerts_data
            repositories_to_process = all_repos_summary_response.get("repositories", [])

        all_alerts_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                all_alerts_data["overall_errors"].append(
                    f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            alert_result = await _fetch_dependabot_alerts_for_repo(owner_name, repo_name, state)
            all_alerts_data["repositories_dependabot_alerts"].append(alert_result)
            all_alerts_data["total_dependabot_alerts_found_overall"] += alert_result["total_alerts"]
            all_alerts_data["overall_errors"].extend(alert_result["errors"])

        all_alerts_data["overall_errors"] = all_alerts_data["overall_errors"] or "None"
        return all_alerts_data

    @tool
    async def get_repository_dependabot_secrets(self, username: str = None,
                                                repository_name: str= None):
        """
        Retrieves a list of Dependabot secrets (names and metadata, not values) for a specified GitHub repository.
        If no username and repository_name are provided, it fetches secrets for all
        accessible repositories (from the authenticated user and their organizations).
        Requires 'repo' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        @tool
        async def _fetch_secrets_for_repo(owner: str, repo: str, headers: dict):
            try:
                secrets_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependabot/secrets"
                async with aiohttp.ClientSession() as session:
                    async with session.get(secrets_url, headers=headers) as response:
                        if response.status == 404:
                            return {
                                "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                                "errors": [
                                    f"No Dependabot secrets found or repository '{owner}/{repo}' does not exist or is inaccessible."]
                            }
                        elif response.status == 403:
                            return {
                                "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                                "errors": [
                                    f"Permission denied to access Dependabot secrets for '{owner}/{repo}'. Check token scopes (requires 'repo' scope)."]
                            }

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
                            "secrets": simplified_secrets,
                            "errors": []
                        }

            except aiohttp.ClientResponseError as e:
                return {
                    "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                    "errors": [f"Error fetching Dependabot secrets for '{owner}/{repo}': {e.status} - {e.message}"]
                }
            except Exception as e:
                return {
                    "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                    "errors": [f"Unexpected error fetching secrets for '{owner}/{repo}': {str(e)}"]
                }

        # Main logic
        headers = await self.common_headers()
        if "error" in headers:
            return {"error": headers["error"]}

        all_secrets_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_dependabot_secrets_found_overall": 0,
            "repositories_dependabot_secrets": [],
            "overall_errors": []
        }

        repositories_to_process = []

        if username and repository_name:
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_secrets_data["total_repositories_processed"] = 1
        else:
            all_repos_summary_response = await self.repository_summary(entity_name=None)
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                all_secrets_data["overall_errors"].append(
                    f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}")
                all_secrets_data["overall_errors"] = all_secrets_data["overall_errors"] or "None"
                return all_secrets_data

            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_secrets_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                all_secrets_data["overall_errors"].append(
                    f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            secret_result = await _fetch_secrets_for_repo(owner_name, repo_name, headers)
            all_secrets_data["repositories_dependabot_secrets"].append(secret_result)
            all_secrets_data["total_dependabot_secrets_found_overall"] += secret_result["total_secrets"]
            if secret_result["errors"]:
                all_secrets_data["overall_errors"].extend(secret_result["errors"])

        all_secrets_data["overall_errors"] = all_secrets_data["overall_errors"] or "None"
        return all_secrets_data

    @tool
    async def list_repository_dependencies(self, username: str = None,
                                           repository_name:str = None):
        """
        Retrieves a list of dependencies for a specified GitHub repository using the dependency manifests API.
        If no username and repository_name are provided, it fetches dependencies for all
        accessible repositories (from the authenticated user and their organizations).
        Requires 'repo' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        @tool
        async def _fetch_dependencies_for_repo(owner: str, repo: str, headers: dict):
            try:
                dependencies_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependency-graph/sbom"
                sbom_headers = headers.copy()
                sbom_headers["Accept"] = "application/vnd.github.sbom+json"

                async with aiohttp.ClientSession() as session:
                    async with session.get(dependencies_url, headers=sbom_headers) as response:
                        if response.status == 404:
                            return {
                                "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                                "errors": [
                                    f"Dependency graph for '{owner}/{repo}' not found or feature not enabled. Enable Dependency Graph on the repository settings."]
                            }
                        elif response.status == 403:
                            return {
                                "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                                "errors": [
                                    f"Permission denied to access dependency graph for '{owner}/{repo}'. Check token scopes (requires 'repo' scope)."]
                            }

                        response.raise_for_status()
                        sbom_data = await response.json()

                        dependencies_list = []
                        if (
                                "sbom" in sbom_data and
                                "packages" in sbom_data["sbom"] and
                                isinstance(sbom_data["sbom"]["packages"], list)
                        ):
                            for package in sbom_data["sbom"]["packages"]:
                                dependencies_list.append({
                                    "name": package.get("name"),
                                    "version": package.get("version"),
                                    "spdx_id": package.get("SPDXID"),
                                    "license": package.get("licenseConcluded"),
                                    "purl": (
                                        package.get("externalRefs", [])[0].get("locator")
                                        if package.get("externalRefs") else None
                                    )
                                })

                        return {
                            "owner": owner, "repository": repo,
                            "total_dependencies_found": len(dependencies_list),
                            "dependencies": dependencies_list,
                            "errors": []
                        }

            except aiohttp.ClientResponseError as e:
                return {
                    "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                    "errors": [f"Error fetching dependencies for '{owner}/{repo}': {e.status} - {e.message}"]
                }
            except Exception as e:
                return {
                    "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                    "errors": [f"Unexpected error fetching dependencies for '{owner}/{repo}': {str(e)}"]
                }

        # ---- Main logic to process all repositories ----
        headers = await self.common_headers()
        if "error" in headers:
            return {"error": headers["error"]}

        all_dependencies_data = {
            "timestamp": datetime.now().isoformat(),
            "total_repositories_processed": 0,
            "total_dependencies_found_overall": 0,
            "repositories_dependencies": [],
            "overall_errors": []
        }

        repositories_to_process = []

        if username and repository_name:
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_dependencies_data["total_repositories_processed"] = 1
        else:
            all_repos_summary_response = await self.repository_summary(entity_name=None)
            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                all_dependencies_data["overall_errors"].append(
                    f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}")
                all_dependencies_data["overall_errors"] = all_dependencies_data["overall_errors"] or "None"
                return all_dependencies_data

            repositories_to_process = all_repos_summary_response.get("repositories", [])
            all_dependencies_data["total_repositories_processed"] = len(repositories_to_process)

        for repo_summary in repositories_to_process:
            owner_name = repo_summary.get("owner_name")
            repo_name = repo_summary.get("name")
            if not (owner_name and repo_name):
                all_dependencies_data["overall_errors"].append(
                    f"Skipping repository entry with missing owner or name: {repo_summary}")
                continue

            dependency_result = await _fetch_dependencies_for_repo(owner_name, repo_name, headers)
            all_dependencies_data["repositories_dependencies"].append(dependency_result)
            all_dependencies_data["total_dependencies_found_overall"] += dependency_result["total_dependencies_found"]
            if dependency_result["errors"]:
                all_dependencies_data["overall_errors"].extend(dependency_result["errors"])

        all_dependencies_data["overall_errors"] = all_dependencies_data["overall_errors"] or "None"
        return all_dependencies_data

    @tool
    async def get_packages(self, username: str = None):
        """
        Retrieves a list of packages for a specified GitHub user.
        If no username is provided, it fetches packages for the authenticated user.
        This function retrieves only general package information (name, type, visibility, creation/update times).
        Requires 'read:packages' scope.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        all_packages_data = {
            "timestamp": datetime.now().isoformat(),
            "total_packages_found_overall": 0,
            "packages_data": [],
            "overall_errors": []
        }

        try:
            packages_url = ""
            if username:
                # Fetch packages for a specific user
                packages_url = f"{GITHUB_API_BASE_URL}/users/{username}/packages"
            else:
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

        except aiohttp.clientRequestException as e:
            status_code = getattr(e.response, 'status_code', 'N/A')
            error_text = getattr(e.response, 'text', str(e))

            if status_code == 404:
                error_message = f"User '{username}' not found or no packages available for this user."
            elif status_code == 403:
                error_message = f"Permission denied to access packages. Check token scopes (requires 'read:packages' scope)."
            else:
                error_message = f"Error fetching packages: {status_code} - {error_text}"

            all_packages_data["overall_errors"].append(error_message)

        all_packages_data["overall_errors"] = all_packages_data["overall_errors"] if all_packages_data[
            "overall_errors"] else "None"
        return all_packages_data


tools = [
    "mfa_evidence",
    "repository_summary",
    "list_organization_members",
    "repository_branches",
    "branch_protection",
    "pull_requests",
    "get_dependabot_alerts",
    "get_repository_dependabot_secrets",
    "list_repository_dependencies",
    "get_packages"
]
