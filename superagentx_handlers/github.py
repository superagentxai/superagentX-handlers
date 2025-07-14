import os
from datetime import datetime
from typing import List, Dict

import aiohttp

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

GITHUB_API_BASE_URL = "https://api.github.com"


class GitHubHandler(BaseHandler):
    """
    A handler for collecting GitHub GRC (Governance, Risk, and Compliance) evidence.
    """

    def __init__(self, github_token: str = None):
        super().__init__()
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')

        if not self.github_token:
            print("ERROR: GITHUB_TOKEN environment variable not set. Please set it.")

    @tool
    async def common_headers(self) -> dict:
        """
        Explanation:
            Returns common HTTP headers for GitHub API requests.
        Args:
            None.
        Dict:
            `Authorization` (str): GitHub personal access token.
            `Accept` (str): GitHub API version.
        """
        if not self.github_token:
            return {"error": "GitHub token not available. Please set GITHUB_TOKEN environment variable."}
        return {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    @tool
    async def fetch_all_pages(self, url: str, headers: dict, params: dict = None):
        """
        Explanation:
            Fetches all pages from a paginated GitHub API endpoint.
        Args:
            `url` (str): Initial API endpoint URL.
            `headers` (dict): HTTP headers for the request.
            `params` (dict, optional): Query parameters.
        Dict:
            A list of dictionaries representing paginated API response items.
        """
        all_data: List[Dict] = []
        current_url = url
        current_params = params if params is not None else {}

        if "error" in headers:
            # If common_headers returned an error, propagate it
            print(f"Error in fetch_all_pages: {headers['error']}")
            return {"error": headers['error']}

        async with aiohttp.ClientSession() as session:
            while current_url:
                try:
                    async with session.get(
                            url=current_url,
                            headers=headers,
                            params=current_params
                    ) as resp:

                        if resp is None:
                            raise aiohttp.ClientError(f"Received None response for URL: {current_url}")

                        resp.raise_for_status()
                        page_data = await resp.json()

                        if isinstance(page_data, list):
                            all_data.extend(page_data)
                        elif isinstance(page_data, dict):
                            found_list = False
                            for key in ["items", "workflow_runs", "jobs", "artifacts", "secrets", "repositories",
                                        "packages"]:
                                if key in page_data and isinstance(page_data[key], list):
                                    all_data.extend(page_data[key])
                                    found_list = True
                                    break
                            if not found_list and page_data:
                                all_data.append(page_data)

                        next_url = None
                        _link = resp.headers.get('link')
                        if _link:
                            links = _link.split(',')
                            for link in links:
                                if 'rel="next"' in link:
                                    next_url = link.split(';')[0].strip('<>')
                                    break
                        current_url = next_url
                        current_params = {}
                except aiohttp.ClientResponseError as e:

                    print(f"HTTP Error fetching pages from {current_url}: {e.status} - {e.message}")
                    return {"error": f"HTTP Error fetching pages: {e.status} - {e.message}"}
                except aiohttp.ClientError as e:
                    # Catch general aiohttp client errors (e.g., network issues)
                    print(f"Client Error fetching pages from {current_url}: {str(e)}")
                    return {"error": f"Client Error fetching pages: {str(e)}"}
                except Exception as e:
                    # Catch any other unexpected errors
                    print(f"Unexpected error fetching pages from {current_url}: {str(e)}")
                    return {"error": f"Unexpected error fetching pages: {str(e)}"}
        return all_data

    @tool
    async def organization_details(self, org_name: str = None):
        """
        Explanation:
            Retrieves details about a GitHub organization or all organizations for the authenticated user.
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
                    if "error" in orgs:
                        return orgs
                    all_org_details = []
                    for org_data in orgs:
                        details = await self.organization_details(org_name=org_data.get("login"))
                        all_org_details.append(details)
                    return {
                        "organizations": all_org_details,
                        "total_organizations_found": len(all_org_details)
                    }
        except aiohttp.ClientResponseError as e:
            return {"error": f"Error fetching organization details: {e.status} - {e.message}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    @tool
    async def user_details(self, username: str = None):
        """
        Explanation:
            Retrieves public profile information for a GitHub user or the authenticated user.
        Args:
            `username` (str, optional): GitHub username.
        Dict:
            A dictionary with user details (e.g., `login`, `id`, `name`).
            Error dictionary if an issue occurs.
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
            return {"error": f"Error fetching user details: {e.status} - {e.message}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    @tool
    async def get_mfa(self, org_name: str = None):
        """
        Explanation:
            Collects MFA compliance evidence for GitHub organizations.
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
            return headers

        async def single_mfa(current_org_name: str = None, common_headers: dict = None):
            evidence = {
                "organization": current_org_name, "timestamp": datetime.now().isoformat(),
                "organization_details": {}, "total_members": 0, "mfa_enforcement_detected": False,
                "members_with_mfa_enabled": [], "members_with_mfa_disabled": [],
                "all_members_details": [], "errors": []
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

                if "error" in disabled_members_basic:
                    evidence["errors"].append(f"Error fetching 2FA disabled members: {disabled_members_basic['error']}")
                elif disabled_members_basic:
                    evidence["mfa_enforcement_detected"] = True
                    evidence["members_with_mfa_disabled"].extend(
                        [{"login": m["login"], "id": m["id"]} for m in disabled_members_basic])

                all_members_basic = await self.fetch_all_pages(
                    f"{GITHUB_API_BASE_URL}/orgs/{current_org_name}/members", common_headers)

                if "error" in all_members_basic:
                    evidence["errors"].append(f"Error fetching all members: {all_members_basic['error']}")
                else:
                    evidence["total_members"] = len(all_members_basic)

                    disabled_logins = {member["login"] for member in evidence["members_with_mfa_disabled"]}

                    for member_basic in all_members_basic:
                        user_detail = await self.user_details(username=member_basic["login"])
                        detailed_info = {
                            "login": member_basic["login"], "id": member_basic["id"],
                            "mfa_enabled": member_basic["login"] not in disabled_logins
                        }
                        if "error" in user_detail:
                            detailed_info["details_error"] = user_detail["error"]
                            evidence["errors"].append(user_detail["error"])
                        else:
                            detailed_info.update({
                                "name": user_detail.get("name"), "type": user_detail.get("type"),
                                "company": user_detail.get("company"), "email": user_detail.get("email"),
                                "created_at": user_detail.get("created_at"),
                                "updated_at": user_detail.get("updated_at"),
                                "public_repos": user_detail.get("public_repos"),
                                "followers": user_detail.get("followers"),
                            })
                        if detailed_info["mfa_enabled"]:
                            evidence["members_with_mfa_enabled"].append(
                                {"login": member_basic["login"], "id": member_basic["id"]})
                        evidence["all_members_details"].append(detailed_info)

            except aiohttp.ClientResponseError as e:
                evidence["errors"].append(
                    f"Error processing organization '{current_org_name}': {e.status} - {e.message}")
            except Exception as e:
                evidence["errors"].append(f"Error processing organization '{current_org_name}': {str(e)}")

            return evidence

        if org_name:
            return await single_mfa(org_name, headers)
        else:
            all_orgs_response = await self.organization_details(org_name=None)
            if "error" in all_orgs_response:
                return {"error": f"Failed to retrieve organizations: {all_orgs_response['error']}"}

            organizations_list = all_orgs_response.get("organizations", [])
            all_evidence = {
                "timestamp": datetime.now().isoformat(), "total_organizations_processed": len(organizations_list),
                "organizations_get_mfa": [], "errors": []
            }
            for org_detail in organizations_list:
                current_org_name = org_detail.get("login")
                if current_org_name:
                    org_evidence = await single_mfa(current_org_name, headers)
                    all_evidence["organizations_get_mfa"].append(org_evidence)
                    if org_evidence["errors"]:
                        all_evidence["errors"].extend(org_evidence["errors"])
                else:
                    all_evidence["errors"].append(f"Skipping organization entry with missing login: {org_detail}")
            return all_evidence

    @tool
    async def repository_summary(self, entity_name: str = None):
        """
        Explanation:
            Retrieves a summary of repositories for a user or organization.
        Args:
            `entity_name` (str, optional): GitHub username or organization name.
        Dict:
            A dictionary with `total_repositories_found` (int), `repositories` (list of dicts with `name`, `status`, `owner_type`, `owner_name`), and `errors` (list or "None").
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        all_repos_summary: List[Dict] = []
        errors: List[str] = []
        processed_repo_full_names = set()

        async def process_repositories(repos_list: List[Dict], source_type: str, source_name: str = None):

            if isinstance(repos_list, dict) and "error" in repos_list:
                errors.append(
                    f"Error processing repositories from {source_type} '{source_name}': {repos_list['error']}")
                return

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
        except aiohttp.ClientResponseError as e:
            errors.append(f"Network or API error during repository fetching: {e.status} - {e.message}")
        except Exception as e:
            errors.append(f"Unexpected error during repository fetching: {str(e)}")

        return {
            "total_repositories_found": len(all_repos_summary),
            "repositories": all_repos_summary,
            "errors": errors if errors else "None"
        }

    @tool
    async def list_organization_members(self, org_name: str = None, role: str = None,
                                        filter_2fa: bool = False):
        """
        Explanation:
            Retrieves a list of members for a GitHub organization(s).
        Args:
            `org_name` (str, optional): Name of the GitHub organization.
            `role` (str, optional): Filters members by role ('all', 'admin', 'member').
            `filter_2fa` (bool, optional): If True, returns only members with 2FA disabled.
        Dict:
            A dictionary where keys are organization names and values contain `members` (list of dicts with `member_id`, `name`) and `count` (int).
            Error dictionary if an issue occurs.
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

                if "error" in members_full_data:
                    all_organization_members[current_org_name] = {"error": members_full_data["error"]}
                    continue

                if filter_2fa:
                    disabled_members_check = await self.fetch_all_pages(
                        f"{GITHUB_API_BASE_URL}/orgs/{current_org_name}/members?filter=2fa_disabled", headers
                    )

                    if "error" in disabled_members_check:
                        all_organization_members[current_org_name] = {"error": disabled_members_check["error"]}
                        continue

                    disabled_logins = {member["login"] for member in disabled_members_check}
                    members_to_process = [
                        member for member in members_full_data
                        if member["login"] in disabled_logins
                    ]
                else:
                    members_to_process = members_full_data

                filtered_members = [
                    {"member_id": member.get("id"), "name": member.get("login")}
                    for member in members_to_process
                ]

                all_organization_members[current_org_name] = {
                    "members": filtered_members,
                    "count": len(filtered_members)
                }

            except aiohttp.ClientResponseError as e:
                all_organization_members[current_org_name] = {
                    "error": f"Error fetching members for {current_org_name}: {e.status} - {e.message}"
                }
            except Exception as e:
                all_organization_members[current_org_name] = {
                    "error": f"Unexpected error fetching members for {current_org_name}: {str(e)}"
                }

        if not all_organization_members and not orgs_to_process:
            return {"error": "No organizations found or the provided organization does not exist."}
        return all_organization_members

    @tool
    async def repository_branches(self, username: str = None,
                                  repository_name: str = None) -> dict:
        """
        Explanation:
            Retrieves a list of branches for a GitHub repository.
        Args:
            `username` (str, optional): Repository owner's username.
            `repository_name` (str, optional): Repository name.
        Dict:
            If specific repo:
                A dictionary with `owner`, `repository`, `total_branches`, `branches` (list of dicts with `name`, `commit_sha`), and `errors`.
            If all accessible repos:
                A dictionary with `total_repositories_processed`, `total_branches_found_overall`, `repositories_branches` (list of dicts), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        async def fetch_repo_branches(owner: str, repo: str) -> dict:
            try:
                branches_data = await self.fetch_all_pages(f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/branches",
                                                           headers)

                if "error" in branches_data:
                    return {
                        "owner": owner, "repository": repo, "total_branches": 0, "branches": [],
                        "errors": [branches_data["error"]]
                    }

                simplified_branches = [{"name": b["name"], "commit_sha": b["commit"]["sha"]} for b in branches_data]
                return {
                    "owner": owner, "repository": repo,
                    "total_branches": len(simplified_branches),
                    "branches": simplified_branches, "errors": []
                }
            except aiohttp.ClientResponseError as e:
                return {
                    "owner": owner, "repository": repo, "total_branches": 0, "branches": [],
                    "errors": [f"Error fetching branches: {e.status} - {e.message}"]
                }
            except Exception as e:
                return {
                    "owner": owner, "repository": repo, "total_branches": 0, "branches": [],
                    "errors": [f"Unexpected error fetching branches: {str(e)}"]
                }

        if username and repository_name:
            return await fetch_repo_branches(username, repository_name)
        else:
            all_repos_summary_response = await self.repository_summary(entity_name=None)

            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                return {"error": f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}"}

            if isinstance(all_repos_summary_response, dict) and "error" in all_repos_summary_response:
                return all_repos_summary_response

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
        Explanation:
            Retrieves branch protection rules for GitHub repository branches.
        Args:
            `username` (str, optional): Repository owner's username.
            `repository_name` (str, optional): Repository name.
            `branch_name` (str, optional): Specific branch name.
        Dict:
            A dictionary with `timestamp`, `total_repositories_processed`, `total_branches_processed`,
            `repositories_with_branch_protection` (list of dicts with `owner`, `repository`, `branches_protection` (list of dicts for each branch)), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        async def single_branch_protection(owner: str, repository: str, branch: str):
            try:
                protection_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repository}/branches/{branch}/protection"
                async with aiohttp.ClientSession() as session:
                    async with session.get(protection_url, headers=headers) as response:
                        if response.status == 404:
                            return {"branch": branch, "protection_enabled": False, "protection_details": None,
                                    "errors": []}
                        response.raise_for_status()
                        return {"branch": branch, "protection_enabled": True,
                                "protection_details": await response.json(), "errors": []}
            except aiohttp.ClientResponseError as e:
                return {
                    "branch": branch, "protection_enabled": False, "protection_details": None,
                    "errors": [f"Error fetching protection: {e.status} - {e.message}"]
                }
            except Exception as e:
                return {
                    "branch": branch, "protection_enabled": False, "protection_details": None,
                    "errors": [f"Unexpected error fetching protection: {str(e)}"]
                }

        all_protection_data = {
            "timestamp": datetime.now().isoformat(), "total_repositories_processed": 0,
            "total_branches_processed": 0, "repositories_with_branch_protection": [], "overall_errors": []
        }

        repositories_to_process = []
        if username and repository_name:
            repositories_to_process.append({"owner_name": username, "name": repository_name})
            all_protection_data["total_repositories_processed"] = 1
        else:
            all_repos_summary_response = await self.repository_summary(entity_name=None)

            if "error" in all_repos_summary_response and all_repos_summary_response["errors"] != "None":
                all_protection_data["overall_errors"].append(
                    f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}")
                all_protection_data["overall_errors"] = all_protection_data["overall_errors"] if all_protection_data[
                    "overall_errors"] else "None"
                return all_protection_data

            if isinstance(all_repos_summary_response, dict) and "error" in all_repos_summary_response:
                all_protection_data["overall_errors"].append(all_repos_summary_response["error"])
                all_protection_data["overall_errors"] = all_protection_data["overall_errors"] if all_protection_data[
                    "overall_errors"] else "None"
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
            if branch_name and owner_name == username and repo_name == repository_name:
                branches_list = [{"name": branch_name}]
            else:
                branches_response = await self.repository_branches(owner_name, repo_name)

                if "error" in branches_response and branches_response.get("errors") != "None":
                    current_repo_entry["repository_errors"].append(
                        f"Could not fetch branches for {owner_name}/{repo_name}: {branches_response['errors']}")
                    all_protection_data["overall_errors"].extend(current_repo_entry["repository_errors"])

                elif isinstance(branches_response, dict) and "error" in branches_response:
                    current_repo_entry["repository_errors"].append(
                        f"Could not fetch branches for {owner_name}/{repo_name}: {branches_response['error']}")
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
        Explanation:
            Retrieves a list of pull requests for a GitHub repository.
        Args:
            `username` (str, optional): Repository owner's username.
            `repository_name` (str, optional): Repository name.
            `state` (str, optional): State of pull requests ('open', 'closed', 'all').
        Dict:
            If specific repo:
                A dictionary with `owner`, `repository`, `state_requested`, `total_pull_requests`, `pull_requests` (list of dicts), and `errors`.
            If all accessible repos:
                A dictionary with `timestamp`, `total_repositories_processed`, `total_pull_requests_found_overall`, `repositories_pull_requests` (list of dicts), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        async def _fetch_pull_requests_for_repo(owner: str, repo: str, pr_state: str):
            try:
                pulls_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/pulls"
                params = {"state": pr_state}
                pulls_data = await self.fetch_all_pages(pulls_url, headers, params=params)

                # Check for errors from fetch_all_pages
                if "error" in pulls_data:
                    return {
                        "owner": owner, "repository": repo, "state_requested": pr_state,
                        "total_pull_requests": 0, "pull_requests": [],
                        "errors": [pulls_data["error"]]
                    }

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
                return {
                    "owner": owner, "repository": repo, "state_requested": pr_state,
                    "total_pull_requests": 0, "pull_requests": [],
                    "errors": [f"Error fetching pull requests: {e.status} - {e.message}"]
                }
            except Exception as e:
                return {
                    "owner": owner, "repository": repo, "state_requested": pr_state,
                    "total_pull_requests": 0, "pull_requests": [],
                    "errors": [f"Unexpected error fetching pull requests: {str(e)}"]
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
                all_prs_data["overall_errors"] = all_prs_data["overall_errors"] if all_prs_data[
                    "overall_errors"] else "None"
                return all_prs_data

            if isinstance(all_repos_summary_response, dict) and "error" in all_repos_summary_response:
                all_prs_data["overall_errors"].append(all_repos_summary_response["error"])
                all_prs_data["overall_errors"] = all_prs_data["overall_errors"] if all_prs_data[
                    "overall_errors"] else "None"
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
        Explanation:
            Retrieves Dependabot alerts for a GitHub repository.
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
            return headers

        async def _fetch_dependabot_alerts_for_repo(owner: str, repo: str, alert_state: str):
            try:
                alerts_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependabot/alerts"
                params = {"state": alert_state}
                alerts_data = await self.fetch_all_pages(alerts_url, headers, params=params)

                # Check for errors from fetch_all_pages
                if "error" in alerts_data:
                    return {
                        "owner": owner, "repository": repo, "state_requested": alert_state,
                        "total_alerts": 0, "alerts": [],
                        "errors": [alerts_data["error"]]
                    }

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
            except aiohttp.ClientResponseError as e:
                status_code = getattr(e, 'status', 'N/A')
                error_message = getattr(e, 'message', str(e))
                return {
                    "owner": owner, "repository": repo, "state_requested": alert_state,
                    "total_alerts": 0, "alerts": [],
                    "errors": [
                        f"Error fetching Dependabot alerts for '{owner}/{repo}': {status_code} - {error_message}"]
                }
            except Exception as e:
                return {
                    "owner": owner, "repository": repo, "state_requested": alert_state,
                    "total_alerts": 0, "alerts": [],
                    "errors": [f"Unexpected error fetching Dependabot alerts for '{owner}/{repo}': {str(e)}"]
                }

        all_alerts_data = {
            "timestamp": datetime.now().isoformat(), "total_repositories_processed": 0,
            "total_dependabot_alerts_found_overall": 0, "repositories_dependabot_alerts": [], "overall_errors": []
        }

        if username and repository_name:
            repositories_to_process = [{"owner_name": username, "name": repository_name}]
        else:
            all_repos_summary_response = await self.repository_summary(entity_name=None)

            if all_repos_summary_response.get("error") and all_repos_summary_response["errors"] != "None":
                all_alerts_data["overall_errors"].append(
                    f"Failed to retrieve repository summary: {all_repos_summary_response['errors']}")
                all_alerts_data["overall_errors"] = all_alerts_data["overall_errors"] or "None"
                return all_alerts_data

            if isinstance(all_repos_summary_response, dict) and "error" in all_repos_summary_response:
                all_alerts_data["overall_errors"].append(all_repos_summary_response["error"])
                all_alerts_data["overall_errors"] = all_alerts_data["overall_errors"] or "None"
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
            if alert_result["errors"]:
                all_alerts_data["overall_errors"].extend(alert_result["errors"])

        all_alerts_data["overall_errors"] = all_alerts_data["overall_errors"] or "None"
        return all_alerts_data

    @tool
    async def get_repository_dependabot_secrets(self, username: str = None,
                                                repository_name: str = None):
        """
        Explanation:
            Retrieves metadata about Dependabot secrets for a GitHub repository.
        Args:
            `username` (str, optional): Repository owner's username.
            `repository_name` (str, optional): Repository name.
        Dict:
            A dictionary with `timestamp`, `total_repositories_processed`, `total_dependabot_secrets_found_overall`,
            `repositories_dependabot_secrets` (list of dicts for each repo's secrets), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        async def _fetch_secrets_for_repo(owner: str, repo: str, headers: dict):
            try:
                secrets_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/dependabot/secrets"
                async with aiohttp.ClientSession() as session:
                    async with session.get(secrets_url, headers=headers) as response:
                        if response.status == 404:
                            return {
                                "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                                "errors": ["No Dependabot secrets found or repository inaccessible."]
                            }
                        elif response.status == 403:
                            return {
                                "owner": owner, "repository": repo, "total_secrets": 0, "secrets": [],
                                "errors": ["Permission denied to access Dependabot secrets. Check token scopes."]
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

        headers = await self.common_headers()
        if "error" in headers:
            return {"error": headers["error"]}

        all_secrets_data = {
            "timestamp": datetime.now().isoformat(), "total_repositories_processed": 0,
            "total_dependabot_secrets_found_overall": 0, "repositories_dependabot_secrets": [], "overall_errors": []
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

            if isinstance(all_repos_summary_response, dict) and "error" in all_repos_summary_response:
                all_secrets_data["overall_errors"].append(all_repos_summary_response["error"])
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
                                           repository_name: str = None):
        """
        Explanation:
            Retrieves a list of dependencies for a GitHub repository using the Dependency Graph.
        Args:
            `username` (str, optional): Repository owner's username.
            `repository_name` (str, optional): Repository name.
        Dict:
            A dictionary with `timestamp`, `total_repositories_processed`, `total_dependencies_found_overall`,
            `repositories_dependencies` (list of dicts for each repo's dependencies), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

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
                                "errors": ["Dependency graph not found or feature not enabled."]
                            }
                        elif response.status == 403:
                            return {
                                "owner": owner, "repository": repo, "total_dependencies_found": 0, "dependencies": [],
                                "errors": ["Permission denied to access dependency graph. Check token scopes."]
                            }

                        response.raise_for_status()
                        sbom_data = await response.json()

                        dependencies_list = []
                        if ("sbom" in sbom_data and "packages" in sbom_data["sbom"] and
                                isinstance(sbom_data["sbom"]["packages"], list)):
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

        headers = await self.common_headers()
        if "error" in headers:
            return {"error": headers["error"]}

        all_dependencies_data = {
            "timestamp": datetime.now().isoformat(), "total_repositories_processed": 0,
            "total_dependencies_found_overall": 0, "repositories_dependencies": [], "overall_errors": []
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

            if isinstance(all_repos_summary_response, dict) and "error" in all_repos_summary_response:
                all_dependencies_data["overall_errors"].append(all_repos_summary_response["error"])
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
        Explanation:
            Retrieves a list of packages for a GitHub user.
        Args:
            `username` (str, optional): GitHub username.
        Dict:
            A dictionary with `timestamp`, `total_packages_found_overall`,
            `packages_data` (list of dicts with `id`, `name`, `package_type`, `visibility`, `created_at`, `updated_at`, `url`), and `overall_errors`.
        """
        headers = await self.common_headers()
        if "error" in headers:
            return headers

        all_packages_data = {
            "timestamp": datetime.now().isoformat(), "total_packages_found_overall": 0,
            "packages_data": [], "overall_errors": []
        }

        try:
            packages_url = ""
            if username:
                packages_url = f"{GITHUB_API_BASE_URL}/users/{username}/packages"
            else:
                packages_url = f"{GITHUB_API_BASE_URL}/user/packages"
            packages = await self.fetch_all_pages(packages_url, headers)

            if "error" in packages:
                all_packages_data["overall_errors"].append(packages["error"])
                all_packages_data["overall_errors"] = all_packages_data["overall_errors"] if all_packages_data[
                    "overall_errors"] else "None"
                return all_packages_data

            simplified_packages = []
            for package in packages:
                simplified_packages.append({
                    "id": package.get("id"), "name": package.get("name"),
                    "package_type": package.get("package_type"), "visibility": package.get("visibility"),
                    "created_at": package.get("created_at"), "updated_at": package.get("updated_at"),
                    "url": package.get("html_url")
                })

            all_packages_data["packages_data"] = simplified_packages
            all_packages_data["total_packages_found_overall"] = len(simplified_packages)

        except aiohttp.ClientResponseError as e:
            status_code = getattr(e, 'status', 'N/A')
            error_message = getattr(e, 'message', str(e))

            if status_code == 404:
                error_message = f"User '{username}' not found or no packages available."
            elif status_code == 403:
                error_message = "Permission denied to access packages. Check token scopes."
            else:
                error_message = f"Error fetching packages: {status_code} - {error_message}"

            all_packages_data["overall_errors"].append(error_message)
        except Exception as e:
            all_packages_data["overall_errors"].append(f"Unexpected error fetching packages: {str(e)}")

        all_packages_data["overall_errors"] = all_packages_data["overall_errors"] if all_packages_data[
            "overall_errors"] else "None"
        return all_packages_data


tools = [
    "get_mfa",
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
