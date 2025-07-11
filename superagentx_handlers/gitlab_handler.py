import os
import logging
import gitlab
from gitlab.exceptions import GitlabError, GitlabGetError 
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

# Custom exceptions for GitLab handler, mirroring other cloud handlers
class GitLabClientInitFailed(Exception): pass
class GitLabListUsersFailed(Exception): pass
class GitLabListProjectsFailed(Exception): pass
class GitLabListGroupsFailed(Exception): pass
class GitLabListIssuesFailed(Exception): pass
class GitLabListMergeRequestsFailed(Exception): pass
class GitLabListHooksFailed(Exception): pass
class GitLabListPipelinesFailed(Exception): pass
class GitLabListBranchesFailed(Exception): pass
class GitLabListBranchProtectionRulesFailed(Exception): pass
class GitLabListPackagesFailed(Exception): pass


class GitlabHandler(BaseHandler):
    """
    A handler class for managing interactions with a GitLab instance.
    This class provides methods to retrieve various GitLab resources,
    facilitating auditing and visibility into projects, users, groups, and CI/CD.
    """

    def __init__(
            self,
            private_token: str | None = None,
            url: str | None = None
    ):
        super().__init__()
        if not url:
            url = "https://gitlab.com"
        self.token = private_token or os.getenv("GITLAB_PRIVATE_TOKEN")
        if not self.token:
            raise ValueError("No GitLab private token provided or set in GITLAB_PRIVATE_TOKEN.")

        try:
            self.gl = gitlab.Gitlab(url, private_token=self.token)
            self.gl.auth() # Authenticate the session
            logger.debug(f"Connected to GitLab as: {self.gl.user.username}")
        except GitlabError as e:
            logger.error(f"Error initializing GitLab client: {e}", exc_info=True)
            raise GitLabClientInitFailed(f"Failed to initialize GitLab Handler: {e}")

    @tool
    async def get_user_profile(self) -> dict:
        """
        Asynchronously collects the GitLab user profile of the authenticated user,
        including admin status, 2FA status, and basic metadata.
        Use this to retrieve current user's identity and security posture.
        """
        try:
            user = self.gl.user # Basic current user info
            full_user = self.gl.users.get(user.id) # Get full user object for more details
            return {
                "id": full_user.id,
                "username": full_user.username,
                "name": full_user.name,
                "email": getattr(full_user, "email", None),
                "is_admin": getattr(full_user, "is_admin", False),
                "two_factor_enabled": getattr(full_user, "two_factor_enabled", None),
                "state": full_user.state,
                "created_at": full_user.created_at,
                "web_url": full_user.web_url
            }
        except GitlabError as e:
            logger.error(f"Error getting user profile: {e}", exc_info=True)
            raise GitLabListUsersFailed(f"Failed to get user profile: {e}")

    @tool
    async def get_projects(self) -> list[dict]:
        """
        Asynchronously retrieves a list of all GitLab projects owned by the authenticated user.
        Includes visibility, default branch, and last activity.
        """
        try:
            projects_data = []
            for project in self.gl.projects.list(owned=True, all=True):
                projects_data.append({
                    "id": project.id,
                    "name": project.name,
                    "visibility": project.visibility,
                    "default_branch": project.default_branch,
                    "last_activity_at": project.last_activity_at,
                    "web_url": project.web_url
                })
            logger.debug(f"Got {len(projects_data)} projects.")
            return projects_data
        except GitlabError as e:
            logger.error(f"Error getting projects: {e}", exc_info=True)
            raise GitLabListProjectsFailed(f"Failed to list projects: {e}")

    @tool
    async def get_groups_and_members(self) -> list[dict]:
        """
        Asynchronously lists GitLab groups owned by the authenticated user and their members.
        Includes group details, member usernames, and access levels.
        """
        groups_data = []
        try:
            for group in self.gl.groups.list(owned=True, all=True):
                members_data = []
                try:
                    for m in group.members.list(all=True): # List all members for the group
                        members_data.append({
                            "username": m.username,
                            "access_level": m.access_level,
                            "email": m.email if hasattr(m, "email") else None,
                        })
                except GitlabError as e:
                    logger.warning(f"Could not retrieve members for group '{group.name}' (ID: {group.id}): {e}")
                    members_data = [] # Ensure members is an empty list on error

                groups_data.append({
                    "group_name": group.name,
                    "group_id": group.id,
                    "web_url": group.web_url,
                    "members": members_data,
                })
            logger.debug(f"Got {len(groups_data)} groups and their members.")
            return groups_data
        except GitlabError as e:
            logger.error(f"Error getting groups and members: {e}", exc_info=True)
            raise GitLabListGroupsFailed(f"Failed to list groups and members: {e}")

    @tool
    async def get_issues(self, project_id: int | None = None) -> list[dict]:
        """
        Asynchronously retrieves GitLab issues. If a project_id is provided, it fetches issues
        for that specific project. Otherwise, it fetches all issues assigned to the current user.
        Includes title, state, creation time, and labels.

        Parameter:
           project_id (int, optional): The ID of the project to retrieve issues from. If None,
                                       issues assigned to the current user are returned.
        """
        issues_data = []
        try:
            if project_id:
                project = self.gl.projects.get(project_id)
                issues = project.issues.list(all=True)
                logger.debug(f"Got issues for project ID {project_id}.")
            else:
                issues = self.gl.issues.list(scope='assigned_to_me', all=True)
                logger.debug("Got issues assigned to current user.")

            for issue in issues:
                issues_data.append({
                    "id": issue.id,
                    "title": issue.title,
                    "state": issue.state,
                    "created_at": issue.created_at,
                    "labels": issue.labels,
                    "web_url": issue.web_url,
                    "project_id": issue.project_id
                })
            return issues_data
        except GitlabGetError as e:
            logger.warning(f"Project ID {project_id} not found or inaccessible for issues: {e}")
            return [] # Return empty list if project not found/inaccessible
        except GitlabError as e:
            logger.error(f"Error getting issues: {e}", exc_info=True)
            raise GitLabListIssuesFailed(f"Failed to list issues: {e}")

    @tool
    async def get_merge_requests(self, project_id: int | None = None) -> list[dict]:
        """
        Asynchronously collects GitLab merge requests. If a project_id is provided, it fetches MRs
        for that specific project. Otherwise, it fetches all MRs assigned to the current user.
        Includes title, source/target branches, and state.

        Parameter:
           project_id (int, optional): The ID of the project to retrieve merge requests from. If None,
                                       MRs assigned to the current user are returned.
        """
        merge_requests_data = []
        try:
            if project_id:
                project = self.gl.projects.get(project_id)
                mrs = project.mergerequests.list(all=True)
                logger.debug(f"Got merge requests for project ID {project_id}.")
            else:
                mrs = self.gl.mergerequests.list(scope='assigned_to_me', all=True)
                logger.debug("Got merge requests assigned to current user.")

            for mr in mrs:
                merge_requests_data.append({
                    "id": mr.id,
                    "title": mr.title,
                    "state": mr.state,
                    "source_branch": mr.source_branch,
                    "target_branch": mr.target_branch,
                    "web_url": mr.web_url,
                    "project_id": mr.project_id
                })
            return merge_requests_data
        except GitlabGetError as e:
            logger.warning(f"Project ID {project_id} not found or inaccessible for merge requests: {e}")
            return [] # Return empty list if project not found/inaccessible
        except GitlabError as e:
            logger.error(f"Error getting merge requests: {e}", exc_info=True)
            raise GitLabListMergeRequestsFailed(f"Failed to list merge requests: {e}")

    @tool
    async def get_hooks(self, project_id: int) -> list[dict]:
        """
        Asynchronously fetches all webhooks configured for the specified GitLab project.
        This helps in auditing integrations and potential data exfiltration points.

        Parameter:
           project_id (int): The ID of the GitLab project to retrieve webhooks from.
        """
        hooks_data = []
        try:
            project = self.gl.projects.get(project_id)
            for hook in project.hooks.list(all=True):
                hooks_data.append({
                    "id": hook.id,
                    "url": hook.url,
                    "push_events": hook.push_events,
                    "merge_requests_events": hook.merge_requests_events,
                    "tag_push_events": hook.tag_push_events,
                    "enable_ssl_verification": hook.enable_ssl_verification,
                    "created_at": hook.created_at,
                })
            logger.debug(f"Got {len(hooks_data)} hooks for project ID {project_id}.")
            return hooks_data
        except GitlabGetError as e:
            logger.warning(f"Project ID {project_id} not found or inaccessible for hooks: {e}")
            return []
        except GitlabError as e:
            logger.error(f"Error getting hooks for project ID {project_id}: {e}", exc_info=True)
            raise GitLabListHooksFailed(f"Failed to list hooks: {e}")

    @tool
    async def get_pipelines(self, project_id: int) -> list[dict]:
        """
        Asynchronously retrieves recent pipeline runs for a specific GitLab project.
        This method provides an overview of the CI/CD execution history for a project.

        Parameter:
           project_id (int): The ID of the GitLab project to retrieve pipelines from.
        """
        pipelines_data = []
        try:
            project = self.gl.projects.get(project_id)
            for pipeline in project.pipelines.list(all=True): # Use all=True to get all pages
                pipelines_data.append({
                    "id": pipeline.id,
                    "status": pipeline.status,
                    "ref": pipeline.ref,
                    "sha": pipeline.sha,
                    "web_url": pipeline.web_url,
                    "created_at": pipeline.created_at,
                    "updated_at": pipeline.updated_at,
                })
            logger.debug(f"Got {len(pipelines_data)} pipelines for project ID {project_id}.")
            return pipelines_data
        except GitlabGetError as e:
            logger.warning(f"Project ID {project_id} not found or inaccessible for pipelines: {e}")
            return []
        except GitlabError as e:
            logger.error(f"Error getting pipelines for project ID {project_id}: {e}", exc_info=True)
            raise GitLabListPipelinesFailed(f"Failed to list pipelines: {e}")

    @tool
    async def get_branches(self, project_id: int) -> list[dict]:
        """
        Asynchronously retrieves a list of all branches for a specific GitLab project.
        Includes branch name, protected status, and last commit details.

        Parameter:
           project_id (int): The ID of the GitLab project to retrieve branches from.
        """
        branches_data = []
        try:
            project = self.gl.projects.get(project_id)
            for branch in project.branches.list(all=True):
                branches_data.append({
                    "name": branch.name,
                    "protected": branch.protected,
                    "default": branch.default,
                    "can_push": branch.can_push,
                    "commit_id": branch.commit['id'] if branch.commit else None,
                    "commit_short_id": branch.commit['short_id'] if branch.commit else None,
                    "commit_message": branch.commit['message'] if branch.commit else None,
                })
            logger.debug(f"Got {len(branches_data)} branches for project ID {project_id}.")
            return branches_data
        except GitlabGetError as e:
            logger.warning(f"Project ID {project_id} not found or inaccessible for branches: {e}")
            return []
        except GitlabError as e:
            logger.error(f"Error getting branches for project ID {project_id}: {e}", exc_info=True)
            raise GitLabListBranchesFailed(f"Failed to list branches: {e}")

    @tool
    async def get_branch_protection_rules(self, project_id: int) -> list[dict]:
        """
        Asynchronously retrieves a list of all branch protection rules for a specific GitLab project.
        This is crucial for auditing code integrity and access controls.

        Parameter:
           project_id (int): The ID of the GitLab project to retrieve branch protection rules from.
        """
        protected_branches_data = []
        try:
            project = self.gl.projects.get(project_id)
            for protected_branch in project.protected_branches.list(all=True):
                protected_branches_data.append({
                    "id": protected_branch.id,
                    "name": protected_branch.name,
                    "push_access_levels": [
                        {"access_level": al.access_level, "access_level_description": al.access_level_description}
                        for al in protected_branch.push_access_levels
                    ],
                    "merge_access_levels": [
                        {"access_level": al.access_level, "access_level_description": al.access_level_description}
                        for al in protected_branch.merge_access_levels
                    ],
                    "allow_force_push": protected_branch.allow_force_push,
                    "code_owner_approval_required": protected_branch.code_owner_approval_required,
                })
            logger.debug(f"Got {len(protected_branches_data)} branch protection rules for project ID {project_id}.")
            return protected_branches_data
        except GitlabGetError as e:
            logger.warning(f"Project ID {project_id} not found or inaccessible for branch protection rules: {e}")
            return []
        except GitlabError as e:
            logger.error(f"Error getting branch protection rules for project ID {project_id}: {e}", exc_info=True)
            raise GitLabListBranchProtectionRulesFailed(f"Failed to list branch protection rules: {e}")

    @tool
    async def get_packages(self, project_id: int) -> list[dict]:
        """
        Asynchronously retrieves a list of all packages published to the package registry
        for a specific GitLab project. This helps in auditing software supply chain assets.

        Parameter:
           project_id (int): The ID of the GitLab project to retrieve packages from.
        """
        packages_data = []
        try:
            project = self.gl.projects.get(project_id)
            # GitLab API for packages is project.packages, but it's nested under project.
            # The list() method is available on project.packages
            for package in project.packages.list(all=True):
                packages_data.append({
                    "id": package.id,
                    "name": package.name,
                    "version": package.version,
                    "package_type": package.package_type,
                    "created_at": package.created_at,
                    "status": package.status,
                    "web_path": package.web_path,
                })
            logger.debug(f"Got {len(packages_data)} packages for project ID {project_id}.")
            return packages_data
        except GitlabGetError as e:
            logger.warning(f"Project ID {project_id} not found or inaccessible for packages: {e}")
            return []
        except GitlabError as e:
            logger.error(f"Error getting packages for project ID {project_id}: {e}", exc_info=True)
            raise GitLabListPackagesFailed(f"Failed to list packages: {e}")

