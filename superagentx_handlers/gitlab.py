import logging
import os
from typing import Optional

import gitlab
import gitlab.v4
import gitlab.v4.objects
from gitlab.exceptions import GitlabError, GitlabGetError
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


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

        self.gl = gitlab.Gitlab(url, private_token=self.token)
        self.gl.auth()
        logger.debug(f"Connected to GitLab as: {self.gl.user.username}")

    @tool
    async def get_user_profile(self) -> dict:
        """
        Asynchronously collects the full GitLab user profile of the authenticated user.
        This includes all available details from the GitLab API for the user.
        """
        try:
            user = self.gl.user
            full_user = self.gl.users.get(user.id)
            return full_user.attributes
        except GitlabError as e:
            logger.error(f"Error getting user profile: {e}", exc_info=True)
            return {}

    @tool
    async def get_projects(self) -> list[dict]:
        """
        Asynchronously retrieves a list of all GitLab projects owned by the authenticated user,
        returning all available details for each project.
        """
        try:
            projects_data = [p.attributes for p in self.gl.projects.list(owned=True, all=True)]
            logger.debug(f"Got {len(projects_data)} projects.")
            return projects_data
        except GitlabError as e:
            logger.error(f"Error getting projects: {e}", exc_info=True)
            return [] # Return empty list on error

    @tool
    async def get_groups_and_members(self) -> list[dict]:
        """
        Asynchronously lists GitLab groups owned by the authenticated user and their full member details.
        Returns all available attributes for each group and its members.
        """
        groups_data = []
        try:
            for group in self.gl.groups.list(owned=True, all=True):
                group_attrs = group.attributes
                try:
                    members_data = [m.attributes for m in group.members.list(all=True)]
                except GitlabError as e:
                    logger.warning(
                        f"Could not retrieve members for group '{group_attrs.get('name', group.id)}' "
                        f"(ID: {group.id}): {e}"
                    )
                    members_data = []
                group_attrs["members"] = members_data
                groups_data.append(group_attrs)
            logger.debug(f"Got {len(groups_data)} groups and their members.")
        except GitlabError as e:
            logger.error(f"Error getting groups and members: {e}", exc_info=True)
        return groups_data

    # --- Helper methods for project-specific data ---
    @staticmethod
    async def _get_project_issues_data(project_obj: gitlab.v4.objects.Project) -> list[dict]:
        """Helper to get full issues data for a single project."""
        return [issue.attributes for issue in project_obj.issues.list(all=True)]

    @staticmethod
    async def _get_project_merge_requests_data(project_obj: gitlab.v4.objects.Project) -> list[dict]:
        """Helper to get full merge requests data for a single project."""
        return [mr.attributes for mr in project_obj.mergerequests.list(all=True)]

    @staticmethod
    async def _get_project_hooks_data(project_obj: gitlab.v4.objects.Project) -> list[dict]:
        """Helper to get full hooks data for a single project."""
        return [hook.attributes for hook in project_obj.hooks.list(all=True)]

    @staticmethod
    async def _get_project_pipelines_data(project_obj: gitlab.v4.objects.Project) -> list[dict]:
        """Helper to get full pipelines data for a single project."""
        return [pipeline.attributes for pipeline in project_obj.pipelines.list(all=True)]

    @staticmethod
    async def _get_project_branches_data(project_obj: gitlab.v4.objects.Project) -> list[dict]:
        """Helper to get full branches data for a single project."""
        return [branch.attributes for branch in project_obj.branches.list(all=True)]

    @staticmethod
    async def _get_project_branch_protection_rules_data(project_obj: gitlab.v4.objects.Project) -> list[dict]:
        """Helper to get full branch protection rules data for a single project."""
        return [protected_branch.attributes for protected_branch in project_obj.protected_branches.list(all=True)]

    @staticmethod
    async def _get_project_packages_data(project_obj: gitlab.v4.objects.Project) -> list[dict]:
        """Helper to get full packages data for a single project."""
        return [package.attributes for package in project_obj.packages.list(all=True)]

    # --- Refactored Tool methods ---

    @tool
    async def get_issues(self, project_id: Optional[int] = None) -> list[dict]:
        """
        Asynchronously retrieves GitLab issues. If a project_id is provided, it fetches issues
        for that specific project. If project_id is None, it fetches issues across all accessible projects.
        Returns all available attributes for each issue.

        Parameter:
           project_id (int, optional): The ID of the GitLab project to retrieve issues from.
                                       If None, issues from all accessible projects are returned.
        """
        all_issues_data = []
        try:
            if project_id:
                try:
                    project = self.gl.projects.get(project_id)
                    all_issues_data.extend(await self._get_project_issues_data(project))
                    logger.debug(f"Got issues for project ID {project_id}.")
                except GitlabGetError as e:
                    logger.warning(f"Project ID {project_id} not found or inaccessible for issues: {e}")
            else:
                for project_summary in await self.get_projects():
                    try:
                        project = self.gl.projects.get(project_summary['id'])
                        all_issues_data.extend(await self._get_project_issues_data(project))
                        logger.debug(f"Got issues for project ID {project_summary['id']} (all projects mode).")
                    except GitlabGetError as e:
                        logger.warning(f"Skipping project ID {project_summary['id']} (issues): {e}")
        except GitlabError as e:
            logger.error(f"Error getting issues: {e}", exc_info=True)
        return all_issues_data

    @tool
    async def get_merge_requests(self, project_id: Optional[int] = None) -> list:
        """
        Asynchronously collects GitLab merge requests. If a project_id is provided, it fetches MRs
        for that specific project. If project_id is None, it fetches MRs across all accessible projects.
        Returns all available attributes for each merge request.

        Parameter:
           project_id (int, optional): The ID of the GitLab project to retrieve merge requests from.
           If None, MRs from all accessible projects are returned.
        """
        all_mrs_data = []
        try:
            if project_id:
                try:
                    project = self.gl.projects.get(project_id)
                    all_mrs_data.extend(await self._get_project_merge_requests_data(project))
                    logger.debug(f"Got merge requests for project ID {project_id}.")
                except GitlabGetError as e:
                    logger.warning(f"Project ID {project_id} not found or inaccessible for merge requests: {e}")
            else:
                for project_summary in await self.get_projects():
                    try:
                        project = self.gl.projects.get(project_summary['id'])
                        all_mrs_data.extend(await self._get_project_merge_requests_data(project))
                        logger.debug(f"Got merge requests for project ID {project_summary['id']} (all projects mode).")
                    except GitlabGetError as e:
                        logger.warning(f"Skipping project ID {project_summary['id']} (merge requests): {e}")
        except GitlabError as e:
            logger.error(f"Error getting merge requests: {e}", exc_info=True)
        return all_mrs_data

    @tool
    async def get_hooks(self, project_id: Optional[int] = None) -> list:
        """
        Asynchronously fetches webhooks configured for a specific GitLab project.
        If project_id is None, it fetches hooks from all accessible projects.
        Returns all available attributes for each webhook.

        Parameter:
           project_id (int, optional): The ID of the GitLab project to retrieve webhooks from.
                                       If None, hooks from all accessible projects are returned.
        """
        all_hooks_data = []
        try:
            if project_id:
                try:
                    project = self.gl.projects.get(project_id)
                    all_hooks_data.extend(await self._get_project_hooks_data(project))
                    logger.debug(f"Got hooks for project ID {project_id}.")
                except GitlabGetError as e:
                    logger.warning(f"Project ID {project_id} not found or inaccessible for hooks: {e}")
            else:
                for project_summary in await self.get_projects():
                    try:
                        project = self.gl.projects.get(project_summary['id'])
                        all_hooks_data.extend(await self._get_project_hooks_data(project))
                        logger.debug(f"Got hooks for project ID {project_summary['id']} (all projects mode).")
                    except GitlabGetError as e:
                        logger.warning(f"Skipping project ID {project_summary['id']} (hooks): {e}")
        except GitlabError as e:
            logger.error(f"Error getting hooks: {e}", exc_info=True)
        return all_hooks_data

    @tool
    async def get_pipelines(self, project_id: Optional[int] = None) -> list:
        """
        Asynchronously retrieves recent pipeline runs for a specific GitLab project.
        If project_id is None, it fetches pipelines from all accessible projects.
        Returns all available attributes for each pipeline.

        Parameter:
           project_id (int, optional): The ID of the GitLab project to retrieve pipelines from.
                                       If None, pipelines from all accessible projects are returned.
        """
        all_pipelines_data = []
        try:
            if project_id:
                try:
                    project = self.gl.projects.get(project_id)
                    all_pipelines_data.extend(await self._get_project_pipelines_data(project))
                    logger.debug(f"Got pipelines for project ID {project_id}.")
                except GitlabGetError as e:
                    logger.warning(f"Project ID {project_id} not found or inaccessible for pipelines: {e}")
            else:
                for project_summary in await self.get_projects():
                    try:
                        project = self.gl.projects.get(project_summary['id'])
                        all_pipelines_data.extend(await self._get_project_pipelines_data(project))
                        logger.debug(f"Got pipelines for project ID {project_summary['id']} (all projects mode).")
                    except GitlabGetError as e:
                        logger.warning(f"Skipping project ID {project_summary['id']} (pipelines): {e}")
        except GitlabError as e:
            logger.error(f"Error getting pipelines: {e}", exc_info=True)
        return all_pipelines_data

    @tool
    async def get_branches(self, project_id: Optional[int] = None) -> list:
        """
        Asynchronously retrieves a list of all branches for a specific GitLab project.
        If project_id is None, it fetches branches from all accessible projects.
        Returns all available attributes for each branch.

        Parameter:
           project_id (int, optional): The ID of the GitLab project to retrieve branches from.
                                       If None, branches from all accessible projects are returned.
        """
        all_branches_data = []
        try:
            if project_id:
                try:
                    project = self.gl.projects.get(project_id)
                    all_branches_data.extend(await self._get_project_branches_data(project))
                    logger.debug(f"Got branches for project ID {project_id}.")
                except GitlabGetError as e:
                    logger.warning(f"Project ID {project_id} not found or inaccessible for branches: {e}")
            else:
                for project_summary in await self.get_projects():
                    try:
                        project = self.gl.projects.get(project_summary['id'])
                        all_branches_data.extend(await self._get_project_branches_data(project))
                        logger.debug(f"Got branches for project ID {project_summary['id']} (all projects mode).")
                    except GitlabGetError as e:
                        logger.warning(f"Skipping project ID {project_summary['id']} (branches): {e}")
        except GitlabError as e:
            logger.error(f"Error getting branches: {e}", exc_info=True)
        return all_branches_data

    @tool
    async def get_branch_protection_rules(self, project_id: Optional[int] = None) -> list:
        """
        Asynchronously retrieves a list of all branch protection rules for a specific GitLab project.
        If project_id is None, it fetches rules from all accessible projects.
        Returns all available attributes for each branch protection rule.

        Parameter:
           project_id (int, optional): The ID of the GitLab project to retrieve branch protection rules from.
                                       If None, rules from all accessible projects are returned.
        """
        all_protected_branches_data = []
        try:
            if project_id:
                try:
                    project = self.gl.projects.get(project_id)
                    all_protected_branches_data.extend(await self._get_project_branch_protection_rules_data(project))
                    logger.debug(f"Got branch protection rules for project ID {project_id}.")
                except GitlabGetError as e:
                    logger.warning(f"Project ID {project_id} not found or inaccessible for branch protection rules: {e}")
            else:
                for project_summary in await self.get_projects():
                    try:
                        project = self.gl.projects.get(project_summary['id'])
                        all_protected_branches_data.extend(await self._get_project_branch_protection_rules_data(project))
                        logger.debug(f"Got branch protection rules for project ID {project_summary['id']} (all projects mode).")
                    except GitlabGetError as e:
                        logger.warning(f"Skipping project ID {project_summary['id']} (branch protection rules): {e}")
        except GitlabError as e:
            logger.error(f"Error getting branch protection rules: {e}", exc_info=True)
        return all_protected_branches_data

    @tool
    async def get_packages(self, project_id: Optional[int] = None) -> list:
        """
        Asynchronously retrieves a list of all packages published to the package registry
        for a specific GitLab project. If project_id is None, it fetches packages from all accessible projects.
        Returns all available attributes for each package.

        Parameter:
           project_id (int, optional): The ID of the GitLab project to retrieve packages from.
                                       If None, packages from all accessible projects are returned.
        """
        all_packages_data = []
        try:
            if project_id:
                try:
                    project = self.gl.projects.get(project_id)
                    all_packages_data.extend(await self._get_project_packages_data(project))
                    logger.debug(f"Got packages for project ID {project_id}.")
                except GitlabGetError as e:
                    logger.warning(f"Project ID {project_id} not found or inaccessible for packages: {e}")
            else:
                for project_summary in await self.get_projects():
                    try:
                        project = self.gl.projects.get(project_summary['id'])
                        all_packages_data.extend(await self._get_project_packages_data(project))
                        logger.debug(f"Got packages for project ID {project_summary['id']} (all projects mode).")
                    except GitlabGetError as e:
                        logger.warning(f"Skipping project ID {project_summary['id']} (packages): {e}")
        except GitlabError as e:
            logger.error(f"Error getting packages: {e}", exc_info=True)
        return all_packages_data
