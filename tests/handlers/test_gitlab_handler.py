# test_gitlab_handler.py
import os
import pytest
import pytest_asyncio

# Import your GitlabHandler and custom exceptions
from superagentx_handlers.gitlab_handler import GitlabHandler, GitLabClientInitFailed, \
    GitLabListUsersFailed, GitLabListProjectsFailed, GitLabListGroupsFailed, \
    GitLabListIssuesFailed, GitLabListMergeRequestsFailed, GitLabListHooksFailed, \
    GitLabListPipelinesFailed, GitLabListBranchesFailed, GitLabListBranchProtectionRulesFailed, \
    GitLabListPackagesFailed

'''
 Run Pytest for GitLab Handler:

   1. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_user_profile
   2. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_projects
   3. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_groups_and_members
   4. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_issues_assigned_to_me
   5. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_issues_for_project
   6. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_merge_requests_assigned_to_me
   7. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_merge_requests_for_project
   8. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_hooks
   9. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_pipelines
   10. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_branches
   11. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_branch_protection_rules
   12. pytest --log-cli-level=INFO test_gitlab_handler.py::TestGitlabHandler::test_get_packages

 Remember to set your GitLab environment variables for a TEST/DEVELOPMENT instance (NOT production) before running:
 export GITLAB_PRIVATE_TOKEN="your_gitlab_private_token"
 export GITLAB_URL="https://gitlab.com" # Or your self-hosted GitLab URL
 export TEST_GITLAB_PROJECT_ID="your_test_project_id" # An existing project ID for tests requiring it
'''

@pytest_asyncio.fixture
async def gitlab_client_init() -> GitlabHandler: # type: ignore
    """
    Initializes and provides a GitlabHandler instance for testing.
    """
    private_token = os.getenv("GITLAB_PRIVATE_TOKEN")
    url = os.getenv("GITLAB_URL", "https://gitlab.com")

    if not private_token:
        pytest.fail("GITLAB_PRIVATE_TOKEN environment variable not set for testing.")

    try:
        handler = GitlabHandler(private_token=private_token, url=url)
        yield handler
    except GitLabClientInitFailed as e:
        pytest.fail(f"Failed to initialize GitlabHandler: {e}")


class TestGitlabHandler:
    """
    This test suite provides brief tests for core read functionalities of the GitlabHandler.
    """

    @pytest.mark.asyncio
    async def test_get_user_profile(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving the authenticated user's profile."""
        user_profile = await gitlab_client_init.get_user_profile()
        assert isinstance(user_profile, dict)
        assert "username" in user_profile
        assert "id" in user_profile

    @pytest.mark.asyncio
    async def test_get_projects(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving a list of all projects owned by the user."""
        projects = await gitlab_client_init.get_projects()
        assert isinstance(projects, list)

    @pytest.mark.asyncio
    async def test_get_groups_and_members(self, gitlab_client_init: GitlabHandler):
        """Tests listing GitLab groups owned by the user and their members."""
        groups = await gitlab_client_init.get_groups_and_members()
        assert isinstance(groups, list)

    @pytest.mark.asyncio
    async def test_get_issues_assigned_to_me(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving issues assigned to the current user (no project_id)."""
        issues = await gitlab_client_init.get_issues()
        assert isinstance(issues, list)

    @pytest.mark.asyncio
    async def test_get_issues_for_project(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving issues for a specific project."""
        project_id = os.getenv("TEST_GITLAB_PROJECT_ID")
        if not project_id: pytest.skip("TEST_GITLAB_PROJECT_ID not set for project-specific issues test.")
        issues = await gitlab_client_init.get_issues(project_id=int(project_id))
        assert isinstance(issues, list)

    @pytest.mark.asyncio
    async def test_get_merge_requests_assigned_to_me(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving merge requests assigned to the current user (no project_id)."""
        mrs = await gitlab_client_init.get_merge_requests()
        assert isinstance(mrs, list)

    @pytest.mark.asyncio
    async def test_get_merge_requests_for_project(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving merge requests for a specific project."""
        project_id = os.getenv("TEST_GITLAB_PROJECT_ID")
        if not project_id: pytest.skip("TEST_GITLAB_PROJECT_ID not set for project-specific merge requests test.")
        mrs = await gitlab_client_init.get_merge_requests(project_id=int(project_id))
        assert isinstance(mrs, list)

    @pytest.mark.asyncio
    async def test_get_hooks(self, gitlab_client_init: GitlabHandler):
        """Tests fetching webhooks configured for a specific GitLab project."""
        project_id = os.getenv("TEST_GITLAB_PROJECT_ID")
        if not project_id: pytest.skip("TEST_GITLAB_PROJECT_ID not set for hooks test.")
        hooks = await gitlab_client_init.get_hooks(project_id=int(project_id))
        assert isinstance(hooks, list)

    @pytest.mark.asyncio
    async def test_get_pipelines(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving recent pipeline runs for a specific GitLab project."""
        project_id = os.getenv("TEST_GITLAB_PROJECT_ID")
        if not project_id: pytest.skip("TEST_GITLAB_PROJECT_ID not set for pipelines test.")
        pipelines = await gitlab_client_init.get_pipelines(project_id=int(project_id))
        assert isinstance(pipelines, list)

    @pytest.mark.asyncio
    async def test_get_branches(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving a list of all branches for a specific GitLab project."""
        project_id = os.getenv("TEST_GITLAB_PROJECT_ID")
        if not project_id: pytest.skip("TEST_GITLAB_PROJECT_ID not set for branches test.")
        branches = await gitlab_client_init.get_branches(project_id=int(project_id))
        assert isinstance(branches, list)

    @pytest.mark.asyncio
    async def test_get_branch_protection_rules(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving branch protection rules for a specific GitLab project."""
        project_id = os.getenv("TEST_GITLAB_PROJECT_ID")
        if not project_id: pytest.skip("TEST_GITLAB_PROJECT_ID not set for branch protection rules test.")
        rules = await gitlab_client_init.get_branch_protection_rules(project_id=int(project_id))
        assert isinstance(rules, list)

    @pytest.mark.asyncio
    async def test_get_packages(self, gitlab_client_init: GitlabHandler):
        """Tests retrieving packages published to the package registry for a specific GitLab project."""
        project_id = os.getenv("TEST_GITLAB_PROJECT_ID")
        if not project_id: pytest.skip("TEST_GITLAB_PROJECT_ID not set for packages test.")
        packages = await gitlab_client_init.get_packages(project_id=int(project_id))
        assert isinstance(packages, list)
