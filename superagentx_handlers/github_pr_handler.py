import os
import subprocess
import shutil
import uuid
import asyncio
import requests
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
import aiohttp


class CIPRHandler(BaseHandler):

    def __init__(self):
        super().__init__()

    @staticmethod
    async def run_tests(self, repo_dir: str):
        process = await asyncio.create_subprocess_exec(
            "pytest",
            cwd=repo_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        return {
            "status": "passed" if process.returncode == 0 else "failed",
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
        }
    @tool
    async def handle_pr(self, pr_id: int, repo_url: str, branch: str):
        """
            Handle a GitHub Pull Request by cloning the repository, checking out a branch,
            running CI tests, and posting results as a comment on the PR.

            Steps performed:
            1. Clone the repository from `repo_url` to a temporary directory.
            2. Checkout the specified `branch`.
            3. Run tests using the internal CI test handler (`_run_tests`).
            4. Format the test results for posting.
            5. Post a comment back to the PR on GitHub.

            Args:
                pr_id (int): The Pull Request number to post the results to.
                repo_url (str): HTTPS URL of the GitHub repository.
                branch (str): Branch name associated with the PR.

            Returns:
                None

            Raises:
                subprocess.CalledProcessError: If git clone or checkout fails.
                Exception: If running tests or posting comments fails.

            Notes:
                - Creates a temporary directory for cloning and cleans it up afterwards.
                - Uses `annotate_pr` to post comments to the PR.
                - Test results can either be "passed" or "failed"; failure messages are formatted.
            """
        print(f" Handling PR #{pr_id}")
        repo_dir = f"temp_repo_{uuid.uuid4()}"

        try:
            # Clone repo
            process = await asyncio.create_subprocess_exec(
                "git", "clone", repo_url, repo_dir
            )
            await process.wait()

            # Checkout branch
            process = await asyncio.create_subprocess_exec(
                "git", "checkout", branch,
                cwd=repo_dir
            )
            await process.wait()

            # Run tests
            result = await self._run_tests()
            print(f"Result: {result}")

            # Format message
            if result["status"] == "failed":
                message = await self._format_failure(result)
            else:
                message = "All tests passed successfully!"

            # Post to GitHub
            await self.annotate_pr(pr_id, message)

        finally:
            shutil.rmtree(repo_dir, ignore_errors=True)

    async def _format_failure(self, result):
        """
        Format failure message for PR comment
        """
        project_type = result.get("project_type", "unknown")
        stderr = result.get("stderr", "")
        error_snippet = stderr[-500:] if stderr else "No error details available"

        return f"""
               CI FAILED
               ### Project Type: {project_type}
               Test Failures Detected:
               {error_snippet}
               Please review the failing tests and fix the issues.
                """

    @tool
    async def annotate_pr(self, pr_id: int, message: str):
        """
            Post a comment to a GitHub Pull Request with CI results or messages.

            This method uses GitHub's REST API to post a comment to the specified PR.
            It requires a valid GitHub token with permissions to comment on the repository.

            Args:
                pr_id (int): Pull Request number to post the comment to.
                message (str): The content of the comment to post.

            Returns:
                None

            Raises:
                Exception: If the API request fails due to network issues or invalid authentication.

            Notes:
                - The GitHub token must be set in the environment variable `GITHUB_TOKEN`.
                - A successful request returns HTTP status code 201.
                - Failure responses and exceptions are logged for debugging purposes.
                - Ensure that `<USERNAME>` and `<REPO>` in the URL are replaced with
                  your actual GitHub username and repository name.
            """
        url = f"https://api.github.com/repos/<USERNAME>/<REPO>/issues/<PR_NUMBER>/comments"
        headers = {
            "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}",
            "Accept": "application/vnd.github+json"
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json={"body": message}, headers=headers) as response:
                    if response.status == 201:
                        print(f"Comment posted to PR #{pr_id}")
                    else:
                        print(f"Failed: {response.status}")
                        print(await response.text())
        except Exception as e:
            print(f"Exception while posting comment: {e}")
