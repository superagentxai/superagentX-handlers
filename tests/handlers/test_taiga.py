import os

import pytest
import logging

from superagentx_handlers.taiga import TaigaHandler  # <-- Replace with your actual import

logger = logging.getLogger(__name__)
"""
pytest --log-cli-level=INFO tests/handlers/test_taiga.py

"""


@pytest.fixture
async def taiga_handler():
    """Initialize AsyncTaigaHandler with credentials."""
    username = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")

    handler = TaigaHandler(username=username, password=password)
    yield handler
    await handler.close()


@pytest.mark.asyncio
class TestAsyncTaigaRealAPI:

    async def test_get_user(self, taiga_handler: TaigaHandler):
        """Fetch authenticated user information."""
        user = await taiga_handler.get()
        logger.info(f"User Info: {user}")

        assert isinstance(user, dict)
        assert "id" in user
        assert "username" in user

    async def test_get_projects(self, taiga_handler: TaigaHandler):
        """Fetch real projects from the Taiga API."""
        projects = await taiga_handler.get_projects()
        logger.info(f"Projects: {projects}")

        assert isinstance(projects, list)
        assert len(projects) > 0
        assert "name" in projects[0]

    async def test_get_stages(self, taiga_handler: TaigaHandler):
        """Fetch workflow stages for first project."""
        projects = await taiga_handler.get_projects()
        project_id = projects[0]["id"]

        stages = await taiga_handler.get_stages("userstory-statuses", project_id)
        logger.info(f"Stages for project {project_id}: {stages}")

        assert isinstance(stages, list)
        if stages:  # Some projects may not have stages
            assert "name" in stages[0]

    async def test_get_all_processes(self, taiga_handler: TaigaHandler):
        """Fetch all workflow processes for all projects."""
        processes = await taiga_handler.get_all_processes()
        logger.info(f"All Project Processes:\n{processes}")

        assert isinstance(processes, dict)
        assert len(processes.keys()) > 0

        first_project = list(processes.keys())[0]
        assert isinstance(processes[first_project], dict)

    async def test_run_full_pipeline(self, taiga_handler: TaigaHandler):
        """Test the final combined tool method."""
        output = await taiga_handler.run_full_pipeline()
        logger.info(f"Full Pipeline Output:\n{output}")

        assert "user" in output
        assert "projects" in output
        assert "processes" in output
