import logging
import os

import pytest

import asana
from superagentx_handlers.asana_handler import AsanaHandler   # <-- update to your actual path

logger = logging.getLogger(__name__)

"""
Run Pytest:

1. pytest --log-cli-level=INFO tests/handlers/test_asana.py::TestAsanaHandler::test_get_workspaces
2. pytest --log-cli-level=INFO tests/handlers/test_asana.py::TestAsanaHandler::test_create_task
3. pytest --log-cli-level=INFO tests/handlers/test_asana.py::TestAsanaHandler::test_update_task
4. pytest --log-cli-level=INFO tests/handlers/test_asana.py::TestAsanaHandler::test_delete_task
5. pytest --log-cli-level=INFO tests/handlers/test_asana.py::TestAsanaHandler::test_get_projects
6. pytest --log-cli-level=INFO tests/handlers/test_asana.py::TestAsanaHandler::test_get_tasks

"""

ASANA_ACCESS_TOKEN = "<ASANA_ACCESS_TOKEN>"


@pytest.fixture
def asana_handler_init() -> AsanaHandler:

    handler = AsanaHandler(token=ASANA_ACCESS_TOKEN)
    return handler


class TestAsanaHandler:

    async def test_get_workspaces(self, asana_handler_init: AsanaHandler):
        res = await asana_handler_init.get_workspaces()
        logger.info(f"Workspaces: {res}")
        assert isinstance(res, dict)

    async def test_create_task(self, asana_handler_init: AsanaHandler):
        res = await asana_handler_init.create_task(
            name="Test Task from API",
            workspace_id="WORKSPACE_ID",
            project_id="PROJECT_ID",
            assignee_id="ASSIGNEE_ID",
            due_on="DUE_ON",
        )

        logger.info(f"Create Task Response: {res}")

        assert isinstance(res, dict)
        assert "data" in res
        assert "gid" in res["data"]

    async def test_update_task(self, asana_handler_init: AsanaHandler):
        task_id = getattr(pytest, "task_id", None)
        assert task_id is not None, "Task ID not found. create_task test may have failed."

        res = await asana_handler_init.update_task(
            task_id=task_id,
            name="Updated Task Name",
            completed=False,
            assignee_id="ASSIGNEE_ID",
            due_on="2025-01-25",
        )

        logger.info(f"Update Task Response: {res}")

        assert isinstance(res, dict)
        assert "data" in res
        assert res["data"]["name"] == "Updated Task Name"

    async def test_delete_task(self, asana_handler_init: AsanaHandler):
        task_id = getattr(pytest, "task_id", None)
        assert task_id is not None, "Task ID not found. create_task test may have failed."

        res = await asana_handler_init.delete_task(task_id)

        logger.info(f"Delete Task Response: {res}")

        assert isinstance(res, dict)
        assert res.get("success") is True
        assert res.get("task_id") == task_id

    async def test_get_users(self, asana_handler_init: AsanaHandler):
        res = await asana_handler_init.get_users()
        logger.info(f"Users: {res}")
        assert isinstance(res, dict)

    async def test_get_projects(self, asana_handler_init: AsanaHandler):
        res = await asana_handler_init.get_projects()
        logger.info(f"Projects: {res}")
        assert isinstance(res, dict)

    async def test_get_dependencies_for_task(self, asana_handler_init: AsanaHandler):
        res = await asana_handler_init.get_dependencies_for_task()
        logger.info(f"Dependencies: {res}")
        assert isinstance(res, dict)

    async def test_get_dependents_for_task(self, asana_handler_init: AsanaHandler):
        res = await asana_handler_init.get_dependents_for_task()
        logger.info(f"Dependents: {res}")
        assert isinstance(res, dict)

    async def test_get_portfolios(self, asana_handler_init: AsanaHandler):
        res = await asana_handler_init.get_portfolios()
        logger.info(f"Portfolios: {res}")
        assert isinstance(res, dict)
