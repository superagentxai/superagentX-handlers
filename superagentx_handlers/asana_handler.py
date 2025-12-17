import logging
import os
from typing import Optional

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

import asana

logger = logging.getLogger(__name__)


class AsanaHandler(BaseHandler):
    """
    AsanaHandler — Async Asana workspace and project operations handler

    This handler manages authenticated, asynchronous interactions with the
    Asana REST API. It initializes an Asana API client using a personal access
    token and exposes decorated tool methods that can be invoked by LLMs
    or autonomous agents to retrieve and traverse Asana organizational data.

    Core capabilities include:
    - Workspace discovery
    - User enumeration
    - Project and task traversal
    - Task dependency graph inspection
    - Tag, portfolio, and goal retrieval

    The handler automatically iterates across all accessible workspaces
    and enriches returned entities with their associated workspace,
    project, and ownership metadata where applicable.

    Workspaces
        - get_workspaces: list all accessible Asana workspaces

    Users
        - get_users: list all users across workspaces

    Projects
        - get_projects: list all projects within each workspace

    Tasks
        - get_tasks: list all tasks across all projects
        - get_dependencies_for_task: retrieve task dependencies
        - get_dependents_for_task: retrieve tasks dependent on a given task

    Tags
        - get_tags: list all tags associated with projects

    Goals
        - get_goals: list goals per workspace (requires Asana Premium)

    Portfolios
        - get_portfolios: list portfolios per workspace and owner

    All methods are asynchronous and return normalized dictionaries
    containing a `data` key for compatibility with agent-based tooling.
    Errors are logged and gracefully handled to avoid agent interruption.
    """

    def __init__(self, token: Optional[str] = None):

        super().__init__()
        access_token = token or os.getenv("ASANA_ACCESS_TOKEN")
        configuration = asana.Configuration()
        configuration.access_token = access_token

        client = asana.ApiClient(configuration)

        # Core Asana endpoints
        self.workspaces_api = asana.WorkspacesApi(client)
        self.users_api = asana.UsersApi(client)
        self.projects_api = asana.ProjectsApi(client)
        self.tasks_api = asana.TasksApi(client)
        self.tags_api = asana.TagsApi(client)
        self.portfolios_api = asana.PortfoliosApi(client)
        self.goals_api = asana.GoalsApi(client)


    # --------------------------------------------------------------------
    # COMMON INTERNAL UTILITIES
    # --------------------------------------------------------------------

    async def _fetch(self, request):
        """Utility helper to await async_req=True workers safely."""
        try:
            return request.get()
        except Exception as e:
            logger.error(f"Asana API error: {str(e)}")
            return {}

    async def get_workspaces(self):
        opts = {}

        try:
            thread = self.workspaces_api.get_workspaces(async_req=True,opts=opts)
            return await self._fetch(thread)
        except Exception as e:
            logger.error(f"get_workspaces failed: {e}")
            return {"data": []}

    # --------------------------------------------------------------------
    # CREATE TASK
    # --------------------------------------------------------------------
    @tool
    async def create_task(
            self,
            name: str,
            workspace_id: str,
            project_id: Optional[str] = None,
            assignee_id: Optional[str] = None,
            due_on: Optional[str] = None,
    ):
        try:
            body = {
                "data": {
                    "name": name,
                    "workspace": workspace_id,
                    "assignee": assignee_id,
                    "due_on": due_on,
                }
            }

            req = self.tasks_api.create_task(body, async_req=True)
            task = await self._fetch(req)

            if project_id:
                add_req = self.tasks_api.add_project_for_task(
                    task["data"]["gid"],
                    {"data": {"project": project_id}},
                    async_req=True,
                )
                await self._fetch(add_req)

            return task
        except Exception as e:
            logger.error(f"create_task failed: {e}")
            return {"error": str(e)}

    # --------------------------------------------------------------------
    # UPDATE TASK
    # --------------------------------------------------------------------
    @tool
    async def update_task(
            self,
            task_id: str,
            name: Optional[str] = None,
            completed: Optional[bool] = None,
            assignee_id: Optional[str] = None,
            due_on: Optional[str] = None,
    ):
        try:
            body = {"data": {}}
            if name is not None:
                body["data"]["name"] = name
            if completed is not None:
                body["data"]["completed"] = completed
            if assignee_id is not None:
                body["data"]["assignee"] = assignee_id
            if due_on is not None:
                body["data"]["due_on"] = due_on

            req = self.tasks_api.update_task(task_id, body, async_req=True)
            return await self._fetch(req)
        except Exception as e:
            logger.error(f"update_task failed: {e}")
            return {"error": str(e)}

    # --------------------------------------------------------------------
    # DELETE TASK
    # --------------------------------------------------------------------
    @tool
    async def delete_task(self, task_id: str):
        try:
            req = self.tasks_api.delete_task(task_id, async_req=True)
            await self._fetch(req)
            return {"success": True, "task_id": task_id}
        except Exception as e:
            logger.error(f"delete_task failed: {e}")
            return {"error": str(e)}

    # --------------------------------------------------------------------
    # USERS
    # --------------------------------------------------------------------
    @tool
    async def get_users(self):
        users = []
        try:
            workspaces = (await self.get_workspaces()).get("data", [])
            for ws in workspaces:
                ws_id = ws.get("gid")
                req = self.users_api.get_users({"workspace": ws_id}, async_req=True)
                data = await self._fetch(req)
                for user in data.get("data", []):
                    user["workspace"] = ws
                    users.append(user)
            return {"data": users}
        except Exception as e:
            logger.error(f"get_users failed: {e}")
            return {"data": []}

    # --------------------------------------------------------------------
    # PROJECTS
    # --------------------------------------------------------------------

    @tool
    async def get_projects(self):
        projects = []
        try:
            workspaces = (await self.get_workspaces()).get("data", [])
            for ws in workspaces:
                ws_id = ws.get("gid")
                req = self.projects_api.get_projects({"workspace": ws_id}, async_req=True)
                resp = await self._fetch(req)
                for project in resp.get("data", []):
                    project["workspace"] = ws
                    projects.append(project)
            return {"data": projects}
        except Exception as e:
            logger.error(f"get_projects failed: {e}")
            return {"data": []}

    # --------------------------------------------------------------------
    # GOALS
    # --------------------------------------------------------------------

    @tool
    async def get_goals(self):
        goals = []
        try:
            workspaces = (await self.get_workspaces()).get("data", [])
            for ws in workspaces:
                ws_id = ws.get("gid")

                req = self.goals_api.get_goals({"workspace": ws_id}, async_req=True)
                resp = await self._fetch(req)

                for goal in resp.get("data", []):
                    goal["workspace"] = ws
                    goals.append(goal)

            return {"data": goals}

        except Exception as e:
            if "402" in str(e):
                return {
                    "error": "Asana Goals API requires a Premium plan."
                }
            logger.error(f"get_goals failed: {e}")
            return {"data": []}

    # --------------------------------------------------------------------
    # TASKS
    # --------------------------------------------------------------------

    @tool
    async def get_tasks(self):
        tasks = []
        try:
            projects = (await self.get_projects()).get("data", [])
            for project in projects:
                project_id = project.get("gid")
                ws = project.get("workspace", {})

                req = self.tasks_api.get_tasks({"project": project_id}, async_req=True)
                resp = await self._fetch(req)

                for task in resp.get("data", []):
                    task["project"] = project
                    task["workspace"] = ws
                    tasks.append(task)

            return {"data": tasks}
        except Exception as e:
            logger.error(f"get_tasks failed: {e}")
            return {"data": []}

    # --------------------------------------------------------------------
    # TAGS
    # --------------------------------------------------------------------

    @tool
    async def get_tags(self):
        tags = []
        try:
            projects = (await self.get_projects()).get("data", [])
            for project in projects:
                project_id = project.get("gid")
                ws = project.get("workspace", {})

                opts = {"project": project_id, "workspace": ws.get("gid", "")}
                req = self.tags_api.get_tags(opts, async_req=True)
                resp = await self._fetch(req)

                for tag in resp.get("data", []):
                    tag["project"] = project
                    tag["workspace"] = ws
                    tags.append(tag)

            return {"data": tags}
        except Exception as e:
            logger.error(f"get_tags failed: {e}")
            return {"data": []}

    # --------------------------------------------------------------------
    # TASK DEPENDENCIES
    # --------------------------------------------------------------------

    @tool
    async def get_dependencies_for_task(self):
        results = []
        try:
            projects = (await self.get_projects()).get("data", [])
            for project in projects:
                ws = project.get("workspace", {})
                project_id = project.get("gid")

                req = self.tasks_api.get_tasks({"project": project_id}, async_req=True)
                task_resp = await self._fetch(req)

                for task in task_resp.get("data", []):
                    task_id = task.get("gid")

                    thread = self.tasks_api.get_dependencies_for_task(task_id, {}, async_req=True)
                    dep_resp = await self._fetch(thread)

                    for dep in dep_resp.get("data", []):
                        dep["task"] = task
                        dep["project"] = project
                        dep["workspace"] = ws
                        results.append(dep)

            return {"data": results}

        except Exception as e:
            logger.error(f"get_dependencies_for_task failed: {e}")
            return {"data": []}

    @tool
    async def get_dependents_for_task(self):
        results = []
        try:
            projects = (await self.get_projects()).get("data", [])
            for project in projects:
                ws = project.get("workspace", {})
                project_id = project.get("gid")

                req = self.tasks_api.get_tasks({"project": project_id}, async_req=True)
                task_resp = await self._fetch(req)

                for task in task_resp.get("data", []):
                    task_id = task.get("gid")

                    thread = self.tasks_api.get_dependents_for_task(task_id, {}, async_req=True)
                    dep_resp = await self._fetch(thread)

                    for dep in dep_resp.get("data", []):
                        dep["task"] = task
                        dep["project"] = project
                        dep["workspace"] = ws
                        results.append(dep)

            return {"data": results}

        except Exception as e:
            logger.error(f"get_dependents_for_task failed: {e}")
            return {"data": []}

    # --------------------------------------------------------------------
    # PORTFOLIOS
    # --------------------------------------------------------------------

    @tool
    async def get_portfolios(self):
        portfolios = []
        try:
            workspaces = (await self.get_workspaces()).get("data", [])

            for ws in workspaces:
                ws_id = ws.get("gid")

                # Retrieve users for each workspace
                users_req = self.users_api.get_users({"workspace": ws_id}, async_req=True)
                users = (await self._fetch(users_req)).get("data", [])

                for user in users:
                    owner_id = user.get("gid")

                    opts = {"workspace": ws_id, "owner": owner_id}

                    req = self.portfolios_api.get_portfolios(workspace=ws_id, opts=opts, async_req=True)
                    resp = await self._fetch(req)

                    for pf in resp.get("data", []):
                        pf["workspace"] = ws
                        pf["owner"] = user
                        portfolios.append(pf)

            return {"data": portfolios}

        except Exception as e:
            logger.error(f"get_portfolios failed: {e}")
            return {"data": []}
