import logging
import os
from typing import Optional

import asana
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class AsanaHandler(BaseHandler):
    def __init__(self, token: Optional[str] = None):
        super().__init__()

        access_token = token or os.getenv("ASANA_ACCESS_TOKEN")
        if not access_token:
            raise ValueError("ASANA_ACCESS_TOKEN is required")

        config = asana.Configuration()
        config.access_token = access_token
        client = asana.ApiClient(config)

        self.workspaces_api = asana.WorkspacesApi(client)
        self.users_api = asana.UsersApi(client)
        self.projects_api = asana.ProjectsApi(client)
        self.tasks_api = asana.TasksApi(client)
        self.tags_api = asana.TagsApi(client)
        self.portfolios_api = asana.PortfoliosApi(client)
        self.goals_api = asana.GoalsApi(client)

    # --------------------------------------------------
    # INTERNAL
    # --------------------------------------------------

    async def _fetch(self, thread):
        try:
            return thread.get()
        except Exception as e:
            logger.error(f"Asana API error: {e}")
            return {"data": []}

    # --------------------------------------------------
    # WORKSPACES
    # --------------------------------------------------

    @tool
    async def get_workspaces(self):
        req = self.workspaces_api.get_workspaces(async_req=True, opts={})
        return await self._fetch(req)

    # --------------------------------------------------
    # TASKS (CRUD)
    # --------------------------------------------------

    @tool
    async def create_task(
            self,
            name: str,
            workspace_id: str,
            project_id: Optional[str] = None,
            assignee_id: Optional[str] = None,
            due_on: Optional[str] = None,
    ):
        body = {
            "data": {
                "name": name,
                "workspace": workspace_id,
            }
        }

        if assignee_id:
            body["data"]["assignee"] = assignee_id
        if due_on:
            body["data"]["due_on"] = due_on

        req = self.tasks_api.create_task(body, {}, async_req=True)
        response = await self._fetch(req)

        # Normalize response (list OR dict)
        if isinstance(response, list):
            response = response[0] if response else {}

        if not isinstance(response, dict):
            return {}

        task = response.get("data", response)

        if project_id and task.get("gid"):
            await self._fetch(
                self.tasks_api.add_project_for_task(
                    {"data": {"project": project_id}},
                    task["gid"],
                    async_req=True,
                )
            )

        return task

    @tool
    async def update_task(
        self,
        task_id: str,
        name: Optional[str] = None,
        completed: Optional[bool] = None,
        assignee_id: Optional[str] = None,
        due_on: Optional[str] = None,
    ):
        data = {}
        if name is not None:
            data["name"] = name
        if completed is not None:
            data["completed"] = completed
        if assignee_id is not None:
            data["assignee"] = assignee_id
        if due_on is not None:
            data["due_on"] = due_on

        req = self.tasks_api.update_task({"data": data}, task_id,  async_req=True)
        return await self._fetch(req)

    @tool
    async def delete_task(self, task_id: str):
        req = self.tasks_api.delete_task(task_id, async_req=True)
        await self._fetch(req)
        return {"success": True, "task_id": task_id}

    # --------------------------------------------------
    # USERS
    # --------------------------------------------------

    @tool
    async def get_users(self):
        results = []
        workspaces = (await self.get_workspaces()).get("data", [])

        for ws in workspaces:
            req = self.users_api.get_users(
                opts={"workspace": ws["gid"]},
                async_req=True,
            )
            resp = await self._fetch(req)

            for u in resp.get("data", []):
                u["workspace"] = ws
                results.append(u)

        return {"data": results}

    # --------------------------------------------------
    # PROJECTS
    # --------------------------------------------------

    @tool
    async def get_projects(self):
        results = []
        workspaces = (await self.get_workspaces()).get("data", [])

        for ws in workspaces:
            req = self.projects_api.get_projects(
                opts={"workspace": ws["gid"]},
                async_req=True,
            )
            resp = await self._fetch(req)

            for p in resp.get("data", []):
                p["workspace"] = ws
                results.append(p)

        return {"data": results}

    # --------------------------------------------------
    # TASK DEPENDENCIES (FIXED API)
    # --------------------------------------------------

    @tool
    async def get_dependencies_for_task(self, task_id: str):
        req = self.tasks_api.get_dependencies_for_task(
            task_id,
            opts={},
            async_req=True,
        )
        return await self._fetch(req)

    @tool
    async def get_dependents_for_task(self, task_id: str):
        req = self.tasks_api.get_dependents_for_task(
            task_id,
            opts={},
            async_req=True,
        )
        return await self._fetch(req)

    # --------------------------------------------------
    # PORTFOLIOS
    # --------------------------------------------------

    @tool
    async def get_portfolios(self):
        results = []
        workspaces = (await self.get_workspaces()).get("data", [])

        for ws in workspaces:
            users_req = self.users_api.get_users(
                opts={"workspace": ws["gid"]},
                async_req=True,
            )
            users = (await self._fetch(users_req)).get("data", [])

            for user in users:
                req = self.portfolios_api.get_portfolios(
                    opts={
                        "workspace": ws["gid"],
                        "owner": user["gid"],
                    },
                    async_req=True,
                )
                resp = await self._fetch(req)

                for pf in resp.get("data", []):
                    pf["workspace"] = ws
                    pf["owner"] = user
                    results.append(pf)

        return {"data": results}
