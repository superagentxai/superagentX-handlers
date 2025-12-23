import logging
import os
from typing import Optional

import asana
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class AsanaHandler(BaseHandler):

    """
       Asynchronous handler for interacting with the Asana API.

       This handler initializes and manages authenticated Asana API clients
       for multiple resource domains such as workspaces, users, projects,
       tasks, portfolios, and goals. It is designed to be used within
       agentic or tool-based workflows where Asana operations are exposed
       as callable tools.

       Authentication is performed using a Personal Access Token (PAT),
       which can be provided directly or read from the environment.

       Workspaces:
            - get_workspaces()

        Users:
            - get_users()

        Projects:
            - get_projects()

        Tasks:
            - create_task(name, workspace_id, project_id=None,
                          assignee_id=None, due_on=None)
            - update_task(task_id, name=None, completed=None,
                          assignee_id=None, due_on=None)
            - delete_task(task_id)

        Task Dependencies:
            - get_dependencies_for_task(task_id)
            - get_dependents_for_task(task_id)

        Portfolios:
            - get_portfolios()

    """

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
        """
           Retrieve all Asana workspaces accessible to the authenticated user.

           This method queries the Asana Workspaces API and returns a list of
           workspaces the user has access to.

        """
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
        """
            Create a new task in Asana.

            The task is created within a specified workspace and can optionally
            be assigned to a user, given a due date, and added to a project.

            Args:
                name (str): The name/title of the task.
                workspace_id (str): The GID of the workspace where the task is created.
                project_id (Optional[str]): The GID of the project to associate
                    the task with after creation.
                assignee_id (Optional[str]): The GID of the user to assign the task to.
                due_on (Optional[str]): The due date of the task in ISO format (YYYY-MM-DD).

            Returns:
                dict: The created task object containing task metadata such as
                      task GID, name, completion status, and timestamps.
            """
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
        """
            Create a new task in Asana.

            The task is created within a specified workspace and can optionally
            be assigned to a user, given a due date, and added to a project.

            Args:
                task_id (str): The GID of the task to update.
                name (Optional[str]): New name for the task.
                completed (Optional[bool]): Mark the task as completed or incomplete.
                assignee_id (Optional[str]): Update the task assignee.
                due_on (Optional[str]): Update the task due date (YYYY-MM-DD).

            Returns:
                dict: The created task object containing task metadata such as
                      task GID, name, completion status, and timestamps.
            """
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
        """
            Delete a task from Asana.

            This operation permanently removes the task.

            Args:
                task_id (str): The GID of the task to delete.
        """
        req = self.tasks_api.delete_task(task_id, async_req=True)
        await self._fetch(req)
        return {"success": True, "task_id": task_id}

    # --------------------------------------------------
    # USERS
    # --------------------------------------------------

    @tool
    async def get_users(self):
        """
            Retrieve all users across all accessible workspaces.

            The method iterates through each workspace and fetches
            users associated with that workspace.

            Returns:
                dict: A dictionary containing a list of users under "data".
                      Each user entry includes its associated workspace metadata.
            """

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
        """
            Retrieve all projects across all accessible workspaces.

            Each project returned is enriched with its corresponding
            workspace information.

            Returns:
                dict: A dictionary containing project data under "data".
                      Each project includes workspace context.
            """
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
        """
           Retrieve tasks that the specified task depends on.

           Dependencies represent tasks that must be completed
           before the given task can start.

           Args:
               task_id (str): The GID of the task.

           Returns:
               dict: A dictionary containing dependency task data.
           """

        req = self.tasks_api.get_dependencies_for_task(
            task_id,
            opts={},
            async_req=True,
        )
        return await self._fetch(req)

    @tool
    async def get_dependents_for_task(self, task_id: str):
        """
            Retrieve tasks that depend on the specified task.

            Dependents are tasks that are blocked by the given task.

            Args:
                task_id (str): The GID of the task.

            Returns:
                dict: A dictionary containing dependent task data.
            """
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
        """
            Retrieve tasks that depend on the specified task.

            Dependents are tasks that are blocked by the given task.

            Returns:
                dict: A dictionary containing dependent task data.
            """
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
