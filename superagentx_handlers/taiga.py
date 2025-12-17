import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class TaigaHandler(BaseHandler):
    """
    TaigaHandler — Async Taiga project management operations handler

    This handler manages authenticated, asynchronous interactions with the
    Taiga REST API. It authenticates using username/password credentials,
    retrieves an access token, and reuses an aiohttp session for efficient
    API communication.

    The handler exposes decorated tool methods designed for LLMs or agent
    frameworks to query Taiga user, project, and workflow configuration data.

    Core capabilities include:
    - Project discovery for the authenticated user
    - Workflow and status stage inspection across projects
    - Unified aggregation of process states (epics, user stories, tasks, issues)

    Available tool methods:

    Projects
        - get_projects: list all projects where the user is a member

    Workflow Stages
        - get_stages: retrieve workflow stages for a given project and entity type
          (epics, user stories, tasks, or issues)
        - get_all_processes: aggregate all workflow stages across all user projects
    """

    def __init__(self, username, password, base_url="https://api.taiga.io/api/v1"):

        super().__init__()
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = None
        self.token = None

    async def _create_session(self):
        if self.session is None:
            self.session = aiohttp.ClientSession()
        return self.session

    async def _login(self):
        session = await self._create_session()
        url = f"{self.base_url}/auth"

        payload = {
            "type": "normal",
            "username": self.username,
            "password": self.password
        }

        async with session.post(url, json=payload) as r:
            r.raise_for_status()
            data = await r.json()
            self.token = data["auth_token"]

    async def _headers(self):
        if self.token is None:
            await self._login()

        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    async def get(self):
        session = await self._create_session()
        url = f"{self.base_url}/users/me"

        async with session.get(url, headers=await self._headers()) as r:
            r.raise_for_status()
            return await r.json()

    @tool
    async def get_stages(self, kind: str, project_id: int):
        session = await self._create_session()
        url = f"{self.base_url}/{kind}?project={project_id}"

        async with session.get(url, headers=await self._headers()) as r:
            r.raise_for_status()
            return await r.json()

    @tool
    async def get_projects(self):
        me = await self.get()
        user_id = me["id"]

        session = await self._create_session()
        url = f"{self.base_url}/projects?member={user_id}"

        async with session.get(url, headers=await self._headers()) as r:
            r.raise_for_status()
            return await r.json()

    @tool
    async def get_all_processes(self):
        projects = await self.get_projects()
        all_statuses = {}

        for project in projects:
            project_id = project["id"]
            project_name = project["name"]
            all_statuses[project_name] = {}

            try:
                epic = await self.get_stages("epic-statuses", project_id)
                all_statuses[project_name]["epic"] = epic
            except aiohttp.ClientResponseError:
                all_statuses[project_name]["epic"] = []

            try:
                us = await self.get_stages("userstory-statuses", project_id)
                all_statuses[project_name]["userstories"] = us
            except aiohttp.ClientResponseError:
                all_statuses[project_name]["userstories"] = []

            try:
                tasks = await self.get_stages("task-statuses", project_id)
                all_statuses[project_name]["tasks"] = tasks
            except aiohttp.ClientResponseError:
                all_statuses[project_name]["tasks"] = []

            try:
                issues = await self.get_stages("issue-statuses", project_id)
                all_statuses[project_name]["issues"] = issues
            except aiohttp.ClientResponseError:
                all_statuses[project_name]["issues"] = []

        return all_statuses

    async def close(self):
        if self.session:
            await self.session.close()
