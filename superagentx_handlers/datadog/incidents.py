import os
from contextlib import asynccontextmanager

from datadog_api_client import AsyncApiClient, Configuration
from datadog_api_client.v2.api.incidents_api import IncidentsApi
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class DDIncidentsHandler(BaseHandler):
    def __init__(
            self,
            host: str | None = None,
            api_key: str | None = None,
            app_key: str | None = None
    ):
        super().__init__()
        host = host or os.getenv('DD_SITE')
        api_key = api_key or os.getenv('DD_API_KEY')
        app_key = app_key or os.getenv('DD_APP_KEY')
        self.configuration = Configuration()
        self.configuration.server_variables['site'] = host
        self.configuration.api_key['apiKeyAuth'] = api_key
        self.configuration.api_key['appKeyAuth'] = app_key

        # Enable list incidents
        self.configuration.unstable_operations['list_incidents'] = True
        self.incidents_cli = self.incidents_cli_conn

    @asynccontextmanager
    async def incidents_cli_conn(self):
        async with AsyncApiClient(configuration=self.configuration) as api_cli:
            yield IncidentsApi(api_client=api_cli)

    @tool
    async def list_incidents(
            self
    ):
        """
        List incidents in Datadog

        Returns:
            list: List of incidents
        """
        async with self.incidents_cli() as cli:
            return await cli.list_incidents()

    @tool
    async def search_incidents(self, query: str):
        """
        Search for incidents matching a certain query in a Datadog.

        Args:
            query (str): query string for the search and filter the incidents.

        Returns:
            list: List of incidents
        """
        async with self.incidents_cli() as cli:
            return await cli.search_incidents(query=query)
