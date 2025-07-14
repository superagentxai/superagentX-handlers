import os

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
        configuration = Configuration()
        configuration.server_variables['site'] = host
        configuration.api_key['apiKeyAuth'] = api_key
        configuration.api_key['appKeyAuth'] = app_key

        # Enable list incidents
        configuration.unstable_operations['list_incidents'] = True
        _api_cli = AsyncApiClient(configuration=configuration)
        self.incidents_cli = IncidentsApi(api_client=_api_cli)

    @tool
    async def list_incidents(
            self
    ):
        """
        List incidents in Datadog

        Returns:
            list: List of incidents
        """
        return await self.incidents_cli.list_incidents()

    @tool
    async def search_incidents(self, query: str):
        """
        Search for incidents matching a certain query in a Datadog.

        Args:
            query (str): query string for the search and filter the incidents.

        Returns:
            list: List of incidents
        """
        return await self.incidents_cli.search_incidents(query=query)
