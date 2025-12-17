import logging
import os

import aiohttp
from aiohttp import BasicAuth
from atlassian import Confluence
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

from superagentx_handlers.atlassian.exceptions import AuthException

logger = logging.getLogger(__name__)


class ConfluenceHandler(BaseHandler):
    """
    ConfluenceHandler — Async Atlassian Confluence operations handler

    This handler manages authenticated, asynchronous interactions with Atlassian
    Confluence Cloud. It creates a Confluence API client using email + token
    authentication and exposes decorated tool methods used by LLMs or agents to
    perform common Confluence data retrieval tasks.

    Discover documentation spaces
    Enumerate pages and hierarchical page trees
    Retrieve audit metadata such as last updated timestamp and editor

        - get_all_spaces: list all Confluence spaces (paginated)
        - get_pages_spaces: list pages within a specific space
        - last_updated_pages: retrieve last-update metadata for a page

    """

    def __init__(
            self,
            *,
            email: str | None = None,
            token: str | None = None,
            organization: str | None = None
    ):
        super().__init__()
        self.email = email or os.getenv('ATLASSIAN_EMAIL')
        self.token = token or os.getenv('ATLASSIAN_TOKEN')
        self.organization = organization or os.getenv('ATLASSIAN_ORGANIZATION')
        self._connection: Confluence = self._connect()

    def _connect(self) -> Confluence:
        try:
            confluence = Confluence(
                url=f'https://{self.organization}.atlassian.net',
                token=self.token
            )
            logger.info("Confluence Authenticate Success")
            return confluence
        except Exception as ex:
            message = f'Confluence Handler Authentication Problem {ex}'
            logger.error(message, exc_info=ex)
            raise AuthException(message)

    @tool
    async def get_all_spaces(
            self,
            *,
            start: int = 0,
            limit: int = 25,
    ):

        """
        Retrieve a paginated list of all available spaces within the Confluence site.

        Discover which spaces exist in the organization
        Enumerate documentation, knowledge-base, team, and project spaces
        Provide an entry point before querying pages

        - start:	int	Pagination start index (default: 0).
        - limit:	int	Number of spaces to return per request (default: 25).
        """
        try:
            result = await sync_to_async(
                self._connection.get_all_spaces,
                start=start,
                limit=limit,
            )
            spaces_url = result["_links"]["self"]
            async with aiohttp.ClientSession() as session:
                async with session.get(
                        spaces_url,
                        auth=BasicAuth(self.email, self.token),
                        headers={'Content-Type': 'application/json'}
                ) as resp:
                    return await resp.json()
        except Exception as ex:
            message = f"Error While getting confluence spaces! {ex}"
            logger.error(message, exc_info={ex})
            raise Exception(message)

    @tool
    async def get_pages_spaces(
            self,
            *,
            space_key: str,
            start: int = 0,
            limit: int = 25,
    ):
        """
        Return all pages located in a specific Confluence space.

        Enumerate documentation in a given space
        Build navigation trees for a team or project area
        Retrieve page IDs for downstream operations

        - space_key:	str	Unique key identifying the space (e.g., "ENG", "DOCS").
        - start	int:	Pagination offset (default: 0).
        - limit	int:	Number of pages to return (default: 25).
        """
        try:
            return await sync_to_async(
                self._connection.get_all_pages_from_space,
                space=space_key,
                expand="children.page",
                start=start,
                limit=limit
            )
        except Exception as ex:
            message = f"Error While getting confluence spaces! {ex}"
            logger.error(message, exc_info={ex})
            raise Exception(message)

    @tool
    async def last_updated_pages(
            self,
            *,
            space_key: str,
            title: str,
            start: int = 0,
            limit: int = 1
    ) -> dict:
        """
        Fetch the page history, including the last updated timestamp and editor.

        Detect stale documentation
        Check whether a page has been recently updated
        Retrieve audit/tracking metadata

        - space_key:	str	Space containing the page.
        - title	str:	Exact title of the Confluence page.
        - start	int:	Pagination index (rarely needed).
        - limit	int:	Number of results (default: 1).
        """
        try:
            result = await sync_to_async(
                self._connection.get_page_by_title,
                space=space_key,
                title=title,
                start=start,
                limit=limit,
                expand='title,history.lastUpdated',
                type="page"
            )
            return result['history'] if result else None
        except Exception as ex:
            message = f"Error While getting last updated info! {ex}"
            logger.error(message, exc_info={ex})
            raise Exception(message)

    @tool
    async def get_organisations(self):
        url = f"{self.base_url}/admin/v1/orgs"
        headers = {"Authorization": f"Bearer {self.admin_api_key}", "Accept": "application/json"}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", []) if isinstance(data, dict) else data
                    logger.error(f"Org fetch failed: {resp.status} {await resp.text()}")
                    return []
        except Exception as e:
            logger.error(f"Exception in get_organisations: {e}")
            return []

    @tool
    async def get_user_organisation(self):
        """
        Fetch the organisations accessible by the authenticated Atlassian user.
        Uses the Atlassian Admin API with Bearer token.

        Returns:
            list[dict] on success
            [] on failure
        """
        url = f"{self.base_url}/admin/v1/orgs"
        headers = {
            "Authorization": f"Bearer {self.admin_api_key}",
            "Accept": "application/json"
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        if isinstance(data, dict) and "data" in data:
                            return data.get("data", [])
                        return data
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to fetch user organisations. "
                            f"Status: {response.status}, Response: {error_text}"
                        )
                        return []
        except Exception as e:
            logger.error(f"Exception while fetching user organisations: {str(e)}")
            return []

    # ---------------------------------------------------------
    # TEAM API
    # ---------------------------------------------------------
    @tool
    async def get_spaces(self):
        try:
            return self.client.get_all_spaces(limit=1000).get("results", [])
        except Exception as e:
            logger.error(f"Error fetching spaces: {e}")
            return []

    @tool
    async def get_space_permissions(self, space_key: str):
        try:
            return self.client.get_space_permissions(space_key=space_key)
        except Exception as e:
            logger.error(f"Error fetching permissions for {space_key}: {e}")
            return {}

    @tool
    async def get_groups(self):
        """Get all Groups"""
        try:
            all_groups = []
            start = 0
            limit = 50
            while True:
                data = self.client.get_all_groups(start=start, limit=limit)
                results = data.get("results", [])
                if not results:
                    break
                all_groups.extend(results)
                if len(results) < limit:
                    break
                start += limit
            return all_groups
        except Exception as e:
            logger.error(f"Error fetching groups: {e}")
            return []

    @tool
    async def get_group_members(self, group_name: str):
        """Get all members of a group."""
        try:
            members = []
            start = 0
            limit = 50
            while True:
                data = self.client.get_group_members(group_name, start=start, limit=limit)
                results = data.get("results", [])
                if not results:
                    break
                members.extend(results)
                if len(results) < limit:
                    break
                start += limit
            return members
        except Exception as e:
            logger.error(f"Error fetching group members for {group_name}: {e}")
            return []

    # ---------------------------------------------------------
    #  KNOWLEDGE API
    # ---------------------------------------------------------
    @tool
    async def get_pages(self):
        """Fetch all pages from all spaces."""
        try:
            all_spaces = await self.get_spaces()
            all_pages = []

            for space in all_spaces:
                key = space.get("key")
                pages = self.client.get_all_pages_from_space(space=key, limit=1000)
                all_pages.extend(pages)

            return all_pages
        except Exception as e:
            logger.error(f"Error fetching pages: {e}")
            return []

    @tool
    async def get_child_pages(self, page_id):
        """Get children for a specific page."""
        try:
            children = self.client.get_page_child_by_type(page_id=page_id, type="page")
            return children.get("results", []) if isinstance(children, dict) else children
        except Exception as e:
            logger.error(f"Error getting child pages: {e}")
            return []

    @tool
    async def get_page_labels(self, page_id):
        try:
            return self.client.get_page_labels(page_id) or []
        except Exception as e:
            logger.error(f"Error getting labels: {e}")
            return []

    @tool
    async def get_page_attachments(self, page_id):
        try:
            data = self.client.get_attachments_from_content(page_id=page_id)
            return data.get("results", [])
        except Exception as e:
            logger.error(f"Error fetching attachments: {e}")
            return []

    @tool
    async def get_page_properties(self, page_id):
        """Metadata properties via REST call."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.client.url}/wiki/rest/api/content/{page_id}?expand=metadata.properties"
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return {}
                    data = await resp.json()
                    return data.get("metadata", {}).get("properties", {})
        except Exception as e:
            logger.error(f"Error fetching page properties: {e}")
            return {}

    @tool
    async def get_blog_posts(self):
        """Fetch blog posts."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.client.url}/wiki/rest/api/content"
                params = {"type": "blogpost", "limit": 50}
                async with session.get(url, params=params) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    return data.get("results", [])
        except Exception as e:
            logger.error(f"Error fetching blog posts: {e}")
            return []
