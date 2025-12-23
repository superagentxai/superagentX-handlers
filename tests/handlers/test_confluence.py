import logging
import os
import pytest

from superagentx_handlers.atlassian.confluence import ConfluenceHandler

logger = logging.getLogger(__name__)

"""
Run:
    pytest --log-cli-level=INFO tests/handlers/test_confluence.py
"""


@pytest.fixture
async def confluence_handler():
    """Initialize ConfluenceHandler with creds from env variables."""

    handler = ConfluenceHandler(
        admin_api_key=os.getenv("ATLASSIAN_KEY"),
        base_url=os.getenv("ATLASSIAN_EMAIL"),
        url=os.getenv("CONFLUENCE_URL"),
        email=os.getenv("CONFLUENCE_EMAIL"),
        access_token=os.getenv("CONFLUENCE_PERSONAL_ACCESS_TOKEN"),
    )

    yield handler
    # No close() required because atlassian client isn't async


@pytest.mark.asyncio
class TestConfluenceHandlerRealAPI:

    # ADMIN API TESTS

    async def test_get_user_organisation(self, confluence_handler: ConfluenceHandler):
        orgs = await confluence_handler.get_user_organisation()
        logger.info(f"User Organisations: {orgs}")

        assert isinstance(orgs, list)
        if orgs:
            assert "id" in orgs[0]

    # TEAM API TESTS

    async def test_get_spaces(self, confluence_handler: ConfluenceHandler):
        spaces = await confluence_handler.get_spaces()
        logger.info(f"Spaces: {spaces}")

        assert isinstance(spaces, list)
        if spaces:
            assert "key" in spaces[0]

    async def test_get_groups(self, confluence_handler: ConfluenceHandler):
        groups = await confluence_handler.get_groups()
        logger.info(f"Groups: {groups}")

        assert isinstance(groups, list)
        if groups:
            assert "name" in groups[0]

    # KNOWLEDGE API TESTS

    async def test_get_pages(self, confluence_handler: ConfluenceHandler):
        pages = await confluence_handler.get_pages()
        logger.info(f"Pages: {pages}")

        assert isinstance(pages, list)
        # cannot guarantee pages exist, so no length check

    async def test_get_blog_posts(self, confluence_handler: ConfluenceHandler):
        posts = await confluence_handler.get_blog_posts()
        logger.info(f"Blog Posts: {posts}")

        assert isinstance(posts, list)
        if posts:
            assert "id" in posts[0]

    async def test_child_pages_and_labels(self, confluence_handler: ConfluenceHandler):
        pages = await confluence_handler.get_pages()

        if not pages:
            pytest.skip("No pages available to test child pages or labels.")

        page_id = pages[0].get("id")

        children = await confluence_handler.get_child_pages(page_id)
        logger.info(f"Child Pages for {page_id}: {children}")

        assert isinstance(children, list)

        labels = await confluence_handler.get_page_labels(page_id)
        logger.info(f"Labels for {page_id}: {labels}")

        assert isinstance(labels, list)

    # MASTER TOOL TEST

    async def test_get_all_confluence_data(self, confluence_handler: ConfluenceHandler):
        result = await confluence_handler.get_all_confluence_data()
        logger.info(f"Full Confluence Data:\n{result}")

        assert isinstance(result, dict)
        assert "spaces" in result
        assert "groups" in result
        assert "pages" in result
        assert "blog_posts" in result
