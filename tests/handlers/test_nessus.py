# test_nessus_handler.py
import os
import pytest
import pytest_asyncio
import logging

# Import your NessusHandler
from nessus import NessusHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest for Nessus Handler:

   1. pytest --log-cli-level=INFO test_nessus_handler.py::TestNessusHandler::test_list_vulnerabilities_no_filter
   2. pytest --log-cli-level=INFO test_nessus_handler.py::TestNessusHandler::test_list_vulnerabilities_with_discovered_after_filter

 Remember to set your Tenable.io environment variables for a TEST/DEVELOPMENT account (NOT production) before running:
 export TENABLE_ACCESS_KEY="your_tenable_access_key"
 export TENABLE_SECRET_KEY="your_tenable_secret_key"
 export TENABLE_IO_BASE_URL="https://cloud.tenable.com" # Or your Nessus Manager URL
'''

# --- Pytest Fixture ---
@pytest_asyncio.fixture(scope="module")
async def nessus_handler_init() -> NessusHandler: # type: ignore
    """
    Initializes and provides a NessusHandler instance for testing.
    It retrieves required credentials from environment variables.
    """
    access_key = os.getenv("TENABLE_ACCESS_KEY")
    secret_key = os.getenv("TENABLE_SECRET_KEY")
    base_url = os.getenv("TENABLE_IO_BASE_URL", "https://cloud.tenable.com")

    if not all([access_key, secret_key]):
        pytest.fail(
            "Missing Nessus credentials. Please set "
            "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY "
            "environment variables for testing."
        )

    handler = NessusHandler(
        access_key=access_key,
        secret_key=secret_key,
        base_url=base_url
    )
    # The handler's __init__ already handles initialization logic and sets _is_initialized
    if not handler._is_initialized:
        pytest.fail("NessusHandler failed to initialize. Check logs for details.")

    yield handler


# --- Test Class ---
class TestNessusHandler:
    """
    This test suite provides basic tests for the NessusHandler's vulnerability listing.
    These tests require actual Tenable.io credentials with appropriate permissions.
    """

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_no_filter(self, nessus_handler_init: NessusHandler):
        """Tests listing all vulnerabilities without any filters."""
        logger.info("Running test_list_vulnerabilities_no_filter...")
        vulnerabilities = await nessus_handler_init.list_vulnerabilities()
        assert isinstance(vulnerabilities, list)
        assert vulnerabilities is not None
        logger.info(f"test_list_vulnerabilities_no_filter: Got {len(vulnerabilities)} vulnerabilities.")

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_with_discovered_after_filter(self, nessus_handler_init: NessusHandler):
        """
        Tests listing vulnerabilities discovered after a specific timestamp.
        NOTE: For this test to return meaningful results, you might need to adjust
        the `test_timestamp` to a value relevant to your Tenable.io data.
        A very recent timestamp might yield an empty list, which is still a valid test.
        """
        logger.info("Running test_list_vulnerabilities_with_discovered_after_filter...")
        test_timestamp = 1678886400000  # Example: March 15, 2023 12:00:00 PM GMT

        logger.info(f"Filtering vulnerabilities discovered after timestamp: {test_timestamp}")
        vulnerabilities = await nessus_handler_init.list_vulnerabilities(discovered_after=test_timestamp)
        assert isinstance(vulnerabilities, list)
        assert vulnerabilities is not None
        logger.info(f"test_list_vulnerabilities_with_discovered_after_filter: "
                    f"Got {len(vulnerabilities)} vulnerabilities discovered after {test_timestamp}.")

