# test_secpod.py
import os
import pytest
import pytest_asyncio
import logging
import time # For generating timestamps

# Import your SecPodHandler
from secpod import SecPodHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest for SecPod Handler:

 pytest --log-cli-level=INFO test_secpod.py::TestSecPodHandler::test_list_vulnerabilities_no_filter
 pytest --log-cli-level=INFO test_secpod.py::TestSecPodHandler::test_list_vulnerabilities_with_discovered_after_filter

 Remember to set your SecPod environment variables for a TEST/DEVELOPMENT account (NOT production) before running:
 export SECPOD_API_KEY="your_secpod_api_key"
 # export SECPOD_BASE_URL="https://saner.secpod.com" # This is the default, no need to set unless different
'''

# --- Pytest Fixture ---
@pytest_asyncio.fixture(scope="module")
async def secpod_handler_init() -> SecPodHandler:
    """
    Initializes and provides a SecPodHandler instance for testing.
    It retrieves required credentials from environment variables.
    """
    api_key = os.getenv("SECPOD_API_KEY")
    base_url = os.getenv("SECPOD_BASE_URL", "https://saner.secpod.com")

    if not api_key:
        pytest.fail(
            "Missing SecPod API Key. Please set "
            "SECPOD_API_KEY environment variable for testing."
        )

    handler = SecPodHandler(
        api_key=api_key,
        base_url=base_url
    )
    # The handler's __init__ already handles initialization logic and sets _is_initialized
    if not handler._is_initialized:
        pytest.fail("SecPodHandler failed to initialize. Check logs for details.")

    yield handler


# --- Test Class ---
class TestSecPodHandler:
    """
    This test suite provides basic tests for the SecPodHandler's vulnerability listing.
    These tests require actual SecPod SanerNow credentials with appropriate permissions.
    """

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_no_filter(self, secpod_handler_init: SecPodHandler):
        """Tests listing all vulnerabilities without any filters."""
        logger.info("Running test_list_vulnerabilities_no_filter...")
        vulnerabilities = await secpod_handler_init.list_vulnerabilities()
        assert isinstance(vulnerabilities, list)
        assert vulnerabilities is not None # The list might be empty if no vulns exist
        logger.info(f"test_list_vulnerabilities_no_filter: Got {len(vulnerabilities)} vulnerabilities.")

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_with_discovered_after_filter(self, secpod_handler_init: SecPodHandler):
        """
        Tests listing vulnerabilities discovered after a specific timestamp.
        NOTE: For this test to return meaningful results, you might need to adjust
        the `test_timestamp` to a value relevant to your SecPod data.
        A very recent timestamp might yield an empty list, which is still a valid test.
        """
        logger.info("Running test_list_vulnerabilities_with_discovered_after_filter...")
        test_timestamp = 1678886400000  # Example: March 15, 2023 12:00:00 PM GMT (adjust as needed)

        logger.info(f"Filtering vulnerabilities discovered after timestamp: {test_timestamp}")
        vulnerabilities = await secpod_handler_init.list_vulnerabilities(discovered_after=test_timestamp)
        assert isinstance(vulnerabilities, list)
        assert vulnerabilities is not None
        logger.info(f"test_list_vulnerabilities_with_discovered_after_filter: "
                    f"Got {len(vulnerabilities)} vulnerabilities discovered after {test_timestamp}.")

