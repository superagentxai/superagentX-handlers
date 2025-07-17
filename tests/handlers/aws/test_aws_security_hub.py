# tests/handlers/test_aws_security_hub.py
import logging
import os

import pytest
import pytest_asyncio
# Import your AWSSecurityHubHandler
from superagentx_handlers import AWSSecurityHubHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest for AWS Security Hub:

   1. pytest --log-cli-level=INFO tests/handlers/test_aws_security_hub.py::TestAWSSecurityHubHandler::test_get_findings_over_time
   2. pytest --log-cli-level=INFO tests/handlers/test_aws_security_hub.py::TestAWSSecurityHubHandler::test_get_top_risky_resources

 Remember to set your AWS environment variables for a TEST/DEVELOPMENT account (NOT production) before running:
 export AWS_ACCESS_KEY_ID="your_aws_access_key_id"
 export AWS_SECRET_ACCESS_KEY="your_aws_secret_access_key"
 export AWS_REGION="us-east-1" # Security Hub is regional, choose your primary region
'''

# --- Pytest Fixture ---
@pytest_asyncio.fixture(scope="module")
async def security_hub_handler_init() -> AWSSecurityHubHandler: # type: ignore
    """
    Initializes and provides an AWSSecurityHubHandler instance for testing.
    It retrieves required credentials from environment variables.
    """
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region_name = os.getenv("AWS_REGION")

    if not all([aws_access_key_id, aws_secret_access_key, region_name]):
        pytest.fail(
            "Missing AWS credentials. Please set "
            "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION "
            "environment variables for testing."
        )

    handler = AWSSecurityHubHandler(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )
    # The handler's __init__ already handles initialization logic and sets _is_initialized
    if not handler._is_initialized:
        pytest.fail("AWSSecurityHubHandler failed to initialize. Check logs for details.")

    yield handler


# --- Test Class ---
class TestAWSSecurityHubHandler:
    """
    This test suite provides basic tests for the AWSSecurityHubHandler's tools.
    These tests require actual AWS credentials with appropriate Security Hub permissions.
    """

    @pytest.mark.asyncio
    async def test_get_findings_over_time(self, security_hub_handler_init: AWSSecurityHubHandler):
        """Tests retrieving findings aggregated over time."""
        logger.info("Running test_get_findings_over_time...")
        findings_data = await security_hub_handler_init.get_findings_over_time()
        assert isinstance(findings_data, dict)
        assert "total_findings" in findings_data
        assert "findings_by_day" in findings_data
        assert "findings_by_severity" in findings_data
        # You might add more specific assertions based on expected data structure or non-empty results
        logger.info(f"test_get_findings_over_time: Total findings: {findings_data.get('total_findings')}")

    @pytest.mark.asyncio
    async def test_get_top_risky_resources(self, security_hub_handler_init: AWSSecurityHubHandler):
        """Tests identifying top risky resources."""
        logger.info("Running test_get_top_risky_resources...")
        top_resources = await security_hub_handler_init.get_top_risky_resources()
        assert isinstance(top_resources, list)
        # Check if elements in the list are dictionaries and contain expected keys
        if top_resources:
            assert isinstance(top_resources[0], dict)
            assert "ResourceId" in top_resources[0]
            assert "FindingCount" in top_resources[0]
            assert "SeverityCounts" in top_resources[0]
        logger.info(f"test_get_top_risky_resources: Got {len(top_resources)} top risky resources.")

