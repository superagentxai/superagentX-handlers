# test_aws_cloudfront.py
import os
import pytest
import pytest_asyncio
import logging

# Import your AWSCloudFrontHandler
from cloudfront import AWSCloudFrontHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest for AWS CloudFront:

   1. pytest --log-cli-level=INFO test_aws_cloudfront.py::TestAWSCloudFrontHandler::test_list_distributions
   2. pytest --log-cli-level=INFO test_aws_cloudfront.py::TestAWSCloudFrontHandler::test_list_certificates
   3. pytest --log-cli-level=INFO test_aws_cloudfront.py::TestAWSCloudFrontHandler::test_list_cache_behaviors
   4. pytest --log-cli-level=INFO test_aws_cloudfront.py::TestAWSCloudFrontHandler::test_list_access_control_configs

 Remember to set your AWS environment variables for a TEST/DEVELOPMENT account (NOT production) before running:
 export AWS_ACCESS_KEY_ID="your_aws_access_key_id"
 export AWS_SECRET_ACCESS_KEY="your_aws_secret_access_key"
 export AWS_REGION="us-east-1" # CloudFront API calls can be made from any region, but us-east-1 is common.
                               # ACM certificates for CloudFront MUST be in us-east-1.
'''

# --- Pytest Fixture ---
@pytest_asyncio.fixture(scope="module")
async def cloudfront_handler_init() -> AWSCloudFrontHandler: # type: ignore
    """
    Initializes and provides an AWSCloudFrontHandler instance for testing.
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

    handler = AWSCloudFrontHandler(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )
    # The handler's __init__ already handles initialization logic and sets _is_initialized
    # We should wait for it to be ready. For this simplified test, we assume if init
    # didn't fail, it's ready.
    if not handler._is_initialized:
        pytest.fail("AWSCloudFrontHandler failed to initialize. Check logs for details.")

    yield handler


# --- Test Class ---
class TestAWSCloudFrontHandler:
    """
    This test suite provides brief tests for core read functionalities of the AWSCloudFrontHandler.
    """

    @pytest.mark.asyncio
    async def test_list_distributions(self, cloudfront_handler_init: AWSCloudFrontHandler):
        """Tests listing CloudFront distributions."""
        logger.info("Running test_list_distributions...")
        distributions = await cloudfront_handler_init.list_distributions()
        assert isinstance(distributions, list)
        assert distributions is not None
        logger.info(f"test_list_distributions: Got {len(distributions)} distributions.")

    @pytest.mark.asyncio
    async def test_list_certificates(self, cloudfront_handler_init: AWSCloudFrontHandler):
        """Tests listing ACM certificates."""
        logger.info("Running test_list_certificates...")
        certificates = await cloudfront_handler_init.list_certificates()
        assert isinstance(certificates, list)
        assert certificates is not None
        logger.info(f"test_list_certificates: Got {len(certificates)} certificates.")

    @pytest.mark.asyncio
    async def test_list_cache_behaviors(self, cloudfront_handler_init: AWSCloudFrontHandler):
        """Tests listing cache behaviors across distributions."""
        logger.info("Running test_list_cache_behaviors...")
        cache_behaviors = await cloudfront_handler_init.list_cache_behaviors()
        assert isinstance(cache_behaviors, list)
        assert cache_behaviors is not None
        logger.info(f"test_list_cache_behaviors: Got {len(cache_behaviors)} cache behaviors.")

    @pytest.mark.asyncio
    async def test_list_access_control_configs(self, cloudfront_handler_init: AWSCloudFrontHandler):
        """Tests listing access control configurations (geo-restrictions, WAF)."""
        logger.info("Running test_list_access_control_configs...")
        access_controls = await cloudfront_handler_init.list_access_control_configs()
        assert isinstance(access_controls, list)
        assert access_controls is not None
        logger.info(f"test_list_access_control_configs: Got {len(access_controls)} access control configurations.")
