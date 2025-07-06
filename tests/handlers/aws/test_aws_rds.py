import logging
import pytest

from superagentx_handlers.aws.rds import AWSRDSHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/aws/test_aws_rds.py::TestAWSRDSHandler::test_get_lambda_functions_info

'''


@pytest.fixture
def rds_handler_init() -> AWSRDSHandler:
    return AWSRDSHandler()


class TestAWSRDSHandler:

    async def test_get_lambda_functions_info(self, rds_handler_init: AWSRDSHandler):
        result = await rds_handler_init.get_rds_association_details()
        logger.info(f"AWS RDS Results: {result}")
        assert isinstance(result, dict)
