import logging
import pytest

from superagentx_handlers.aws.serverless import AWSLambdaHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/aws/test_aws_lambda.py::TestAWSLambdaHandler::test_get_lambda_functions_info
       
'''


@pytest.fixture
def lambda_handler_init() -> AWSLambdaHandler:
    return AWSLambdaHandler()


class TestAWSLambdaHandler:

    async def test_get_lambda_functions_info(self, lambda_handler_init: AWSLambdaHandler):
        result = await lambda_handler_init.get_lambda_functions()
        logger.info(f"Lambda Serverless Results: {result}")
        assert isinstance(result, list)
