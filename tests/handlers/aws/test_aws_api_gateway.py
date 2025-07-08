import logging
import pytest

from superagentx_handlers.aws.api_gateway import AWSAPIGatewayHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/aws/test_aws_api_gateway.py::TestAWSAPIGatewayHandler::test_get_api_gateway_info

'''


@pytest.fixture
def api_gateway_handler_init() -> AWSAPIGatewayHandler:
    return AWSAPIGatewayHandler()


class TestAWSAPIGatewayHandler:

    async def test_get_api_gateway_info(self, api_gateway_handler_init: AWSAPIGatewayHandler):
        result = await api_gateway_handler_init.get_all_api_gateways_info()
        logger.info(f"AWS API Gateway Results: {result}")
        assert isinstance(result, dict)
