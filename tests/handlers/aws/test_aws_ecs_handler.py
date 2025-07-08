import logging
import pytest

from superagentx_handlers.aws.ecs import AWSECSHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/aws/test_aws_ecs_handler.py::TestAWSECSHandler::test_get_ecs_info

'''


@pytest.fixture
def api_ecs_handler_init() -> AWSECSHandler:
    return AWSECSHandler()


class TestAWSECSHandler:

    async def test_get_ecs_info(self, api_ecs_handler_init: AWSECSHandler):
        result = await api_ecs_handler_init.get_all_ecs_data()
        logger.info(f"AWS ECS Results: {result}")
        assert isinstance(result, dict)