import logging
import pytest

from superagentx_handlers.aws.elb import AWSElasticLoadBalancerHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/aws/test_aws_elb.py::TestAWSElasticLoadBalancerHandler::test_get_elb_info

'''


@pytest.fixture
def elb_handler_init() -> AWSElasticLoadBalancerHandler:
    return AWSElasticLoadBalancerHandler()


class TestAWSElasticLoadBalancerHandler:

    async def test_get_elb_info(self, elb_handler_init: AWSElasticLoadBalancerHandler):
        result = await elb_handler_init.get_elb_details()
        logger.info(f"AWS ELB Results: {result}")
        assert isinstance(result, dict)
