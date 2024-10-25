import logging
import pytest

from superagentx_handlers import AWSEC2Handler

logger = logging.getLogger(__name__)

'''
 Run Pytest:
 
   1.pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2::test_ec2_handler_get_all_running_instances
   2.pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2::test_ec2_handler_get_all_stopped_instances

'''


@pytest.fixture
def aws_ec2_client_init() -> AWSEC2Handler:
    ec2_handler = AWSEC2Handler()
    return ec2_handler


class TestAWSEC2:

    # To test to get all running instances
    async def test_ec2_handler_get_all_running_instances(self, aws_ec2_client_init: AWSEC2Handler):
        ec2_handler = await aws_ec2_client_init.get_all_running_instances()
        assert isinstance(ec2_handler, list)
        assert len(ec2_handler) > 0
        assert ec2_handler[0]["State"]["Name"] == "running"

    # To test to get all stopped instances
    async def test_ec2_handler_get_all_stopped_instances(self, aws_ec2_client_init: AWSEC2Handler):
        ec2_handler = await aws_ec2_client_init.get_all_stopped_instances()
        assert isinstance(ec2_handler, list)
        assert len(ec2_handler) > 0
        assert ec2_handler[0]["State"]["Name"] == "stopped"