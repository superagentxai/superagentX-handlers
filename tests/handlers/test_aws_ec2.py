import os
import pytest

from superagentx_handlers import AWSEC2Handler

'''
 Run Pytest:  

   1.pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2::test_ec2_handler_get_all_instances
   2.pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2::test_ec2_handler_get_all_running_instance
   3.pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2::test_ec2_handler_get_instance_status
   4.pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2::test_ec2_handler_get_all_stop_instance

'''


@pytest.fixture
def aws_ec2_client_init() -> AWSEC2Handler:
    ec2_handler = AWSEC2Handler()
    return ec2_handler


class TestAWSEC2:

    async def test_ec2_handler_get_all_instances(self, aws_ec2_client_init: AWSEC2Handler):
        await aws_ec2_client_init.get_all_instances()


    async def test_ec2_handler_get_all_running_instance(self, aws_ec2_client_init: AWSEC2Handler):
        ec2_handler = await aws_ec2_client_init.get_all_running_instance(
            instance_id="i-036aba9f3527bf366"
        )
        assert isinstance(ec2_handler, dict)


    async def test_ec2_handler_get_instance_status(self, aws_ec2_client_init: AWSEC2Handler):
        ec2_handler = await aws_ec2_client_init.get_instance_status(
            instance_id="i-036aba9f3527bf366"
        )
        assert isinstance(ec2_handler, dict)


    async def test_ec2_handler_get_all_stop_instance(self, aws_ec2_client_init: AWSEC2Handler):
        ec2_handler = await aws_ec2_client_init.get_all_stop_instance(
            instance_id="i-036aba9f3527bf366"
        )
        assert isinstance(ec2_handler, dict)
