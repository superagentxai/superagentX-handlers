import logging
import pytest

from superagentx_handlers.aws.ec2 import AWSEC2Handler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2GRCHandler::test_get_ec2_instances
    2. pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2GRCHandler::test_get_ec2_security_groups
    3. pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2GRCHandler::test_get_ec2_volumes
    4. pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2GRCHandler::test_get_ec2_amis
    5. pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2GRCHandler::test_get_ec2_snapshots
    6. pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2GRCHandler::test_get_ec2_key_pairs
    7. pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2GRCHandler::test_get_ec2_network_interfaces
    8. pytest --log-cli-level=INFO tests/handlers/test_aws_ec2.py::TestAWSEC2GRCHandler::test_collect_all_ec2    
'''


@pytest.fixture
def ec2_handler_init() -> AWSEC2Handler:
    return AWSEC2Handler()


class TestAWSEC2GRCHandler:

    async def test_get_ec2_instances(self, ec2_handler_init: AWSEC2Handler):
        result = await ec2_handler_init.get_ec2_instances()
        logger.info(f"Instances: {result}")
        assert isinstance(result, list)

    async def test_get_ec2_security_groups(self, ec2_handler_init: AWSEC2Handler):
        result = await ec2_handler_init.get_ec2_security_groups()
        logger.info(f"Security Groups: {result}")
        assert isinstance(result, list)

    async def test_get_ec2_volumes(self, ec2_handler_init: AWSEC2Handler):
        result = await ec2_handler_init.get_ec2_volumes()
        logger.info(f"EBS Volumes: {result}")
        assert isinstance(result, list)

    async def test_get_ec2_amis(self, ec2_handler_init: AWSEC2Handler):
        result = await ec2_handler_init.get_ec2_amis()
        logger.info(f"AMIs: {result}")
        assert isinstance(result, list)

    async def test_get_ec2_snapshots(self, ec2_handler_init: AWSEC2Handler):
        result = await ec2_handler_init.get_ec2_snapshots()
        logger.info(f"Snapshots: {result}")
        assert isinstance(result, list)

    async def test_get_ec2_key_pairs(self, ec2_handler_init: AWSEC2Handler):
        result = await ec2_handler_init.get_ec2_key_pairs()
        logger.info(f"Key Pairs: {result}")
        assert isinstance(result, list)

    async def test_get_ec2_network_interfaces(self, ec2_handler_init: AWSEC2Handler):
        result = await ec2_handler_init.get_ec2_network_interfaces()
        logger.info(f"Network Interfaces: {result}")
        assert isinstance(result, list)

    async def test_collect_all_ec2(self, ec2_handler_init: AWSEC2Handler):
        result = await ec2_handler_init.collect_all_ec2()
        logger.info(f"All GRC: {result}")
        assert isinstance(result, dict)
        assert "ec2_instances" in result
        assert isinstance(result["ec2_instances"], list)
