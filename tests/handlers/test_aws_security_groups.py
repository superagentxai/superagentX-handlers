import pytest
import logging

from superagentx_handlers import AWSSecurityGroupsHandler

logger = logging.getLogger(__name__)

"""
Run Pytest for EC2 Security Group GRC Evidence Collection:

1. pytest --log-cli-level=INFO tests/handlers/test_aws_security_groups.py::TestAWSSecurityGroups::test_get_ec2_security_groups
"""

@pytest.fixture
def ec2_handler_init():
    return AWSSecurityGroupsHandler(

    )

@pytest.mark.asyncio
class TestAWSSecurityGroups:

    async def test_get_ec2_security_groups(self, ec2_handler_init: AWSSecurityGroupsHandler):

        aws_sgs = await ec2_handler_init.get_ec2_security_groups()
        logger.info(aws_sgs)

