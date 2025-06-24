import logging

from superagentx_handlers import AWSIAMHandler
import pytest

logger = logging.getLogger(__name__)

'''
 Run Pytest:

   1.pytest --log-cli-level=INFO tests/handlers/test_aws_iam.py::TestAWSIAM::test_collect_all_iam

'''


@pytest.fixture
def aws_iam_client_init() -> AWSIAMHandler:
    iam_handler = AWSIAMHandler()
    return iam_handler


class TestAWSIAM:

    async def test_list_iam_users_with_details(self, aws_iam_client_init: AWSIAMHandler):
        user_details = await aws_iam_client_init.list_iam_users_with_details()
        assert isinstance(user_details, list)
        assert len(user_details) > 0

    async def test_get_credential_report(self, aws_iam_client_init: AWSIAMHandler):
        report = await aws_iam_client_init.get_credential_report()
        assert isinstance(report, dict)
        assert report != {}

    async def test_get_account_password_policy(self, aws_iam_client_init: AWSIAMHandler):
        password_policy = await aws_iam_client_init.get_account_password_policy()
        assert isinstance(password_policy, dict)
        assert password_policy != {}

    async def test_list_iam_roles_with_details(self, aws_iam_client_init: AWSIAMHandler):
        iam_role_policy = await aws_iam_client_init.list_iam_roles_with_details()
        assert isinstance(iam_role_policy, list)
        assert len(iam_role_policy) > 0

    async def test_list_iam_groups_with_details(self, aws_iam_client_init: AWSIAMHandler):
        iam_group = await aws_iam_client_init.list_iam_groups_with_details()
        assert isinstance(iam_group, list)
        assert len(iam_group) > 0

    async def test_list_iam_managed_policies_with_documents(self, aws_iam_client_init: AWSIAMHandler):
        iam_managed_policy = await aws_iam_client_init.list_iam_managed_policies_with_documents()
        assert isinstance(iam_managed_policy, list)
        assert len(iam_managed_policy) > 0

    async def test_collect_all_iam(self, aws_iam_client_init: AWSIAMHandler):
        all_iam = await aws_iam_client_init.collect_all_iam()
        assert isinstance(all_iam, dict)
        assert all_iam != {}

    async def test_list_mfa_enabled_users(self, aws_iam_client_init: AWSIAMHandler):
        mfa_device = await aws_iam_client_init.list_mfa_enabled_users()
        assert isinstance(mfa_device, list)
        assert len(mfa_device) > 0

    async def test_get_account_summary(self, aws_iam_client_init: AWSIAMHandler):
        account_summary = await aws_iam_client_init.get_account_summary()
        assert isinstance(account_summary, dict)
        assert account_summary != {}

    async def test_list_virtual_mfa_devices(self, aws_iam_client_init: AWSIAMHandler):
        virtual_mfa = await aws_iam_client_init.list_virtual_mfa_devices()
        assert isinstance(virtual_mfa, list)
        assert len(virtual_mfa) > 0

    async def test_get_account_authorization_details(self, aws_iam_client_init: AWSIAMHandler):
        account_authorization = await aws_iam_client_init.get_account_authorization_details()
        assert isinstance(account_authorization, dict)
        assert account_authorization != {}

    async def test_list_account_aliases(self, aws_iam_client_init: AWSIAMHandler):
        aliases = await aws_iam_client_init.list_account_aliases()
        assert isinstance(aliases, list)
        assert len(aliases) > 0
