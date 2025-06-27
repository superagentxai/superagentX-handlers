# tests/test_entra_iam_handler.py
import logging
import pytest
import asyncio # Required for running async test functions
import os

import pytest_asyncio

# Import your EntraIAMHandler.
# Ensure your 'entra_iam_handler.py' file is accessible to this test file.
# For example, it could be in the same directory, or your project's structure
# might require adjusting the import path.
from Handlers.MicrosoftEntra.entra_iam import EntraIAMHandler 

logger = logging.getLogger(__name__)

# --- Pytest Run Commands (for your reference) ---
'''
To run these tests from your project's root directory (assuming 'tests' is a subdirectory):

To run a specific test:
pytest --log-cli-level=INFO test_entra_iam_handler.py::TestEntraIAM::test_collect_users_iam_evidence
pytest --log-cli-level=INFO test_entra_iam_handler.py::TestEntraIAM::test_collect_groups_iam_evidence
pytest --log-cli-level=INFO test_entra_iam_handler.py::TestEntraIAM::test_collect_applications_iam_evidence
pytest --log-cli-level=INFO test_entra_iam_handler.py::TestEntraIAM::test_collect_roles_definitions
pytest --log-cli-level=INFO test_entra_iam_handler.py::TestEntraIAM::test_collect_mfa_status_evidence
pytest --log-cli-level=INFO test_entra_iam_handler.py::TestEntraIAM::test_collect_all_entra_iam_evidence

To run all tests in this file:
pytest --log-cli-level=INFO test_entra_iam_handler.py

Remember to set your Microsoft Entra ID environment variables for a TEST/DEVELOPMENT tenant (NOT production) before running:
export AZURE_TENANT_ID="your_test_tenant_id"
export AZURE_CLIENT_ID="your_test_client_id"
export AZURE_CLIENT_SECRET="your_test_client_secret"
'''
# --- Pytest Fixture ---

@pytest_asyncio.fixture(scope="module") 
async def entra_iam_client_init() -> EntraIAMHandler: # type: ignore
    """
    Initializes and provides an EntraIAMHandler instance for testing.
    It retrieves required credentials from environment variables.
    """
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        pytest.fail(
            "Missing Microsoft Entra ID credentials. Please set "
            "AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET "
            "environment variables for testing."
        )
    
    # Initialize the handler. If credentials are bad or permissions are missing,
    # the handler's __init__ will raise an exception, causing the tests to fail early.
    handler = EntraIAMHandler(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    yield handler # Yield the initialized handler to the test functions

# --- Test Class ---

class TestEntraIAM:
    """
    This test suite validates the core read functionalities of the EntraIAMHandler.
    It performs basic type and content checks on the data collected from Microsoft Entra ID.
    """

    @pytest.mark.asyncio # Marks the test as an asynchronous function
    async def test_collect_users_iam_evidence(self, entra_iam_client_init: EntraIAMHandler):
        """
        Verifies that 'collect_users_iam_evidence' returns a non-empty list of user details.
        """
        logger.info("Running test_collect_users_iam_evidence...")
        user_details = await entra_iam_client_init.collect_users_iam_evidence()
        
        assert isinstance(user_details, list), "Expected user_details to be a list."
        assert len(user_details) > 0, "Expected to collect at least one user record."
        # Basic check for expected keys in the first user object
        if user_details:
            assert "id" in user_details[0]
            assert "displayName" in user_details[0]
            assert "userPrincipalName" in user_details[0]
        logger.info(f"test_collect_users_iam_evidence: Collected {len(user_details)} users.")

    @pytest.mark.asyncio
    async def test_collect_groups_iam_evidence(self, entra_iam_client_init: EntraIAMHandler):
        """
        Verifies that 'collect_groups_iam_evidence' returns a non-empty list of group details.
        """
        logger.info("Running test_collect_groups_iam_evidence...")
        group_details = await entra_iam_client_init.collect_groups_iam_evidence()
        
        assert isinstance(group_details, list), "Expected group_details to be a list."
        assert len(group_details) > 0, "Expected to collect at least one group record."
        if group_details:
            assert "id" in group_details[0]
            assert "displayName" in group_details[0]
        logger.info(f"test_collect_groups_iam_evidence: Collected {len(group_details)} groups.")

    @pytest.mark.asyncio
    async def test_collect_applications_iam_evidence(self, entra_iam_client_init: EntraIAMHandler):
        """
        Verifies that 'collect_applications_iam_evidence' returns a non-empty list of application (Service Principal) details.
        """
        logger.info("Running test_collect_applications_iam_evidence...")
        app_details = await entra_iam_client_init.collect_applications_iam_evidence()
        
        assert isinstance(app_details, list), "Expected app_details to be a list."
        # Note: In some test tenants, there might be no custom applications,
        # so you might need to adjust this assert if an empty list is valid.
        assert len(app_details) > 0, "Expected to collect at least one application (service principal) record." 
        if app_details:
            assert "id" in app_details[0]
            assert "displayName" in app_details[0]
            assert "appId" in app_details[0]
        logger.info(f"test_collect_applications_iam_evidence: Collected {len(app_details)} applications.")

    @pytest.mark.asyncio
    async def test_collect_roles_definitions(self, entra_iam_client_init: EntraIAMHandler):
        """
        Verifies that 'collect_roles_definitions' returns a non-empty list of role definitions.
        """
        logger.info("Running test_collect_roles_definitions...")
        role_definitions = await entra_iam_client_init.collect_roles_definitions()
        
        assert isinstance(role_definitions, list), "Expected role_definitions to be a list."
        assert len(role_definitions) > 0, "Expected to collect at least one role definition."
        if role_definitions:
            assert "id" in role_definitions[0]
            assert "displayName" in role_definitions[0]
        logger.info(f"test_collect_roles_definitions: Collected {len(role_definitions)} role definitions.")

    @pytest.mark.asyncio
    async def test_collect_mfa_status_evidence(self, entra_iam_client_init: EntraIAMHandler):
        """
        Verifies that 'collect_mfa_status_evidence' returns a non-empty list of user MFA status data.
        """
        logger.info("Running test_collect_mfa_status_evidence...")
        # You can pass 'days_ago' as needed for your test data, e.g., days_ago=7
        mfa_evidence = await entra_iam_client_init.collect_mfa_status_evidence(days_ago=7) 
        
        assert isinstance(mfa_evidence, list), "Expected mfa_evidence to be a list."
        # This assert relies on your test tenant having users with MFA data or recent sign-ins.
        assert len(mfa_evidence) > 0, "Expected to collect at least one user's MFA status."
        if mfa_evidence:
            first_mfa_user = mfa_evidence[0]
            assert "id" in first_mfa_user
            assert "isMfaRegistered" in first_mfa_user
            assert "recentMfaAttempts" in first_mfa_user
        logger.info(f"test_collect_mfa_status_evidence: Collected MFA status for {len(mfa_evidence)} users.")

    @pytest.mark.asyncio
    async def test_collect_all_entra_iam_evidence(self, entra_iam_client_init: EntraIAMHandler):
        """
        Verifies that 'collect_all_entra_iam_evidence' returns a dictionary with
        non-empty lists for each expected data type.
        """
        logger.info("Running test_collect_all_entra_iam_evidence...")
        all_iam_evidence = await entra_iam_client_init.collect_all_entra_iam_evidence()
        
        assert isinstance(all_iam_evidence, dict), "Expected all_iam_evidence to be a dictionary."
        assert all_iam_evidence != {}, "Expected all_iam_evidence dictionary not to be empty."
        
        # Check for the presence of each expected key and that their values are lists
        assert "users" in all_iam_evidence and isinstance(all_iam_evidence["users"], list)
        assert "groups" in all_iam_evidence and isinstance(all_iam_evidence["groups"], list)
        assert "applications" in all_iam_evidence and isinstance(all_iam_evidence["applications"], list)
        assert "roleDefinitions" in all_iam_evidence and isinstance(all_iam_evidence["roleDefinitions"], list)
        assert "mfaStatus" in all_iam_evidence and isinstance(all_iam_evidence["mfaStatus"], list)
        
        # Optionally, assert that each sub-list contains data (if expected in your test tenant)
        assert len(all_iam_evidence["users"]) > 0, "Expected 'users' list to be non-empty."
        assert len(all_iam_evidence["groups"]) > 0, "Expected 'groups' list to be non-empty."
        assert len(all_iam_evidence["applications"]) > 0, "Expected 'applications' list to be non-empty."
        assert len(all_iam_evidence["roleDefinitions"]) > 0, "Expected 'roleDefinitions' list to be non-empty."
        assert len(all_iam_evidence["mfaStatus"]) > 0, "Expected 'mfaStatus' list to be non-empty."
        
        logger.info("test_collect_all_entra_iam_evidence: Successfully collected all Entra IAM evidence.")