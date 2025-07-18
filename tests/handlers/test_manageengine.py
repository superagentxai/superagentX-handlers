# test_manageengine.py
import os
import pytest
import pytest_asyncio
import logging

# Import your ManageEngineHandler
from superagentx_handlers import ManageEngineHandler  # Assuming the file is named tenable_io_handler.py

logger = logging.getLogger(__name__)

'''
 Run Pytest for ManageEngine Handler (Tenable.io Integration):

   1. pytest --log-cli-level=INFO test_manageengine.py::TestManageEngineHandler::test_list_assets
   2. pytest --log-cli-level=INFO test_manageengine.py::TestManageEngineHandler::test_get_asset_info
   3. pytest --log-cli-level=INFO test_manageengine.py::TestManageEngineHandler::test_list_scans
   4. pytest --log-cli-level=INFO test_manageengine.py::TestManageEngineHandler::test_get_scan_details
   5. pytest --log-cli-level=INFO test_manageengine.py::TestManageEngineHandler::test_get_scan_history
   6. pytest --log-cli-level=INFO test_manageengine.py::TestManageEngineHandler::test_get_scan_history_details
   7. pytest --log-cli-level=INFO test_manageengine.py::TestManageEngineHandler::test_import_vulnerabilities

 Remember to set your Tenable.io environment variables for a TEST/DEVELOPMENT account (NOT production) before running:
 export TENABLE_ACCESS_KEY="your_tenable_access_key"
 export TENABLE_SECRET_KEY="your_tenable_secret_key"
 export TENABLE_IO_BASE_URL="https://cloud.tenable.com" # Or your Nessus Manager/Tenable.sc URL

 For tests requiring specific IDs, set these (use actual IDs from your Tenable.io environment):
 export TEST_TENABLE_ASSET_ID="your_test_asset_id" # e.g., an asset UUID
 export TEST_TENABLE_SCAN_ID="your_test_scan_id"   # e.g., an integer scan ID
 export TEST_TENABLE_HISTORY_ID="your_test_history_id" # e.g., an integer history ID for the above scan
 export TEST_TENABLE_IMPORT_FILE_ID="your_test_import_file_id" # A file_id from a previous file upload to Tenable.io
 export TEST_TENABLE_IMPORT_REPOSITORY_ID="your_test_import_repository_id" # An integer repository ID
'''


# --- Pytest Fixture ---
@pytest_asyncio.fixture(scope="module")
async def manageengine_handler_init() -> ManageEngineHandler:  # type: ignore
    """
    Initializes and provides a ManageEngineHandler instance for testing.
    It retrieves required credentials from environment variables.
    """
    access_key = os.getenv("TENABLE_ACCESS_KEY")
    secret_key = os.getenv("TENABLE_SECRET_KEY")
    base_url = os.getenv("TENABLE_IO_BASE_URL", "https://cloud.tenable.com")

    if not all([access_key, secret_key]):
        pytest.fail(
            "Missing Tenable.io credentials. Please set "
            "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY "
            "environment variables for testing."
        )

    handler = ManageEngineHandler(
        access_key=access_key,
        secret_key=secret_key,
        base_url=base_url
    )
    # The handler's __init__ already handles initialization logic and sets _is_initialized
    if not handler._is_initialized:
        pytest.fail("ManageEngineHandler failed to initialize. Check logs for details.")

    yield handler


# --- Test Class ---
class TestManageEngineHandler:
    """
    This test suite provides basic tests for the ManageEngineHandler's Tenable.io integration tools.
    These tests require actual Tenable.io credentials and potentially existing data.
    """

    @pytest.mark.asyncio
    async def test_list_assets(self, manageengine_handler_init: ManageEngineHandler):
        """Tests retrieving a list of assets."""
        logger.info("Running test_list_assets...")
        assets = await manageengine_handler_init.list_assets()
        assert isinstance(assets, list)
        assert assets is not None
        logger.info(f"test_list_assets: Got {len(assets)} assets.")

    @pytest.mark.asyncio
    async def test_get_asset_info(self, manageengine_handler_init: ManageEngineHandler):
        """Tests retrieving detailed information for a specific asset."""
        asset_id = os.getenv("TEST_TENABLE_ASSET_ID")
        if not asset_id:
            pytest.skip("TEST_TENABLE_ASSET_ID not set for get_asset_info test.")

        logger.info(f"Running test_get_asset_info for asset ID: {asset_id}...")
        asset_info = await manageengine_handler_init.get_asset_info(asset_id=asset_id)
        assert isinstance(asset_info, dict) or asset_info is None  # Can be None if not found
        if asset_info:
            assert "id" in asset_info
            assert asset_info["id"] == asset_id
        logger.info(f"test_get_asset_info: Asset info retrieved: {asset_info is not None}.")

    @pytest.mark.asyncio
    async def test_list_scans(self, manageengine_handler_init: ManageEngineHandler):
        """Tests retrieving a list of scans."""
        logger.info("Running test_list_scans...")
        scans = await manageengine_handler_init.list_scans()
        assert isinstance(scans, list)
        assert scans is not None
        logger.info(f"test_list_scans: Got {len(scans)} scans.")

    @pytest.mark.asyncio
    async def test_get_scan_details(self, manageengine_handler_init: ManageEngineHandler):
        """Tests retrieving detailed information for a specific scan."""
        scan_id = 0
        scan_id_str = os.getenv("TEST_TENABLE_SCAN_ID")
        if not scan_id_str:
            pytest.skip("TEST_TENABLE_SCAN_ID not set for get_scan_details test.")

        try:
            scan_id = int(scan_id_str)
        except ValueError:
            pytest.fail("TEST_TENABLE_SCAN_ID must be an integer.")

        logger.info(f"Running test_get_scan_details for scan ID: {scan_id}...")
        scan_details = await manageengine_handler_init.get_scan_details(scan_id=scan_id)
        assert isinstance(scan_details, dict) or scan_details is None
        if scan_details:
            assert "id" in scan_details
            assert scan_details["id"] == scan_id
        logger.info(f"test_get_scan_details: Scan details retrieved: {scan_details is not None}.")

    @pytest.mark.asyncio
    async def test_get_scan_history(self, manageengine_handler_init: ManageEngineHandler):
        """Tests retrieving the history of a specific scan."""
        scan_id = 0
        scan_id_str = os.getenv("TEST_TENABLE_SCAN_ID")
        if not scan_id_str:
            pytest.skip("TEST_TENABLE_SCAN_ID not set for get_scan_history test.")

        try:
            scan_id = int(scan_id_str)
        except ValueError:
            pytest.fail("TEST_TENABLE_SCAN_ID must be an integer.")

        logger.info(f"Running test_get_scan_history for scan ID: {scan_id}...")
        scan_history = await manageengine_handler_init.get_scan_history(scan_id=scan_id)
        assert isinstance(scan_history, list)
        assert scan_history is not None
        logger.info(f"test_get_scan_history: Got {len(scan_history)} history entries for scan {scan_id}.")

    @pytest.mark.asyncio
    async def test_get_scan_history_details(self, manageengine_handler_init: ManageEngineHandler):
        """Tests retrieving detailed information for a specific scan history entry."""
        scan_id_str = os.getenv("TEST_TENABLE_SCAN_ID")
        history_id_str = os.getenv("TEST_TENABLE_HISTORY_ID")
        scan_id = 0
        history_id = 0
        if not scan_id_str or not history_id_str:
            pytest.skip("TEST_TENABLE_SCAN_ID or TEST_TENABLE_HISTORY_ID not set for get_scan_history_details test.")

        try:
            scan_id = int(scan_id_str)
            history_id = int(history_id_str)
        except ValueError:
            pytest.fail("TEST_TENABLE_SCAN_ID and TEST_TENABLE_HISTORY_ID must be integers.")

        logger.info(f"Running test_get_scan_history_details for scan ID {scan_id}, history ID {history_id}...")
        history_details = await manageengine_handler_init.get_scan_history_details(
            scan_id=scan_id, history_id=history_id
        )
        assert isinstance(history_details, dict) or history_details is None
        if history_details:
            assert "history_id" in history_details
            assert history_details["history_id"] == history_id
        logger.info(f"test_get_scan_history_details: History details retrieved: {history_details is not None}.")

    @pytest.mark.asyncio
    async def test_import_vulnerabilities(self, manageengine_handler_init: ManageEngineHandler):
        """Tests importing vulnerability data."""
        file_id = os.getenv("TEST_TENABLE_IMPORT_FILE_ID")
        repository_id_str = os.getenv("TEST_TENABLE_IMPORT_REPOSITORY_ID")

        if not file_id or not repository_id_str:
            pytest.skip(
                "TEST_TENABLE_IMPORT_FILE_ID or TEST_TENABLE_IMPORT_REPOSITORY_ID not set for import_vulnerabilities test.")

        try:
            repository_id = int(repository_id_str)
        except ValueError:
            pytest.fail("TEST_TENABLE_IMPORT_REPOSITORY_ID must be an integer.")

        # Dummy asset data for import. In a real scenario, this would come from a scan.
        test_assets = [
            {
                "fqdn": "test-host-1.example.com",
                "ipv4": ["192.168.1.1"],
                "vulnerabilities": [
                    {
                        "plugin_id": 10180,  # Example Nessus plugin ID (e.g., for Host DNS Lookup)
                        "plugin_name": "Host DNS Lookup",
                        "severity": "info",
                        "description": "DNS resolution successful for test-host-1.",
                        "port": 0,
                        "protocol": "tcp"
                    }
                ]
            },
            {
                "fqdn": "test-host-2.example.com",
                "ipv4": ["192.168.1.2"],
                "vulnerabilities": [
                    {
                        "plugin_id": 10335,  # Example Nessus plugin ID (e.g., for HTTP Server Type and Version)
                        "plugin_name": "HTTP Server Type and Version",
                        "severity": "low",
                        "description": "Identified Apache HTTP Server 2.4.52.",
                        "port": 80,
                        "protocol": "tcp"
                    }
                ]
            }
        ]

        logger.info("Running test_import_vulnerabilities...")
        import_status = await manageengine_handler_init.import_vulnerabilities(
            source="security_center",  # As per API docs
            vuln_type="vm",  # As per API docs
            assets=test_assets
        )
        assert isinstance(import_status, dict)
        assert "status" in import_status  # Expecting a status key in response
        # The actual status might be 'success', 'pending', or 'error' depending on async processing
        logger.info(f"test_import_vulnerabilities: Import status: {import_status.get('status')}")

