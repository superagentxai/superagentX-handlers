import logging
import pytest

from superagentx_handlers.gcp.cloud_run import GCPCloudRunHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/gcp/test_gcp_cloud_run.py::TestGCPCloudRunHandler::test_get_cloud_run_info

'''


@pytest.fixture
def cloud_run_handler_init() -> GCPCloudRunHandler:
    return GCPCloudRunHandler()


class TestGCPCloudRunHandler:

    async def test_get_cloud_run_info(self, cloud_run_handler_init: GCPCloudRunHandler):
        result = await cloud_run_handler_init.get_gcp_cloud_run_details()
        assert result is not None
        assert 'services' in result
        assert 'summary' in result
        assert 'project_id' in result
        logger.info(f"GCP Cloud Run Results: {result}")
