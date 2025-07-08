import logging
import pytest

from superagentx_handlers.aws.elasticache import AWSElasticCacheHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1. pytest --log-cli-level=INFO tests/handlers/aws/test_aws_elasticache.py::TestAWSElastiCacheHandler::test_get_elasticache_functions_info

'''


@pytest.fixture
def elasticache_handler_init() -> AWSElasticCacheHandler:
    return AWSElasticCacheHandler()


class TestAWSElastiCacheHandler:

    async def test_get_elasticache_functions_info(self, elasticache_handler_init: AWSElasticCacheHandler):
        result = await elasticache_handler_init.get_elastic_cache_details()
        logger.info(f"AWS ElastiCache Results: {result}")
        assert isinstance(result, dict)
