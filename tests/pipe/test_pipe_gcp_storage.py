import logging
import os

import pytest
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx_handlers.gcp.gcp_storage import GcpStorageInfoCollector
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_pipe_gcp_storage.py::TestPipeGCPStorage::test_pipe_gcp_storage
'''


@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.0-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response


class TestPipeGCPStorage:

    async def test_pipe_gcp_storage(self, agent_client_init: dict):
        llm_client: LLMClient = agent_client_init.get('llm')
        storage_handler = GcpStorageInfoCollector()
        prompt_template = PromptTemplate()
        storage_engine = Engine(
            handler=storage_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )

        storage_agent = Agent(
            goal="To provide info about various features available in the GCP Storage service.",
            role="Agent to provide info about GCP Storage service",
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[storage_engine],
        )

        pipe = AgentXPipe(
            agents=[storage_agent]
        )
        result = await pipe.flow(
            query_instruction="List all the available buckets."
        )
        logger.info(f"Result => {result}")
