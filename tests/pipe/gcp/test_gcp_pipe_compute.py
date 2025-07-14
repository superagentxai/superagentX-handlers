import logging

import pytest
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate
from superagentx_handlers.gcp.compute import GcpComputeHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_gcp_pipe_compute.py::TestPipeGCPCompute::test_pipe_gcp_compute
'''


@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.0-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response


class TestPipeGCPCompute:

    async def test_pipe_gcp_compute(self, agent_client_init: dict):
        llm_client: LLMClient = agent_client_init.get('llm')
        compute_handler = GcpComputeHandler()
        prompt_template = PromptTemplate()
        compute_engine = Engine(
            handler=compute_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )

        compute_agent = Agent(
            goal="To provide info about various features available in the GCP Compute service.",
            role="Agent to provide info about GCP Compute service",
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[compute_engine],
        )

        pipe = AgentXPipe(
            agents=[compute_agent]
        )
        result = await pipe.flow(
            query_instruction="List all compute info."
        )
        logger.info(f"Result => {result}")
