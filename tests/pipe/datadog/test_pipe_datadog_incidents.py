import logging

import pytest
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

from superagentx_handlers.datadog import DDIncidentsHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/datadog/test_pipe_datadog_incidents.py::TestPipeDDIncidents::test_pipe_dd_incidents
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.0-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestPipeDDIncidents:
    async def test_pipe_dd_incidents(self, agent_client_init: dict):
        llm_client : LLMClient = agent_client_init.get('llm')

        handler = DDIncidentsHandler()

        prompt = PromptTemplate()

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal="To help retrieving incidents from the Datadog",
            role="AI Datadog Assistant",
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="Collect the latest Incidents")

        logger.debug(f"Result =>{result}")