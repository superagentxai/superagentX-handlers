import logging

import pytest

from superagentx_handlers.zohohirs import ZohoHIRSHandler
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_zoho_hirs.py::TestZohoHIRS::test_servicenow
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.0-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestZohoHIRS:
    async def test_zoho(self, agent_client_init: dict):
        llm_client : LLMClient = agent_client_init.get('llm')

        handler = ZohoHIRSHandler()

        prompt = PromptTemplate()

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal="To help retrieving information about the list of employees onboarding and offboarding.",
            role="Expert in retrieving Zoho employee list.",
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="Get me the list of employees .")

        logger.debug(f"Result =>{result}")
