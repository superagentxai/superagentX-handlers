import logging
import pytest

from superagentx_handlers.defender365 import DefenderO365GetHandler
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   pytest --log-cli-level=INFO test_pipe_defender365.py::TestPipeDefender365::test_pipe_defender365
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.5-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    return {'llm': llm_client}


class TestPipeDefender365:
    @pytest.mark.asyncio
    async def test_pipe_defender365(self, agent_client_init: dict):
        llm_client: LLMClient = agent_client_init['llm']

        handler = DefenderO365GetHandler()

        prompt = PromptTemplate()

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal=(
                "Help users retrieve and analyze Microsoft Defender for Office 365 data, "
                "including email threats, user submissions, quarantined messages, and policy insights."
            ),
            role=(
                "A security assistant that uses PowerShell to access Microsoft Defender data and respond to security queries."
            ),
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt,
            max_retry=2
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="What are the Safe Attachments configurations?.")

        logger.info("\nDefender O365 Query Result:\n")
        logger.info(result)


