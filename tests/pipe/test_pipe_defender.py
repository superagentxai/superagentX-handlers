import logging
import pytest

from superagentx_handlers.defender import DefenderHandler
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO test_pipe_github.py::TestPipeGitHub::test_pipe_github
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.5-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestPipeDefender:
    @pytest.mark.asyncio
    async def test_pipe_defender(self, agent_client_init: dict):

        llm_client : LLMClient = agent_client_init.get('llm')

        handler = DefenderHandler()

        prompt = PromptTemplate()

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal=(
                "Help users retrieve, filter, and understand Windows Defender Firewall rules, "
                "including port restrictions and application-level access settings."
            ),
            role=(
                "An intelligent security assistant that can query the Windows Defender Firewall, "
                "list rules, identify blocked ports, and show which applications have access."
            ),
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt,
            max_retry=2
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="List restrict rules for ports 80.")

        logger.info("\nFirewall Query Result:\n")
        logger.info(result)

