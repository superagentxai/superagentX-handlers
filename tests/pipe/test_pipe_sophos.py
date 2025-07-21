import logging
import pytest

from superagentx_handlers.sophos import SophosHandler
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   pytest --log-cli-level=INFO test_pipe_sophos.py::TestPipeSophos::test_pipe_sophos
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.5-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    return {'llm': llm_client}


class TestPipeSophos:
    @pytest.mark.asyncio
    async def test_pipe_sophos(self, agent_client_init: dict):
        llm_client: LLMClient = agent_client_init['llm']

        handler = SophosHandler()

        prompt = PromptTemplate()

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal=(
                "Assist users in retrieving threat protection, antivirus status, firewall rules, "
                "and application control policy data from Sophos Central."
            ),
            role=(
                "A cybersecurity assistant that interacts with the Sophos Central API to help monitor and audit endpoint protection."
            ),
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt,
            max_retry=2
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="Show me devices with outdated antivirus.")

        logger.info("\nSophos API Query Result:\n")
        logger.info(result)
