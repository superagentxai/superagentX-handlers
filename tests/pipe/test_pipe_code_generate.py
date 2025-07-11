import logging

import pytest

from superagentx_handlers.code_gen import CodeHandler
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_pipe_code_generate.py::TestPipeCodeGenerator::test_pipe_code_generate
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.0-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestPipeCodeGenerator:
    async def test_pipe_code_generate(self, agent_client_init: dict):
        llm_client : LLMClient = agent_client_init.get('llm')

        handler = CodeHandler(llm=llm_client)

        prompt = PromptTemplate()

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal="To generate code as per the user request.",
            role="AI Code Generator",
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="Generate code to solve minesweeper problem using Dynamic Programming")

        logger.debug(f"Result =>{result}")
