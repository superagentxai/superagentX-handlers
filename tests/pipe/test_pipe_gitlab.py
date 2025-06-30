import logging
import os

import pytest

from superagentx_handlers.gitlab_details import GitlabHandler
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_pipe_gitlab.py::TestPipeGitLab::test_pipe_gitlab
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.0-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestPipeGitLab:
    async def test_pipe_gitlab(self, agent_client_init: dict):
        llm_client : LLMClient = agent_client_init.get('llm')

        handler = GitlabHandler()

        prompt = PromptTemplate()

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal="To help retrieving information about the GitLab user profile",
            role="AI GitLab Assistant",
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="Collect the GitLab user profile,")

        logger.debug(f"Result =>{result}")