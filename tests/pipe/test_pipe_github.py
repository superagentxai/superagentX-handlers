import logging
import os


import pytest

from superagentx_handlers.github_handler import GitHubHandler
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1.  python -m pytest --log-cli-level=INFO test_pipe_github.py::TestPipeGitHub::test_pipe_github
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.0-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestPipeGitHub:
    @pytest.mark.asyncio
    async def test_pipe_github(self, agent_client_init: dict):
        github_token = os.getenv("GITHUB_TOKEN")

        if not github_token:
            print("ERROR: GITHUB_TOKEN environment variable not set. Please set it.")
            return

        llm_client : LLMClient = agent_client_init.get('llm')

        handler = GitHubHandler(github_token=github_token)

        prompt = PromptTemplate()

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal="Provide comprehensive details about GitHub organizations and user accounts, including general profile information like repository counts, and compliance-related evidence such as Multi-Factor Authentication (MFA) registration status for GRC (Governance, Risk, and Compliance) purposes.Your response MUST be valid JSON.",
            role="An intelligent agent that can retrieve various types of information from GitHub, specializing in both general user/organization details and compliance-related evidence like MFA status.",
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="get the details of the user")

        logger.info(result)
        #logger.info(f"result => \n{result}")

