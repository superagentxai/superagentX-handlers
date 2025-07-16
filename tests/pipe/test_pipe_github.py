import logging
import os


import pytest

from superagentx_handlers.github import GitHubHandler
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

class TestPipeGitHub:
    @pytest.mark.asyncio
    async def test_pipe_github(self, agent_client_init: dict):
        github_token = os.getenv("GITHUB_TOKEN")
        logger.info(github_token)
        if not github_token:
            print("ERROR: GITHUB_TOKEN environment variable not set. Please set it.")
            return

        llm_client : LLMClient = agent_client_init.get('llm')

        handler = GitHubHandler(github_token=github_token)

        prompt = PromptTemplate(system_message="You are a Github Expert.\n\n Example: You have access to a get_user_details tool. This tool can retrieve GitHub user information. If the user asks for details but doesn't specify a username, you should still call get_user_details without a username argument, as it will attempt to use a default or handle the missing value.")

        engine = Engine(
            handler=handler,
            llm=llm_client,
            prompt_template=prompt
        )

        agent = Agent(
            goal="Generate the response",
            role="An intelligent agent that can retrieve various types of information from GitHub, specializing in both general user/organization details and compliance-related evidence like MFA status.",
            llm=llm_client,
            engines=[engine],
            prompt_template=prompt,
            max_retry=2
        )

        pipe = AgentXPipe(
            agents=[agent],
        )

        result = await pipe.flow(query_instruction="List the branch protection for all my repositories")

        logger.info(result)
        logger.info(f"result =>{result}")

