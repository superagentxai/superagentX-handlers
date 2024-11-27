import logging
import os

import pytest
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

from superagentx_handlers.atlassian.confluence import ConfluenceHandler
from superagentx_handlers.atlassian.jira import JiraHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/agent/test_atlassian_agent.py::TestAtlassianAgent::test_atlassian_agent
'''


@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gpt-4o', 'llm_type': 'openai'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client, 'llm_type': 'openai'}
    return response


class TestAtlassianAgent:

    async def test_atlassian_agent(
            self,
            agent_client_init: dict
    ):
        llm_client: LLMClient = agent_client_init.get('llm')
        jira_handler = JiraHandler(
            email=os.getenv('ATLASSIAN_EMAIL'),
            token=os.getenv('ATLASSIAN_TOKEN'),
            organization=os.getenv('ATLASSIAN_ORGANIZATION')
        )

        confluence_handler = ConfluenceHandler(
            email=os.getenv('ATLASSIAN_EMAIL'),
            token=os.getenv('ATLASSIAN_TOKEN'),
            organization=os.getenv('ATLASSIAN_ORGANIZATION'),
        )
        prompt_template = PromptTemplate()
        jira_engine = Engine(
            handler=jira_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )

        confluence_engine = Engine(
            handler=confluence_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )
        atlassian_agent = Agent(
            goal="Get a proper answer for asking a question in atlassian.",
            role="You are the Atlassian admin",
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[jira_engine, confluence_engine],
            max_retry=1
        )

        result = await atlassian_agent.execute(
            query_instruction="Give me all the spaces"
        )
        logger.info(f"Result => {result}")

        assert result
