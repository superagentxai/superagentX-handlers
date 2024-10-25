import logging
import os

import pytest
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx_handlers.google.gmail import GmailHandler
from superagentx_handlers.crm.hubspot_crm import HubSpotHandler
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate


logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_pipe_email_hubspot.py::TestPipeEmailHubSpot::test_pipe_email_hubspot
'''


@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gpt-4o', 'llm_type': 'openai'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response


class TestPipeEmailHubSpot:

    async def test_pipe_email_hubspot(self, agent_client_init: dict):
        llm_client: LLMClient = agent_client_init.get('llm')
        gmail_handler = GmailHandler(
            credentials="/Users/arulvivek/Desktop/Agentx/Google/credentials.json"
        )
        hubspot_handler = HubSpotHandler(
            token=os.getenv("HUBSPOT_TOKEN")
        )
        prompt_template = PromptTemplate()
        gmail_engine = Engine(
            handler=gmail_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )
        hubspot_engine = Engine(
            handler=hubspot_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )
        gmail_agent = Agent(
            goal="To read the last email info",
            role="Yor are the best Gmail helper",
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[gmail_engine],
        )
        hubspot_agent = Agent(
            goal="Create a ticket in hubspot and get the ticket id",
            role="Yor are the hubspot admin",
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[hubspot_engine],
        )
        pipe = AgentXPipe(
            agents=[gmail_agent, hubspot_agent]
        )
        result = await pipe.flow(
            query_instruction="Get the email result and create new ticket in hubspot"
        )
        logger.info(f"Result => {result}")
