import pytest
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.handler.ai import AIHandler
from superagentx.io import IOConsole
from superagentx.llm import LLMClient
from superagentx.memory import Memory
from superagentx.prompt import PromptTemplate

from superagentx_handlers.ecommerce.amazon import AmazonHandler
from superagentx_handlers.ecommerce.flipkart import FlipkartHandler

'''
 Run Pytest:  

   1. pytest -s --log-cli-level=INFO tests/pipe/test_pipe_ecom.py::TestEcommercePipe::test_ecom_pipe
'''


@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gpt-4o', 'llm_type': 'openai'}
    # llm_config = {'model': 'anthropic.claude-3-5-sonnet-20240620-v1:0', 'llm_type': 'bedrock', 'async_mode': True}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response


class TestEcommercePipe:

    async def test_ecom_pipe(self, agent_client_init: dict):
        llm_client: LLMClient = agent_client_init.get('llm')
        amazon_ecom_handler = AmazonHandler()
        flipkart_ecom_handler = FlipkartHandler()
        ai_handler = AIHandler(
            llm=llm_client
        )
        prompt_template = PromptTemplate()
        amazon_engine = Engine(
            handler=amazon_ecom_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )
        flipkart_engine = Engine(
            handler=flipkart_ecom_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )
        ai_engine = Engine(
            handler=ai_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )
        memory = Memory()
        ecom_agent = Agent(
            name="Ecom Agent",
            goal="Get me the best search results",
            role="You are the best product searcher",
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[[amazon_engine, flipkart_engine]]
        )
        price_review_agent = Agent(
            name="Price Review Agent",
            goal="Get me the best one from the given context",
            role="You are the price reviewer",
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[ai_engine]
        )
        pipe = AgentXPipe(
            agents=[ecom_agent, price_review_agent],
            memory=memory
        )
        io = IOConsole(
            read_phrase="\n\n\nEnter your query here:\n\n=>",
            write_phrase="\n\n\nYour result is =>\n\n"
        )
        while True:
            input_instruction = await io.read()
            result = await pipe.flow(query_instruction=input_instruction)
            await io.write(result)
