import logging
import os

import pytest
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate


from superagentx_handlers import SQLHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/agent/test_chat_with_db.py::TestChatWithDB::test_chat_with_db
'''


@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gpt-5-mini', 'llm_type': 'azure-openai'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client, 'llm_type': 'azure-openai'}
    return response


class TestChatWithDB:

    async def test_chat_with_db(
            self,
            agent_client_init: dict
    ):
        llm_config  = {'model': 'gpt-5-mini', 'llm_type': 'azure-openai'}
        llm_client: LLMClient = agent_client_init.get('llm')
        sql_handler = SQLHandler(
            llm=llm_config,
            database_type="postgres",
            database="ai_chatbot",
            host="localhost",
            port=5432,
            username="chatbot_user",
            password="chatbot123"
        )
        prompt_template = PromptTemplate(
            system_message="""
        You are an intelligent Database AI Assistant.

        You can interact with a database using provided tools.

        Responsibilities:
        - Understand user questions in natural language
        - Decide when to interact with the database
        - Use the appropriate tool to query the database
        - Convert natural language into SQL queries when needed
        - Return accurate, concise, and structured responses

        Tool Usage Rules:
        - ALWAYS use the database tool when the question requires data retrieval
        - DO NOT generate answers without querying the database if data is required
        - Use the tool to:
            - Fetch data
            - Analyze records
            - Answer factual queries

        Behavior:
        - If the query is about data → interact with DB
        - If the query is not DB-related → answer normally
        - If no data found → clearly state it

        Avoid:
        - Hallucinating data
        - Making assumptions without querying the database
        """
        )
        agent = Agent(
            goal="""
            Answer user questions by interacting with the database.
            Convert natural language into SQL queries, execute them,
            and return meaningful results with insights when needed.
            """,

            role="""
            You are a Database AI Agent and SQL expert.
            You specialize in translating natural language into SQL,
            querying databases, and explaining results clearly.
            """,
            llm=llm_client,
            prompt_template=prompt_template,
            tool=sql_handler,
            max_retry=1
        )

        pipe = AgentXPipe(agents=[agent])

        result = await pipe.flow(
            query_instruction="list out all users"
        )
        logger.info(f"Result => {result}")

        assert result
