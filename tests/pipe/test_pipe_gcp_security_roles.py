import logging
import os

import pytest
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx_handlers.gcp.gcp_security_roles import GcpSecurityInfoCollector
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_pipe_gcp_security_roles.py::TestPipeGCPSecurityInfo::test_pipe_gcp_security_roles
'''


@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gemini-2.0-flash', 'llm_type': 'gemini'}
    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response


class TestPipeGCPSecurityInfo:

    async def test_pipe_gcp_security_roles(self, agent_client_init: dict):
        llm_client: LLMClient = agent_client_init.get('llm')
        security_roles_handler = GcpSecurityInfoCollector()
        prompt_template = PromptTemplate()
        security_roles_engine = Engine(
            handler=security_roles_handler,
            llm=llm_client,
            prompt_template=prompt_template
        )

        security_roles_agent = Agent(
            goal="To provide info about various features available in the GCP Security Info service.",
            role="Agent to provide info about GCP Security Info service",
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[security_roles_engine],
        )

        pipe = AgentXPipe(
            agents=[security_roles_agent]
        )
        result = await pipe.flow(
            query_instruction="List all security_roles info."
        )
        logger.info(f"Result => {result}")
