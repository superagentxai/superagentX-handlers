import pytest
import logging
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate
from superagentx_handlers import AzureApplicationGatewayHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/azure/test_azure_application_gateway_pipe.py::TestAzureApplicationGatewayPipe::test_azure_application_gateway_pipe
'''

@pytest.fixture
def pipe_client_init() -> dict:
    # llm_config = {'model': 'gpt-4-turbo-2024-04-09', 'llm_type': 'openai'}
    llm_config = {'model': 'gemini-2.5-flash', 'llm_type': 'gemini'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestAzureApplicationGatewayPipe:

    async def test_azure_application_gateway_pipe(self, pipe_client_init: dict):
        llm_client: LLMClient = pipe_client_init.get('llm')
        azure_vm_handler = AzureApplicationGatewayHandler()
        prompt_template = PromptTemplate(system_message=f"You are an Azure Application Gateway for GRC")
        engine = Engine(
            llm=llm_client,
            prompt_template=prompt_template,
            handler=azure_vm_handler
        )
        ec2_agent = Agent(
            name=f"Azure Application Gateway Agent",
            goal="Generate the response and data based on the user input.",
            role=f"You are a GRC Evidence Collection Expert.",
            llm=llm_client,
            prompt_template=prompt_template,
            max_retry=2,
            engines=[engine],
        )
        pipe = AgentXPipe(
            agents=[ec2_agent]
        )
        prompt = f"""
        If the task has implementing or creating, you just collect evidence the data implemented or created not try to implement.
        """
        query_instruct = "Are HTTP/2 protocols enabled? If yes, is TLS termination enforced?"
        result = await pipe.flow(
            query_instruction=f"{prompt}\n\nTool:Azure Application Gateway\n\nTask:{query_instruct}"
        )
        logger.info(result)