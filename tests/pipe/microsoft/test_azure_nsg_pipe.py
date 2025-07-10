import pytest
import logging
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate
from superagentx_handlers import AzureNSGHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/microsoft/test_azure_nsg_pipe.py::TestAzureNSGPipe::test_azure_nsg_pipe
'''

@pytest.fixture
def pipe_client_init() -> dict:
    # llm_config = {'model': 'gpt-4-turbo-2024-04-09', 'llm_type': 'openai'}
    llm_config = {'model': 'gpt-4o', 'llm_type': 'openai'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestAzureNSGPipe:

    async def test_azure_nsg_pipe(self, pipe_client_init: dict):
        llm_client: LLMClient = pipe_client_init.get('llm')
        azure_vm_handler = AzureNSGHandler()
        prompt_template = PromptTemplate(system_message=f"You are an Azure NSG for GRC")
        engine = Engine(
            llm=llm_client,
            prompt_template=prompt_template,
            handler=azure_vm_handler
        )
        ec2_agent = Agent(
            name=f"Azure NSG Agent",
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
        query_instruct = "Implementing firewall to protect networks connected to internet"
        result = await pipe.flow(
            query_instruction=f"{prompt}\n\nTool:Azure NSG\n\nTask:{query_instruct}"
        )
        logger.info(result)