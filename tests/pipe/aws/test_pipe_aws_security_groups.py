import pytest
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate
from superagentx_handlers import AWSSecurityGroupsHandler
from superagentx_handlers.twitter import logger

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_pipe_aws_security_groups.py::TestAWSSecurityGroupsPipe::test_aws_security_groups_pipe
'''

@pytest.fixture
def pipe_client_init() -> dict:
    # llm_config = {'model': 'gpt-4-turbo-2024-04-09', 'llm_type': 'openai'}
    llm_config = {'model': 'gpt-4o', 'llm_type': 'openai'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestAWSSecurityGroupsPipe:

    async def test_aws_security_groups_pipe(self, pipe_client_init: dict):
        llm_client: LLMClient = pipe_client_init.get('llm')
        aws_sg_handler = AWSSecurityGroupsHandler(
            # aws_access_key_id="<ACCESS_KEY>",
            # aws_secret_access_key="<SECRET_ACCESS_KEY",
            # region_name="<REGION>"
        )
        prompt_template = PromptTemplate(system_message=f"You are an AWS Security Groups for GRC.")
        engine = Engine(
            llm=llm_client,
            prompt_template=prompt_template,
            handler=aws_sg_handler
        )
        aws_sg_agent = Agent(
            name=f"AWS Security Groups Agent",
            goal="Generate the response and data based on the user input.",
            role=f"You are a GRC Evidence Collection Expert.",
            llm=llm_client,
            prompt_template=prompt_template,
            max_retry=2,
            engines=[engine],
        )
        pipe = AgentXPipe(
            agents=[aws_sg_agent]
        )
        prompt = f"""
        If the task has implementing or creating, you just collect evidence the data implemented or created not try to implement.
        """
        query_instruct = "Implementing firewall to protect networks connected to internet"
        result = await pipe.flow(
            query_instruction=f"{prompt}\n\nTool:AWS Security Groups\n\nTask:{query_instruct}"
        )
        logger.info(result)

