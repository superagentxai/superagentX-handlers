import pytest
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate
from superagentx_handlers import AWSEC2Handler

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_pipe_aws_ec2.py::TestAWSEC2Pipe::test_aws_ec2_pipe
'''

@pytest.fixture
def pipe_client_init() -> dict:
    # llm_config = {'model': 'gpt-4-turbo-2024-04-09', 'llm_type': 'openai'}
    llm_config = {'model': 'gpt-4o', 'llm_type': 'openai'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestAWSEC2Pipe:

    async def test_aws_ec2_pipe(self, pipe_client_init: dict):
        llm_client: LLMClient = pipe_client_init.get('llm')
        aws_ec2_handler = AWSEC2Handler(
            aws_access_key_id="<ACCESS_KEY>",
            aws_secret_access_key="<SECRET_ACCESS_KEY",
            region_name="<REGION>"
        )
        prompt_template = PromptTemplate(system_message=f"You are an AWS EC2.")
        engine = Engine(
            llm=llm_client,
            prompt_template=prompt_template,
            handler=aws_ec2_handler
        )
        ec2_agent = Agent(
            name=f"AWS EC2 Agent",
            goal="Summarize the data based on the user input.",
            role=f"You are a Summarizer for EC2",
            llm=llm_client,
            prompt_template=prompt_template,
            max_retry=2,
            engines=[engine],
        )
        pipe = AgentXPipe(
            agents=[ec2_agent]
        )
        result = await pipe.flow(
            query_instruction="list out the instances and configured security group"
        )
        print(result)