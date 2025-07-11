import pytest
import logging
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate
from superagentx_handlers import AWSS3Handler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/aws/test_aws_s3_pipe.py::TestAWSS3Pipe::test_aws_s3_pipe
'''

@pytest.fixture
def pipe_client_init() -> dict:
    # llm_config = {'model': 'gpt-4-turbo-2024-04-09', 'llm_type': 'openai'}
    llm_config = {'model': 'gpt-4o', 'llm_type': 'openai'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestAWSS3Pipe:

    async def test_aws_s3_pipe(self, pipe_client_init: dict):
        llm_client: LLMClient = pipe_client_init.get('llm')
        aws_s3_handler = AWSS3Handler()
        prompt_template = PromptTemplate(system_message=f"You are an AWS S3.")
        engine = Engine(
            llm=llm_client,
            prompt_template=prompt_template,
            handler=aws_s3_handler
        )
        s3_agent = Agent(
            name=f"AWS S3 Agent",
            goal="Summarize the data based on the user input.",
            role=f"You are a Summarizer for AWS S3",
            llm=llm_client,
            prompt_template=prompt_template,
            max_retry=2,
            engines=[engine],
        )
        pipe = AgentXPipe(
            agents=[s3_agent]
        )
        result = await pipe.flow(
            query_instruction="Encrypting sensitive data at rest"
        )
        logger.info(result)