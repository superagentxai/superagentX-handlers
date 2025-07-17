import pytest
import logging
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.agentxpipe import AgentXPipe
from superagentx.prompt import PromptTemplate
from superagentx_handlers import JiraHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/pipe/test_jira_pipe.py::TestJiraPipe::test_jira_pipe
'''


@pytest.fixture
def pipe_client_init() -> dict:
    # llm_config = {'model': 'gpt-4-turbo-2024-04-09', 'llm_type': 'openai'}
    llm_config = {'model': 'gemini-2.5-flash', 'llm_type': 'gemini'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response


class TestJiraPipe:

    async def test_jira_pipe(self, pipe_client_init: dict):
        llm_client: LLMClient = pipe_client_init.get('llm')
        aws_sg_handler = JiraHandler()
        prompt_template = PromptTemplate(system_message=f"You are an Jira for GRC.")
        engine = Engine(
            llm=llm_client,
            prompt_template=prompt_template,
            handler=aws_sg_handler
        )
        goal = (
            "Generate the response and data based on the user input. Set the result as it is from the Output Context."
            "Output must be in strict valid JSON format. "
            "DO NOT include any explanations, suggestions, markdown formatting, or extra text before or after the JSON. "
            "Only emit clean, parseable JSON with double quotes for all keys and string values. "
            "No trailing commas. No comments. No bullet points. No code blocks."
        )

        role = (
            "You are a GRC Evidence Collection and Reporting Expert. "
            "You specialize in compliance, audit, and security evidence gathering. "
            "You also serve as a strict JSON generator."
            "Always ensure the JSON is syntactically valid, complete, and captures all related associations and context for each resource. "
            "Your output will be parsed by an automated system, so correctness is critical. "
            "Do NOT include any explanation or commentary—just the JSON object."
        )
        aws_sg_agent = Agent(
            name=f"Jira Agent",
            goal=goal,
            role=role,
            llm=llm_client,
            prompt_template=prompt_template,
            max_retry=2,
            engines=[engine],
        )
        pipe = AgentXPipe(
            agents=[aws_sg_agent]
        )
        prompt = f"""
        If the task involves implementing or creating, do NOT attempt to implement or create. 
        Instead, collect evidence that shows what has been implemented or created.

        When retrieving data from any system or API (such as AWS, Azure, GCP, Kubernetes, or on-prem tools), 
        you must also gather and summarize all related association details.

        For example, if collecting evidence about AWS EC2 instances, include:
        - associated security groups and their inbound/outbound rules (including open ports and protocols),
        - IAM roles or instance profiles attached,
        - key pairs used,
        - attached EBS volumes,
        - elastic IPs (if any),
        - tags applied.

        Ensure that your summary captures all relationships and configurations that are relevant for compliance, 
        security, and risk review.

        Be thorough and exhaustive in summarizing this context in your evidence data.
        """
        query_instruct = "Provide all tickets"
        result = await pipe.flow(
            query_instruction=f"{prompt}\n\nTool:Jira\n\nTask:{query_instruct} to collect evidence for GRC"
        )
        logger.info(result)
