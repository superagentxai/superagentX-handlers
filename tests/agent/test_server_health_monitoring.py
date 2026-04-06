import logging

import pytest
from superagentx.agent import Agent
from superagentx.agentxpipe import AgentXPipe
from superagentx.engine import Engine
from superagentx.task_engine import TaskEngine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate
from superagentx_handlers.aws.cloudwatch import AWSCloudWatchHandler
from superagentx.handler.ai import AIHandler
from superagentx_handlers.slack import SlackHandler

logger = logging.getLogger(__name__)

'''
 Run Pytest:  

   1. pytest --log-cli-level=INFO tests/agent/test_server_health_monitoring.py::TestServerHealthMonitorHandler::test_server_health_monitor
'''

@pytest.fixture
def agent_client_init() -> dict:
    llm_config = {'model': 'gpt-5-mini', 'llm_type': 'azure-openai'}

    llm_client: LLMClient = LLMClient(llm_config=llm_config)
    response = {'llm': llm_client}
    return response

class TestServerHealthMonitorHandler:

    async def test_server_health_monitor(self, agent_client_init: dict):
        llm_client: LLMClient = agent_client_init.get('llm')

        aws_handler = AWSCloudWatchHandler(
            aws_access_key_id="<ACCESS_KEY_ID>",
            aws_secret_access_key="<SECRET_ACCESS_KEY>",
            region_name="<REGION_NAME>"
        )
        ai_handler = AIHandler(
            llm=llm_client
        )
        slack_handler = SlackHandler(
            bot_token= "",
        )

        threshold_prompt = PromptTemplate(
           system_message= """
                You are a system responsible for server health monitoring.

                A threshold is a predefined limit value used to determine whether a system metric
                is in a normal or abnormal state.
                
                Your task is to:
                - Compare incoming server metrics (CPU, memory, disk, network, etc.)
                  against their defined threshold limits.
                - If a metric value exceeds its threshold, mark it as a breach.
                - Classify the result clearly (OK, WARNING, CRITICAL).
                - Pass the threshold evaluation result to the next workflow step
                  for issue detection and alerting.
                
                Definition:
                - Threshold = Safe operating limit for a metric.
                - If metric value > threshold → issue detected.
                
                Example thresholds:
                - CPU usage > 80% → HIGH
                - Memory usage > 75% → HIGH
                - Disk usage > 85% → CRITICAL
                
                Do not trigger alerts or log results directly.
                Only analyze metrics and return a structured threshold evaluation output.

            """
        )

        detect_promt = PromptTemplate(
            system_message="""
            You are an Issue Detection Agent in a server health monitoring workflow.

            Your responsibility is to analyze the output from the Threshold Analyzer
            and determine actual system issues and their severity.
            
            Your tasks are:
            - Read threshold evaluation results for server metrics
              (CPU, memory, disk, network, etc.).
            - Identify which metrics represent real issues.
            - Assign a clear issue type for each detected problem
              (e.g., CPU_OVERLOAD, MEMORY_PRESSURE, DISK_FULL, NETWORK_LATENCY).
            - Determine severity levels such as WARNING, HIGH, or CRITICAL
              based on how severe the threshold breach is.
            - Return a structured list of detected issues.
            
            Rules:
            - Do not collect metrics.
            - Do not analyze thresholds again.
            - Do not trigger alerts or log data.
            - Focus only on issue identification and severity classification.
            
            Example Input:
            {
              "cpu": "HIGH",
              "memory": "OK",
              "disk": "CRITICAL"
            }
            
            Example Output:
            {
              "issues": [
                {
                  "type": "CPU_OVERLOAD",
                  "severity": "HIGH"
                },
                {
                  "type": "DISK_FULL",
                  "severity": "CRITICAL"
                }
              ]
            }

            """
        )

        ai_prompt = PromptTemplate(
            system_message="Deploy application safely using validated inputs."
        )

        notification_prompt = PromptTemplate(
            system_message="Notify deployment result to user."
        )

        aws_engine = TaskEngine(
            handler=aws_handler,
            instructions=[[{
                "get_cloudwatch_data": {}
            }]]
        )

        ai_engine = Engine(
            handler=ai_handler,
            llm=llm_client,
            prompt_template=ai_prompt
        )

        gmail_engine = Engine(
            handler=slack_handler,
            llm=llm_client,
            prompt_template=notification_prompt
        )

        aws_agent = Agent(
            name="AWS CloudWatch Agent",
            engines=[aws_engine]
        )

        analyze_agent = Agent(
            name="Analyze Agent",
            role="You are a Threshold Analysis Agent in a server health monitoring workflow.",
            goal=(
                "Analyze incoming server metrics by comparing them against predefined "
                "threshold limits and classify each metric as OK, WARNING, or CRITICAL. "
                "Return a structured threshold evaluation without detecting issues, "
                "sending notifications, or logging results."
            ),
            llm=llm_client,
            prompt_template=threshold_prompt,
            engines=[ai_engine],
            max_retry=1
        )

        detect_issue_agent = Agent(
            name="Detect Issue Agent",
            role="You are an Issue Detection and Summarization Agent in a server health monitoring workflow.",
            goal=(
                "Analyze threshold analysis results to identify actual server issues and "
                "their severity. Generate a concise, human-readable summary of all detected "
                "issues and return both the structured issue data and the summary for use "
                "by the notification handler. Do not send notifications or perform logging."
            ),
            llm=llm_client,
            prompt_template=detect_promt,
            engines=[ai_engine],
            max_retry=1
        )

        notification_agent = Agent(
            name="Notification Agent",
            role="You are a Server Health Monitoring Notification Agent.",
            goal=(
                "Receive a summarized description of detected server issues and send a "
                "clear, human-readable notification to the configured communication "
                "channel. Ensure the message includes severity, server context, and "
                "timestamp. Do not analyze metrics or detect issues."
            ),
            llm=llm_client,
            prompt_template=notification_prompt,
            engines=[gmail_engine],
            max_retry=1
        )

        pipe = AgentXPipe(
            agents=[
                aws_agent,
                analyze_agent,
                detect_issue_agent,
                notification_agent
            ],
        )
        result = await pipe.flow(
            query_instruction= "Use the detected server issue summary and send it as an email "
                            "notification to vetharupini938@gmail.com."
        )
        logger.info(f"Result=>   {result}")
