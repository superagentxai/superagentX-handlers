import logging
import os

import pytest
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.memory import Memory
from superagentx.prompt import PromptTemplate
from superagentx_handlers.paddle_ocr import PaddleOCRHandler

logger = logging.getLogger(__name__)

'''
Run Pytest:

    pytest --log-cli-level=INFO \
    tests/agent/test_paddle_ocr_agent.py::TestPaddleOCRAgent::test_paddle_ocr_agent

Make sure the required LLM environment/configuration is available.
'''


@pytest.fixture
def agent_client_init() -> dict:
    """
    Initialize the LLM client used by the SuperAgentX agent.
    """

    llm_config = {
        "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "llm_type": "bedrock",
        "async_mode": True,
    }

    llm_client: LLMClient = LLMClient(
        llm_config=llm_config
    )

    return {
        "llm": llm_client
    }


class TestPaddleOCRAgent:

    async def test_paddle_ocr_agent(
            self,
            agent_client_init: dict,
    ):
        """
        Test PaddleOCRHandler through a SuperAgentX Agent.

        Flow:

            User Query
                ↓
            SuperAgentX Agent
                ↓
            Engine
                ↓
            PaddleOCRHandler.extract_pdf()
                ↓
            Structured OCR JSON
        """

        llm_client: LLMClient = agent_client_init.get("llm")

        # ---------------------------------------------------------
        # PDF INPUT
        # ---------------------------------------------------------

        pdf_path = ("YOUR PDF FILE PATH")

        assert os.path.isfile(
            pdf_path
        ), f"PDF file does not exist: {pdf_path}"

        # ---------------------------------------------------------
        # HANDLER
        # ---------------------------------------------------------

        paddle_ocr_handler = PaddleOCRHandler()

        # ---------------------------------------------------------
        # PROMPT
        # ---------------------------------------------------------

        prompt_template = PromptTemplate()

        # ---------------------------------------------------------
        # ENGINE
        # ---------------------------------------------------------

        paddle_ocr_engine = Engine(
            handler=paddle_ocr_handler,
            llm=llm_client,
            prompt_template=prompt_template,
        )

        # ---------------------------------------------------------
        # MEMORY
        # ---------------------------------------------------------

        memory = Memory()

        # ---------------------------------------------------------
        # AGENT
        # ---------------------------------------------------------

        paddle_ocr_agent = Agent(
            goal=(
                "Extract the OCR content from the provided Arabic PDF "
                "document and return the structured OCR result."
            ),
            role=(
                "You are an OCR document ingestion agent. "
                "Use the PaddleOCR handler to extract text and "
                "preserve the document's OCR evidence."
            ),
            llm=llm_client,
            prompt_template=prompt_template,
            engines=[
                paddle_ocr_engine
            ],
        )

        # ---------------------------------------------------------
        # QUERY
        # ---------------------------------------------------------

        query_instruction = f"""
Extract OCR content from this PDF document:

{pdf_path}

Use the PaddleOCR extraction tool.

Return the complete structured OCR result.
Do not translate the Arabic text.
Do not classify the document.
Do not infer business meaning.
Do not summarize the document.
Preserve the OCR evidence and page structure.
"""

        # ---------------------------------------------------------
        # EXECUTE AGENT
        # ---------------------------------------------------------

        result = await paddle_ocr_agent.execute(
            query_instruction=query_instruction
        )

        # ---------------------------------------------------------
        # OUTPUT
        # ---------------------------------------------------------

        logger.info(
            "PaddleOCR Agent Result:\n%s",
            result,
        )

        assert result is not None

        print("\n")
        print("=" * 100)
        print("PADDLE OCR AGENT RESULT")
        print("=" * 100)
        print(result)
        print("=" * 100)

        # ---------------------------------------------------------
        # BASIC ASSERTIONS
        # ---------------------------------------------------------

        assert result