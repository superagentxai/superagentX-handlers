import logging
import pytest

from superagentx_handlers.ml.ml_handler import UniversalMLHandler

logger = logging.getLogger(__name__)

"""
Run Pytest:

pytest --log-cli-level=INFO tests/handlers/ml/test_huggingface.py::TestHuggingFaceUniversalHandler::test_text_classification
pytest --log-cli-level=INFO tests/handlers/ml/test_huggingface.py::TestHuggingFaceUniversalHandler::test_ner

"""


@pytest.fixture(scope="module")
def hf_handler_init() -> UniversalMLHandler:
    """
    Initialize HuggingFace Universal Handler once per module
    """
    return UniversalMLHandler()


class TestHuggingFaceUniversalHandler:

    # -----------------------------
    # Text Classification
    # -----------------------------
    async def test_text_classification(self, hf_handler_init):
        result = await hf_handler_init.run(
            task="text-classification",
            model_name="distilbert-base-uncased-finetuned-sst-2-english",
            inputs="This product is amazing!",
            device="cpu",
            framework="huggingface"
        )
        logger.info(f"Text Classification Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], list)

    # -----------------------------
    # Named Entity Recognition
    # -----------------------------
    async def test_ner(self, hf_handler_init):
        result = await hf_handler_init.run(
            framework="huggingface",
            task="token-classification",
            model_name="dslim/bert-base-NER",
            inputs="Sundar Pichai is CEO of Google",
            parameters={"aggregation_strategy": "simple"}
        )
        logger.info(f"NER Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], list)

    # -----------------------------
    # Text Generation
    # -----------------------------
    async def test_text_generation(self, hf_handler_init):
        result = await hf_handler_init.run(
            task="text-generation",
            model_name="gpt2",
            inputs="Explain ISO 27001:",
            parameters={
                "max_new_tokens": 50,
                "temperature": 0.7
            },
            framework="huggingface"
        )
        logger.info(f"Text Generation Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], list)

    # -----------------------------
    # Summarization
    # -----------------------------
    async def test_summarization(self, hf_handler_init):
        result = await hf_handler_init.run(
            framework="huggingface",
            task="summarization",
            model_name="facebook/bart-large-cnn",
            inputs=(
                "ISO 27001 is an international standard that provides "
                "requirements for an information security management system."
            ),
            parameters={
                "max_length": 40,
                "min_length": 20
            }
        )
        logger.info(f"Summarization Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], list)

    # -----------------------------
    # Question Answering
    # -----------------------------
    async def test_question_answering(self, hf_handler_init):
        result = await hf_handler_init.run(
            framework="huggingface",
            task="question-answering",
            model_name="deepset/roberta-base-squad2",
            inputs={
                "question": "What does ISO 27001 provide?",
                "context": "ISO 27001 provides requirements for an ISMS."
            }
        )
        logger.info(f"QA Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], dict)
        assert "answer" in result["output"]

    # -----------------------------
    # Embeddings / Feature Extraction
    # -----------------------------
    async def test_feature_extraction(self, hf_handler_init):
        result = await hf_handler_init.run(
            framework="huggingface",
            task="feature-extraction",
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            inputs="Compliance risk assessment"
        )
        logger.info(f"Embedding Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], list)

    # -----------------------------
    # Zero-Shot Classification
    # -----------------------------
    async def test_zero_shot_classification(self, hf_handler_init):
        result = await hf_handler_init.run(
            framework="huggingface",
            task="zero-shot-classification",
            model_name="facebook/bart-large-mnli",
            inputs="This contract violates privacy regulations",
            parameters={
                "candidate_labels": ["legal", "finance", "compliance"]
            }
        )
        logger.info(f"Zero-Shot Result: {result}")
        assert "output" in result
        assert "labels" in result["output"]

    # -----------------------------
    # Translation
    # -----------------------------
    async def test_translation(self, hf_handler_init):
        result = await hf_handler_init.run(
            framework="huggingface",
            task="translation",
            model_name="Helsinki-NLP/opus-mt-en-fr",
            inputs="Data privacy is important."
        )
        logger.info(f"Translation Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], list)

    # -----------------------------
    # Fill Mask
    # -----------------------------
    async def test_fill_mask(self, hf_handler_init):
        result = await hf_handler_init.run(
            framework="huggingface",
            task="fill-mask",
            model_name="bert-base-uncased",
            inputs="ISO 27001 is a [MASK] standard."
        )
        logger.info(f"Fill Mask Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], list)

    # -----------------------------
    # Batch Inference
    # -----------------------------
    async def test_batch_inference(self, hf_handler_init):
        result = await hf_handler_init.run(
            framework="huggingface",
            task="text-classification",
            model_name="distilbert-base-uncased-finetuned-sst-2-english",
            inputs=[
                "I love this product",
                "This is terrible",
                "It is okay"
            ]
        )
        logger.info(f"Batch Result: {result}")
        assert "output" in result
        assert isinstance(result["output"], list)
        assert len(result["output"]) == 3
