import numpy as np
import os, pytest, tempfile, logging, joblib
from sklearn.datasets import load_iris
from sklearn.linear_model import LogisticRegression

from superagentx_handlers.ml.ml_handler import UniversalMLHandler

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.asyncio

"""
Run Pytest:

pytest --log-cli-level=INFO tests/handlers/ml/test_sklearn_handler.py::TestSklearnUniversalHandler::test_predict
pytest --log-cli-level=INFO tests/handlers/ml/test_sklearn_handler.py::TestSklearnUniversalHandler::test_predict_proba

"""

@pytest.fixture(scope="module")
def sklearn_model_path():
    """
    Create and save a dummy sklearn model once per module
    """
    x, y = load_iris(return_X_y=True)

    model = LogisticRegression(max_iter=200)
    model.fit(x, y)

    tmp_dir = tempfile.gettempdir()
    model_path = os.path.join(tmp_dir, "test_sklearn_model.joblib")

    joblib.dump(model, model_path)

    return model_path

@pytest.fixture(scope="module")
def sklearn_handler_init() -> UniversalMLHandler:
    """
    Initialize Universal Handler once per module
    """
    return UniversalMLHandler()

class TestSklearnUniversalHandler:

    # -----------------------------
    # Predict Test
    # -----------------------------
    async def test_predict(self, sklearn_handler_init, sklearn_model_path):
        sample_input = [[5.1, 3.5, 1.4, 0.2]]

        result = await sklearn_handler_init.run(
            framework="sklearn",
            task=None,
            model_name=None,
            model_path=sklearn_model_path,
            inputs=sample_input,
            parameters={"method": "predict"}
        )

        logger.info(f"Sklearn Predict Result: {result}")

        assert "output" in result
        assert isinstance(result["output"], (list, np.ndarray))

    # -----------------------------
    # Predict Proba Test
    # -----------------------------
    async def test_predict_proba(self, sklearn_handler_init, sklearn_model_path):
        sample_input = [[5.1, 3.5, 1.4, 0.2]]

        result = await sklearn_handler_init.run(
            framework="sklearn",
            task=None,
            model_name=None,
            model_path=sklearn_model_path,
            inputs=sample_input,
            parameters={"method": "predict_proba"}
        )

        logger.info(f"Sklearn Predict Proba Result: {result}")

        assert "output" in result
        assert isinstance(result["output"], (list, np.ndarray))
        assert len(result["output"]) == 1