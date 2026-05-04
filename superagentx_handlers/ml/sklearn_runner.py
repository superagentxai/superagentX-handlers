import joblib, pickle, logging, warnings
from aiopath import AsyncPath
from typing import Any
import numpy as np
import pandas as pd
from superagentx_handlers.ml.base import BaseRunner
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)

def _load_model_from_disk(model_path: str):
    """Load a sklearn model from .joblib or .pkl file."""
    if model_path.endswith(".joblib"):
        return joblib.load(model_path)
    elif model_path.endswith(".pkl"):
        warnings.warn(f"Loading '{model_path}' via pickle. Pickle files can execute "
                      "arbitrary code — only load files you trust. Prefer .joblib for safety.",
                      UserWarning, stacklevel=2)
        with open(model_path, "rb") as f:
            return pickle.load(f)
    else:
        raise ValueError("Unsupported model format. Use .joblib or .pkl")

class SklearnRunner(BaseRunner):

    _cache: dict = {}

    def __init__(self):
        self.model = None

    async def load(self, config: dict):
        model_path = config.get("model_path")
        if not model_path:
            raise ValueError("`model_path` is required for sklearn models.")

        path = AsyncPath(model_path)

        if not await path.exists():
            raise FileNotFoundError(f"Model file not found: '{model_path}'")

        stat = await path.stat()
        mtime = stat.st_mtime
        key = (model_path, mtime)

        if key not in self._cache:
            logger.info(f"Loading model from '{model_path}' (mtime={mtime})")
            self._cache[key] = await sync_to_async(_load_model_from_disk, model_path)
        else:
            logger.debug(f"Using cached model for '{model_path}'")

        self.model = self._cache[key]
        return self.model

    async def run(self, inputs: Any, params: dict):
        if self.model is None:
            raise RuntimeError("Model not loaded. Call `load(config)` before `run()`.")

        if not isinstance(inputs, (list, np.ndarray, pd.DataFrame)):
            raise TypeError(f"`inputs` must be array-like (list, np.ndarray, or pd.DataFrame), "
                            f"got {type(inputs).__name__}.")

        method = params.get("method", "predict")

        if not hasattr(self.model, method):
            raise ValueError(f"Model does not support method `{method}`. "
                             f"Available methods: {[m for m in dir(self.model) if not m.startswith('_')]}")

        def infer():
            func = getattr(self.model, method)
            result = func(inputs)

            try:
                return result.tolist()
            except AttributeError:
                return result

        logger.info(f"Running sklearn inference with method='{method}'")
        return await sync_to_async(infer)