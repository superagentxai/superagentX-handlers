from superagentx_handlers.ml.base import BaseRunner
from superagentx.utils.helper import sync_to_async
from transformers import pipeline
import torch

class HuggingFaceRunner(BaseRunner):

    _cache = {}

    def __init__(self):
        self.pipeline = None

    async def load(self, config):
        key = (
            config["task"],
            config["model_name"],
            config.get("device", "cpu"),
            config.get("torch_dtype")
        )

        if key not in self._cache:
            device = 0 if config.get("device") == "gpu" and torch.cuda.is_available() else -1

            dtype = None
            if config.get("torch_dtype") == "fp16":
                dtype = torch.float16

            self._cache[key] = await sync_to_async(pipeline,
                task=config["task"],
                model=config["model_name"],
                device=device,
                torch_dtype=dtype
            )

        # ✅ CRITICAL LINE (THIS WAS MISSING)
        self.pipeline = self._cache[key]

        return self.pipeline

    async def run(self, inputs, params):
        if self.pipeline is None:
            raise RuntimeError(
                "Pipeline not loaded. Call `load(config)` before `run()`."
            )
        return await sync_to_async(self.pipeline,inputs, **params)