from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class FrameworkRouter:

    async def route(self, framework: str):
        if framework == "huggingface":
            from superagentx_handlers.ml.huggingface import HuggingFaceRunner
            return HuggingFaceRunner()
        if framework == "sklearn":
            from superagentx_handlers.ml.sklearn_runner import SklearnRunner
            return SklearnRunner()
        # if framework == "tensorflow":
        #     return TensorFlowRunner()
        # if framework == "spacy":
        #     return SpaCyRunner()
        raise ValueError(f"Unsupported framework: '{framework}'. "
            f"Supported options: huggingface, sklearn")

class UniversalMLHandler(BaseHandler):
    """
    Framework-agnostic ML handler for SuperAgentX.
    """

    def __init__(self):
        super().__init__()
        self.router = FrameworkRouter()
        self._runner_cache: Dict[tuple, Any] = {}

    async def _get_runner(self, framework: str, model_path: Optional[str]):
        key = (framework, model_path)
        if key not in self._runner_cache:
            logger.info(f"Creating new runner for framework='{framework}', model_path='{model_path}'")
            self._runner_cache[key] = await self.router.route(framework)
        return self._runner_cache[key]

    @tool
    async def run(
        self,
        framework: str,
        task: Optional[str] = None,
        model_name: Optional[str] = None,
        model_path: Optional[str] = None,
        inputs: Any = None,
        device: str = "cpu",
        parameters: Optional[Dict[str, Any]] = None,
        optimization: Optional[Dict[str, Any]] = None
    ):
        """
        Run inference using any ML framework.

        Args:
            framework:    huggingface | sklearn
            task:         task name (HuggingFace only)
            model_name:   model identifier (HuggingFace only)
            model_path:   path to model file (sklearn only)
            inputs:       input data (array-like for sklearn, text/dict for HF)
            device:       cpu | gpu
            parameters:   inference parameters (e.g. {"method": "predict"})
            optimization: fp16, quantization, compile, etc. (HuggingFace only)
        """

        logger.info(f"UniversalMLHandler.run called: framework={framework}, method={parameters}")

        runner = await self._get_runner(framework, model_path)

        config = {
            "device": device,
            **(optimization or {})
        }

        if framework == "huggingface":
            config.update({
                "task": task,
                "model_name": model_name,
            })

        elif framework == "sklearn":
            config.update({
                "model_path": model_path,
            })

        await runner.load(config)
        output = await runner.run(inputs, parameters or {})

        logger.info(f"Inference complete for framework='{framework}'")

        return {
            "framework": framework,
            "output": output
        }