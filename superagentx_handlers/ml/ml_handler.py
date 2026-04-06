from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

from typing import Dict, Any

class FrameworkRouter:

    async def route(self, framework: str):
        if framework == "huggingface":
            from superagentx_handlers.ml.huggingface import HuggingFaceRunner
            return HuggingFaceRunner()
        # if framework == "tensorflow":
        #     return TensorFlowRunner()
        # if framework == "sklearn":
        #     return SklearnRunner()
        # if framework == "spacy":
        #     return SpaCyRunner()
        raise ValueError(f"Unsupported framework: {framework}")

class UniversalMLHandler(BaseHandler):
    """
    Framework-agnostic ML handler for SuperAgentX.
    """

    def __init__(self):
        super().__init__()
        self.router = FrameworkRouter()

    @tool
    async def run(
        self,
        framework: str,
        task: str | None,
        model_name: str | None,
        # model_path: str | None,
        inputs: Any,
        device: str = "cpu",
        parameters: Dict[str, Any] | None = None,
        optimization: Dict[str, Any] | None = None
    ):
        """
        Run inference using any ML framework.

        Args:
            framework: huggingface | tensorflow | sklearn | spacy
            task: task name (HF only)
            model_name: model identifier
            inputs: input data
            device: cpu | gpu
            parameters: inference parameters
            optimization: fp16, quantization, compile, etc.
        """

        runner = await self.router.route(framework)

        config = {
            "task": task,
            "model_name": model_name,
            # "model_path": model_path,
            "device": device,
            **(optimization or {})
        }

        await runner.load(config)
        output = await runner.run(inputs, parameters or {})

        return {
            "framework": framework,
            "output": output
        }