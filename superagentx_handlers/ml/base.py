from typing import Dict, Any

class BaseRunner:
    async def load(self, config: Dict[str, Any]):
        raise NotImplementedError

    async def run(self, inputs: Any, params: Dict[str, Any]):
        raise NotImplementedError