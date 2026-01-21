from typing import Dict, Any
from abc import ABC, abstractmethod

class BaseRunner(ABC):

    @abstractmethod
    async def load(self, config: Dict[str, Any]):
        raise NotImplementedError

    @abstractmethod
    async def run(self, inputs: Any, params: Dict[str, Any]):
        raise NotImplementedError