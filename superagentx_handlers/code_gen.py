from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.llm import LLMClient
from superagentx.llm.models import ChatCompletionParams


class CodeHandler(BaseHandler):
    """
        Abstract handler to enable code generation for various purposes.
        This class extends BaseHandler and defines the interface for code generation.
    """

    def __init__(
            self,
            llm: LLMClient,
            role: str | None = None,
            code_basics: str | None = None
    ):
        super().__init__()
        self.llm=llm
        self.role=role
        self.code_basics = code_basics

        if not self.role:
            self.role = "You are a coding prodigy."


    @tool
    async def code_generation(
            self,
            *,
            instruction: str
    ):
        """
        Generates programming code for the given use case with the suitable language useful for function or application
        development. Generates full code without any unwanted markdown or unnecessary information apart from comments. Use the language mentioned
        by the user. If no language mentioned, use language which will be most suited for the given use case. Be ready to use multiple languages also.

        Args:
            @param instruction: String containing the use case or the problem statement. Language can either be specified by the user or you can use required languages
            suitable for the given use case.
        """
        content = instruction
        if self.code_basics:
            content = f"\n Base of the coding : {self.code_basics} Instruction: {instruction}"
        messages = [
            {
                "role":"system",
                "content":self.role
            },
            {
                "role":"user",
                "content":content
            }
        ]
        chat_completion = ChatCompletionParams(
            messages=messages
        )

        return await self.llm.achat_completion(
            chat_completion_params=chat_completion
        )