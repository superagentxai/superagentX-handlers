import logging
import re

import pandas as pd
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.llm import LLMClient, ChatCompletionParams
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class CsvHandler(BaseHandler):

    def __init__(
            self,
            *,
            file_path: str,
            llm_client: LLMClient,
    ):
        super().__init__()
        self.file_path = file_path
        self.llm_client = llm_client

    @tool
    async def search(self, query: str):
        """
        A search operation using the provided query string. This method initiates an asynchronous search based on
        the input `query` and returns the search results. The actual behavior and data source of the search
        (e.g., a database, an API, or a local cache) depend on the underlying implementation.

        Args:
            query (str):
                The search term or query string used to retrieve relevant results. This can be a keyword, a phrase,
                or any other string that specifies what to search for.
        """

        try:
            df = await sync_to_async(pd.read_csv, self.file_path)
            prompt = (f"Given the following CSV data columns: {list(df.columns)},"
                      f"generate a filter condition based on the query: '{query}'."
                      f"Example:\n df[(df['Index'] >= 10) & (df['Index'] <= 15)]")
            messages = [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
            chat_completion_params = ChatCompletionParams(
                messages=messages,
                temperature=0
            )
            response = await self.llm_client.achat_completion(
                chat_completion_params=chat_completion_params
            )
            if response and response.choices:
                result = response.choices[0].message.content.strip()
                start = '```python\n'
                end = '```'
                trim_res = await sync_to_async(
                    re.findall,
                    re.escape(start) + "(.+?)" + re.escape(end),
                    result,
                    re.DOTALL
                )
                if trim_res:
                    result = eval(trim_res[0])
                    return result.to_json()
        except Exception as ex:
            logger.error(f"Error while searching result! {ex}")
            raise
