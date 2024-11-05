import pytest

from superagentx.llm import LLMClient
from superagentx_handlers.csv_data import CsvHandler

'''
Run Pytest:

    1.pytest --log-cli-level=INFO tests/handlers/test_csv_handler.py::TestCSV::test_csv_handler

'''


@pytest.fixture
def csv_client_init() -> CsvHandler:
    input_path = "/home/vijay/Documents/POC/people.csv"
    llm_config = {'llm_type': 'openai'}
    llm_client = LLMClient(llm_config=llm_config)
    csv_handler = CsvHandler(
        csv_path=input_path,
        llm_client=llm_client
    )
    return csv_handler


class TestCSV:
    async def test_csv_handler(self, csv_client_init: CsvHandler):
        query = "who are all Petroleum engineer?"
        res = await csv_client_init.search(query)
        assert isinstance(res, object)
