import logging

import pytest

from superagentx_handlers.snowflake import SnowflakeHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:

    1.pytest --log-cli-level=INFO tests/handlers/test_snowflake.py::TestSnowflakeHandler::test_fetch_query_history
    2.pytest --log-cli-level=INFO tests/handlers/test_snowflake.py::TestSnowflakeHandler::test_get_query_events
    3.pytest --log-cli-level=INFO tests/handlers/test_snowflake.py::TestSnowflakeHandler::test_create_table_with_values
    4.pytest --log-cli-level=INFO tests/handlers/test_snowflake.py::TestSnowflakeHandler::test_create_table
    5.pytest --log-cli-level=INFO tests/handlers/test_snowflake.py::TestSnowflakeHandler::test_delete_rows
    6.pytest --log-cli-level=INFO tests/handlers/test_snowflake.py::TestSnowflakeHandler::test_update_rows
    7.pytest --log-cli-level=INFO tests/handlers/test_snowflake.py::TestSnowflakeHandler::test_new_column
    8.pytest --log-cli-level=INFO tests/handlers/test_snowflake.py::TestSnowflakeHandler::test_get_databases

'''


@pytest.fixture
def snow_handler_init() -> SnowflakeHandler:
    snowflake_handler = SnowflakeHandler(
    )
    return snowflake_handler


class TestSnowflakeHandler:

    async def test_fetch_query_history(self, snow_handler_init: SnowflakeHandler):
        res = await snow_handler_init.fetch_query_history(
            limit=5
        )
        logger.info(f"Result: {res}")

    async def test_get_query_events(self, snow_handler_init: SnowflakeHandler):
        res = await snow_handler_init.get_query_events()
        logger.info(f"Result: {res}")

    async def test_create_table(self,snow_handler_init: SnowflakeHandler):
        res = await snow_handler_init.create_table(
            table_name="Testing10"
        )
        logger.info(f"Result: {res}")

    async def test_create_table_with_values(self, snow_handler_init: SnowflakeHandler):
        res = await snow_handler_init.create_table_with_values(
            table_name="Testing_users_1",
            columns=["ID", "NAME", "AGE", "EMAIL", "NUMBER"],
            values=[
                (1, "Sridhar",23, "sridhar@gmail.com", 23456789),
                (2, "Ravi",24, "sridhar@gmail.com", 23456789),
                (3, "Sri",28, "sridhar@gmail.com", 98765432),
                (4, "Ram",30, "sridhar@gmail.com", 8765432),
                (5, "Kumar",50, "sridhar@gmail.com",3456789)
            ]
        )
        logger.info(f"Result: {res}")

    async def test_delete_rows(self,snow_handler_init: SnowflakeHandler):
        res = await snow_handler_init.delete_rows(
            table_name="User_Details_Table",
            primary_key_column="ID",
            primary_key_values=[3]
        )
        logger.info(f"Delete Result: {res}")

    async def test_update_rows(self,snow_handler_init: SnowflakeHandler):
        res = await snow_handler_init.update_rows(
            table_name="Testing",
            primary_key_column="ID",
            primary_key_values=[1,2,3,4,5],
            update_column="DOB",
            update_values=["01-jan-2004","01-feb-2005","01-jan-2004","01-jan-2004","01-jan-2004"]
        )

        logger.info(f"Result: {res}")

    async def test_new_column(self, snow_handler_init: SnowflakeHandler):
        """
        Test trigger for detecting columns in an existing table.
        """

        res = await snow_handler_init.add_column(
            table_name="Testing",
            column_name="DOB",
            column_type="VARCHAR"
        )

        logger.info(f"Trigger Result: {res}")

    async def test_get_databases(self, snow_handler_init: SnowflakeHandler):
        """
        Test action for fetching all databases in Snowflake.
        """

        res = await snow_handler_init.get_databases()

        logger.info(f"Action Result: {res}")

    async def test_get_schemas(self, snow_handler_init: SnowflakeHandler):
        """
        Test action for fetching all schemas in a database.
        """

        res = await snow_handler_init.get_schemas()

        logger.info(f"Action Result: {res}")

    async def test_get_tables(self, snow_handler_init: SnowflakeHandler):
        """
        Test action for fetching all tables in a schema.
        """

        res = await snow_handler_init.get_tables()

        logger.info(f"Action Result: {res}")

    async def test_get_table_columns(self, snow_handler_init: SnowflakeHandler):
        """
        Test action for fetching columns of a specific table.
        """

        res = await snow_handler_init.get_table_columns(
            table_name="USER_DETAILS_TABLE"
        )

        logger.info(f"Action Result: {res}")











