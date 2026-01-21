import logging
import os
from typing import List, Tuple

import snowflake.connector
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class SnowflakeHandler(BaseHandler):
    """
        A Snowflake handler that uses user-provided configuration
        to fetch, create, update, and delete Snowflake resources
        based on triggered actions or events.

    """

    def __init__(
        self,
        *,
        user: str | None = None,
        password: str | None = None,
        account: str | None = None,
        warehouse: str | None = None,
        database: str | None = None,
        schema: str | None = None,
        role: str | None = None,
    ):
        super().__init__()
        self.config = {
            "user": user or os.getenv("SNOWFLAKE_USER"),
            "password": password or os.getenv("SNOWFLAKE_PASSWORD"),
            "account": account or os.getenv("SNOWFLAKE_ACCOUNT"),
            "warehouse": warehouse or os.getenv("SNOWFLAKE_WAREHOUSE"),
            "database": database or os.getenv("SNOWFLAKE_DATABASE"),
            "schema": schema or os.getenv("SNOWFLAKE_SCHEMA"),
            "role": role or os.getenv("SNOWFLAKE_ROLE", "SYSADMIN"),
        }

        missing = [k for k, v in self.config.items() if not v]
        if missing:
            raise RuntimeError(f"Missing Snowflake config values: {missing}")

    # ------------------------------------------------------------------

    def _connect(self):
        conn = snowflake.connector.connect(
            account=self.config["account"],
            user=self.config["user"],
            password=self.config["password"],
            role=self.config["role"],
            warehouse=self.config["warehouse"],
            database=self.config["database"],
            schema=self.config["schema"],
        )

        self._set_session_context(conn)
        self._validate_session_context(conn)

        return conn

    # ------------------------------------------------------------------

    def _set_session_context(self, conn):
        cursor = conn.cursor()
        try:
            cursor.execute(f"USE ROLE {self.config['role']}")
            cursor.execute(f"USE WAREHOUSE {self.config['warehouse']}")
            cursor.execute(f"USE DATABASE {self.config['database']}")
            cursor.execute(
                f"USE SCHEMA {self.config['database']}.{self.config['schema']}"
            )
        finally:
            cursor.close()

    # ------------------------------------------------------------------

    def _validate_session_context(self, conn):
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                SELECT
                    CURRENT_WAREHOUSE(),
                    CURRENT_DATABASE(),
                    CURRENT_SCHEMA(),
                    CURRENT_ROLE()
                """
            )
            warehouse, database, schema, role = cursor.fetchone()

            if not warehouse:
                raise RuntimeError("No warehouse selected")
            if not database or not schema:
                raise RuntimeError("Database or schema not selected")

        finally:
            cursor.close()

    # ------------------------------------------------------------------

    def _ensure_table_exists(self, conn, fq_table: str, columns: List[str]):
        cursor = conn.cursor()
        try:
            cols_def = ", ".join([f'"{col}" VARCHAR' for col in columns])

            query = f"""
                CREATE TABLE IF NOT EXISTS {fq_table} (
                    {cols_def}
                )
            """
            cursor.execute(query)
        finally:
            cursor.close()

    # ------------------------------------------------------------------
    @tool
    async def fetch_query_history(self, limit: int):
        """
           Action: Fetch query execution history from Snowflake.

           Args:
               limit (int): Number of recent queries to fetch.

           Returns:
               list[dict]: List of query history records.
           """

        def _run():
            conn = self._connect()
            cursor = conn.cursor(snowflake.connector.DictCursor)
            try:
                cursor.execute(
                    f"""
                    SELECT
                        QUERY_ID,
                        USER_NAME,
                        QUERY_TEXT,
                        EXECUTION_STATUS,
                        START_TIME
                    FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                    ORDER BY START_TIME DESC
                    LIMIT {limit}
                    """
                )
                return cursor.fetchall()
            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)

    # ------------------------------------------------------------------

    @tool
    async def get_query_events(self, limit: int = 10):
        """
           Action: Fetch recent Snowflake query events.

           Args:
               limit (int): Number of query events to fetch (default 10).

           Returns:
               list[dict]: List of query event details.

           """

        if limit <= 0:
            raise ValueError("Limit must be greater than 0")

        logger.debug(f"Fetching last {limit} Snowflake query events")
        return await self.fetch_query_history(limit)

    # ------------------------------------------------------------------
    async def create_table(self, table_name: str):
        """
           Action: Create a table in the configured database and schema.

           Args:
               table_name (str): Name of the table to create.

           Returns:
               None

           """

        def _run():
            conn = self._connect()
            fq_table = f'{self.config["database"]}.{self.config["schema"]}.{table_name}'

            cursor = conn.cursor()
            try:
                # Create table with a default 'id' column
                query = f"CREATE TABLE IF NOT EXISTS {fq_table} (id STRING)"
                cursor.execute(query)
            finally:
                cursor.close()
                conn.close()

        await sync_to_async(_run)

    @tool
    async def create_table_with_values(
            self,
            table_name: str,
            columns: List[str],
            values: List[Tuple],
    ):

        """
            Action: Create a table (if not exists) and insert rows into it.

            Args:
                table_name (str): Name of the table.
                columns (List[str]): List of column names.
                values (List[Tuple]): Rows to insert.

            Returns:
                dict: Status, table name, and number of rows inserted.

            """
        def _run():
            conn = self._connect()

            # Fully qualified table name
            fq_table = (
                f'{self.config["database"]}.'
                f'{self.config["schema"]}.'
                f'{table_name}'
            )

            self._ensure_table_exists(conn, fq_table, columns)

            cursor = conn.cursor()
            try:
                cols = ", ".join([f'"{c}"' for c in columns])
                placeholders = ", ".join(["%s"] * len(columns))

                query = f"""
                    INSERT INTO {fq_table} ({cols})
                    VALUES ({placeholders})
                """

                cursor.executemany(query, values)

                return {
                    "status": "success",
                    "table": table_name,
                    "rows_inserted": cursor.rowcount,
                }
            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)

    @tool
    async def delete_rows(
            self,
            table_name: str,
            primary_key_column: str,
            primary_key_values: List[int]
    ):
        """
        Deletes rows from a Snowflake table based on primary key values.

        Args:
            table_name (str): Name of the table.
            primary_key_column (str): Column name to filter by (primary key).
            primary_key_values (str[Any]): List of primary key values to delete.

        Returns:
            dict: Status and number of rows deleted.
        """

        def _run():
            if not primary_key_values:
                return {"status": "failed", "message": "No primary key values provided", "rows_deleted": 0}

            conn = self._connect()
            fq_table = f'{self.config["database"]}.{self.config["schema"]}.{table_name}'

            cursor = conn.cursor()
            try:
                # Build placeholders for SQL query
                placeholders = ", ".join(["%s"] * len(primary_key_values))
                query = f"""
                    DELETE FROM {fq_table}
                    WHERE "{primary_key_column}" IN ({placeholders})
                """
                cursor.execute(query, primary_key_values)

                return {
                    "status": "success",
                    "table": table_name,
                    "primary_key_column": primary_key_column,
                    "rows_deleted": cursor.rowcount
                }
            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)

    @tool
    async def update_rows(
            self,
            table_name: str,
            primary_key_column: str,
            primary_key_values: list,
            update_column: str,
            update_values: list,
    ):
        """
           Action: Update rows in a Snowflake table.

           Args:
               table_name (str): Name of the table.
               primary_key_column (str): Primary key column name.
               primary_key_values (list): Primary key values to match.
               update_column (str): Column to update.
               update_values (list): New values for the update column.

           Returns:
               dict: Status and number of rows updated.
           """


        def _run():
            conn = self._connect()
            cursor = conn.cursor()

            fq_table = f'{self.config["database"]}.{self.config["schema"]}.{table_name}'.upper()

            try:
                if len(primary_key_values) != len(update_values):
                    raise ValueError("primary_key_values and update_values must have same length")

                query = f"""
                    UPDATE {fq_table}
                    SET {update_column.upper()} = %s
                    WHERE {primary_key_column.upper()} = %s
                """

                data = list(zip(update_values, primary_key_values))
                cursor.executemany(query, data)

                return {
                    "status": "success",
                    "rows_updated": cursor.rowcount,
                }
            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)

    @tool
    async def add_column(
            self,
            table_name: str,
            column_name: str,
            column_type: str = "VARCHAR",
    ):
        """
        Action: Adds a new column to an existing Snowflake table.

        Args:
            table_name (str): Existing table name
            column_name (str): New column name to add
            column_type (str): Snowflake column type (default VARCHAR)

        Returns:
            dict: Status and column details
        """

        def _run():
            conn = self._connect()
            cursor = conn.cursor()
            try:
                fq_table = (
                    f'{self.config["database"]}.'
                    f'{self.config["schema"]}.'
                    f'{table_name.upper()}'
                )

                query = f'''
                    ALTER TABLE {fq_table}
                    ADD COLUMN IF NOT EXISTS "{column_name.upper()}" {column_type}
                '''
                cursor.execute(query)

                return {
                    "status": "success",
                    "table": table_name,
                    "column_added": column_name,
                    "column_type": column_type,
                }

            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)

    @tool
    async def get_databases(self):
        """
        Action: Fetch all databases in the Snowflake account.

        Returns:
            dict: List of databases
        """

        def _run():
            conn = self._connect()
            cursor = conn.cursor()
            try:
                cursor.execute("SHOW DATABASES")
                rows = cursor.fetchall()

                return {
                    "status": "success",
                    "databases": rows,
                }
            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)

    @tool
    async def get_schemas(self):
        """
        Action: Fetch all schemas in the configured database.

        Returns:
            dict: List of schemas
        """

        def _run():
            conn = self._connect()
            cursor = conn.cursor()
            try:
                cursor.execute(f'SHOW SCHEMAS IN DATABASE {self.config["database"]}')
                rows = cursor.fetchall()

                return {
                    "status": "success",
                    "schemas": rows,
                }
            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)

    @tool
    async def get_tables(self):
        """
        Action: Fetch all tables in the configured schema.

        Returns:
            dict: List of tables
        """

        def _run():
            conn = self._connect()
            cursor = conn.cursor()
            try:
                fq_schema = (
                    f'{self.config["database"]}.'
                    f'{self.config["schema"]}'
                )

                cursor.execute(f"SHOW TABLES IN SCHEMA {fq_schema}")
                rows = cursor.fetchall()

                return {
                    "status": "success",
                    "tables": rows,
                }
            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)

    @tool
    async def get_table_columns(self, table_name: str):
        """
        Action: Fetch columns of a specific table.

        Args:
            table_name (str): Table name

        Returns:
            dict: Column metadata
        """

        def _run():
            conn = self._connect()
            cursor = conn.cursor()
            try:
                fq_table = (
                    f'{self.config["database"]}.'
                    f'{self.config["schema"]}.'
                    f'{table_name.upper()}'
                )

                cursor.execute(f"DESCRIBE TABLE {fq_table}")
                rows = cursor.fetchall()

                return {
                    "status": "success",
                    "table": table_name,
                    "columns": rows,
                }
            finally:
                cursor.close()
                conn.close()

        return await sync_to_async(_run)







