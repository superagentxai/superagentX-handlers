from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class InvalidDatabase(Exception):
    pass


class InvalidSQLAction(Exception):
    pass


class SQLHandler(BaseHandler):
    """
    SQLHandler — Async SQL operations handler

    This handler centralizes asynchronous SQL database interactions across multiple
    dialects (PostgreSQL, MySQL/MariaDB, SQLite, Oracle, MSSQL). It creates an
    async SQLAlchemy engine (connection pool) from the provided connection parameters
    and exposes a set of decorated async methods (tools) to perform common SQL tasks:

        - select:     execute read-only SELECT queries
        - insert:     execute parameterized INSERT(s)
        - update:     execute parameterized UPDATE(s)
        - delete:     execute parameterized DELETE(s)
        - create_table/drop_table/alter_table: DDL operations
        - get_schema_metadata: introspect database schema, columns and DDL
    """

    def __init__(
            self,
            *,
            database_type: str,
            database: str,
            host: str | None = None,
            port: int | None = None,
            username: str | None = None,
            password: str | None = None
    ):
        """
        Initialize SQLHandler.

        Args:
            database_type: one of "postgres", "mysql", "mariadb", "sqlite", "oracle", "mssql"
            database: database name, or for sqlite the file path
            host: hostname or IP (sqlite ignores)
            port: TCP port (defaults provided per dialect)
            username: DB user (sqlite typically doesn't use this)
            password: DB password
        """
        super().__init__()
        self.database_type = database_type.lower()
        self.host = host or "localhost"
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        match self.database_type:
            case "postgres":
                self._conn_str = self._postgres_conn_str()
            case "mysql" | "mariadb":
                self._conn_str = self._mysql_or_mariadb_conn_str()
            case "sqlite":
                self._conn_str = self._sqlite_conn_str()
            case "oracle":
                self._conn_str = self._oracle_conn_str()
            case "mssql":
                self._conn_str = self._mssql_conn_str()
            case _:
                raise InvalidDatabase(f"Invalid database type `{self.database_type}`")


        self._engine = create_async_engine(url=self._conn_str)

    def _postgres_conn_str(self):
        if not self.port:
            self.port = 5432
        return f"postgresql+asyncpg://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


    def _mysql_or_mariadb_conn_str(self):
        if not self.port:
            self.port = 3306
        return (f"mysql+aiomysql://{self.username}:{self.password}@"
                f"{self.host}:{self.port}/{self.database}?charset=utf8mb4")

    def _sqlite_conn_str(self):
        return f"sqlite+aiosqlite:///{self.database}"

    def _oracle_conn_str(self):
        return self._oracle_conn_str()

    def _mssql_conn_str(self):
        if not self.port:
            self.port = 1433
        return f"mssql+aioodbc://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}?charset=utf8"

    @tool
    async def select(
            self,
            *,
            query: str
    ):
        """
            Asynchronously retrieves data based on the specified query string.
            This method executes a selection operation, returning relevant information according to the query criteria.

            parameters:
                 query (str):The main search query used to retrieve content. This is a required field and should be a
                descriptive string that accurately represents what content is being searched for.
                **kwargs: Additional keyword arguments that may be passed to customize the behavior of the handler.

            Returns:
                Any: The result of handling the action. The return type may vary depending on the specific action handled.

        """
        async with self._engine.connect() as conn:
            res = await conn.execute(text(query))
            return res.all()

    @tool
    async def insert(
            self,
            *,
            stmt: str,
            values: list[dict]
    ):

        """
            Asynchronously inserts data into a database using the specified SQL statement and a list of value dictionaries.
            This method handles the execution of the insertion operation based on the provided parameters.

            parameters:
                 stmt (str): The SQL statement to be executed for the insertion, which should include placeholders
                 for values.
                 values (list[dict]): A list of dictionaries containing the values to be inserted, where each dictionary
                 represents a set of values corresponding to the placeholders in the SQL statement.

            Returns:
                Any: The result of handling the action. The return type may vary depending on the specific action handled.

        """

        return await self._stat_begin(
            stmt=stmt,
            values=values
        )

    @tool
    async def update(
            self,
            *,
            stmt: str,
            values: list[dict]
    ):

        """
        Asynchronously updates records in a database based on the provided SQL statement and a list of value
        dictionaries.This method manages the execution of the update operation to modify existing entries as specified.

        parameters:
                 stmt (str): The SQL statement to be executed for the insertion, which should include placeholders
                 for values.
                 values (list[dict]): A list of dictionaries containing the values to be inserted, where each dictionary
                 represents a set of values corresponding to the placeholders in the SQL statement.

            Returns:
                Any: The result of handling the action. The return type may vary depending on the specific action handled.
        """
        return await self._stat_begin(
            stmt=stmt,
            values=values
        )

    @tool
    async def delete(
            self,
            *,
            stmt: str,
            values: list[dict]
    ):
        """

         Asynchronously deletes records from a database using the specified SQL statement and a list of value dictionaries.
         This method executes the deletion operation based on the provided parameters to remove specified entries.

         parameters:
                 stmt (str): The SQL statement to be executed for the insertion, which should include placeholders
                 for values.
                 values (list[dict]): A list of dictionaries containing the values to be inserted, where each dictionary
                 represents a set of values corresponding to the placeholders in the SQL statement.

            Returns:
                Any: The result of handling the action. The return type may vary depending on the specific action handled.

        """


        return await self._stat_begin(
            stmt=stmt,
            values=values
        )

    @tool
    async def create_table(
            self,
            *,
            stmt: str
    ):

        """
        Asynchronously creates a new database table using the specified SQL statement.
        This method executes the table creation operation based on the provided SQL command.

         parameters:
            stmt (str): The SQL statement to be executed for the insertion, which should include placeholders
            for values.

        Returns:
            Any: The result of handling the action. The return type may vary depending on the specific action handled.

        """
        async with self._engine.begin() as conn:
            return await conn.execute(
                text(stmt)
            )

    @tool
    async def drop_table(
            self,
            *,
            stmt: str
    ):
        """
        Asynchronously drops an existing database table using the specified SQL statement.
        This method executes the table removal operation based on the provided SQL command.

         parameters:
            stmt (str): The SQL statement to be executed for the insertion, which should include placeholders
            for values.

         Returns:
            Any: The result of handling the action. The return type may vary depending on the specific action handled.

        """
        async with self._engine.begin() as conn:
            return await conn.execute(
                text(stmt)
            )

    @tool
    async def alter_table(
            self,
            *,
            stmt: str,
            values: list[dict]
    ):
        """
        Asynchronously alters an existing database table using the specified SQL statement and a list of value dictionaries.
        This method executes the alteration operation to modify the table structure as defined by the provided parameters.

        parameters:
             stmt (str): The SQL statement to be executed for the insertion, which should include placeholders
             for values.
             values (list[dict]): A list of dictionaries containing the values to be inserted, where each dictionary
             represents a set of values corresponding to the placeholders in the SQL statement.

        Returns:
            Any: The result of handling the action. The return type may vary depending on the specific action handled.

        """

        return await self._stat_begin(
            stmt=stmt,
            values=values
        )

    async def _stat_begin(
            self,
            *,
            stmt: str,
            values: list[dict]
    ):
        """
        Asynchronously begins a statistical operation using the specified SQL statement and a list of value dictionaries.
        This method sets up the context for performing statistical analysis based on the provided parameters.

        parameters:
             stmt (str): The SQL statement to be executed for the insertion, which should include placeholders
             for values.
             values (list[dict]): A list of dictionaries containing the values to be inserted, where each dictionary
             represents a set of values corresponding to the placeholders in the SQL statement.

        Returns:
            Any: The result of handling the action. The return type may vary depending on the specific action handled.

        """

        async with self._engine.begin() as conn:
            return await conn.execute(
                text(stmt),
                values
            )

    @tool
    async def get_schema_metadata(self, schema: str = None):
        """
        Fetch full metadata for the given database schema.

        Supports:
            - PostgreSQL
            - MySQL / MariaDB
            - SQLite

        Returned metadata:
        {
            "schema": "public",
            "tables": [
                {
                    "name": "users",
                    "ddl": "CREATE TABLE ...",
                    "columns": [
                        {"name": "id", "type": "integer", "nullable": false, "default": "..."}
                    ]
                }
            ]
        }

        Args:
            schema (str, optional):
                - PostgreSQL: default "public"
                - MySQL: current database
                - SQLite: schema ignored

        Returns:
            dict: schema → tables → columns + ddl
        """
        async with self._engine.connect() as conn:
            dialect = conn.dialect.name.lower()

            # -------- Set Default Schema -------- #
            if dialect == "postgresql" and schema is None:
                schema = "public"

            if dialect == "mysql" and schema is None:
                result = await conn.execute(text("SELECT DATABASE();"))
                schema = result.scalar()

            if dialect == "sqlite":
                schema = "main"  # SQLite has no schemas

            final = {"schema": schema, "tables": []}

            # ============================================================
            # 1. TABLE LIST
            # ============================================================
            if dialect == "postgresql":
                query_tables = text("""
                    SELECT tablename AS table_name
                    FROM pg_catalog.pg_tables
                    WHERE schemaname = :schema;
                """)
                rows = await conn.execute(query_tables, {"schema": schema})
                table_list = [{"table_name": r._mapping["table_name"]} for r in rows]

            elif dialect == "mysql":
                query_tables = text("""
                    SELECT TABLE_NAME AS table_name
                    FROM information_schema.tables
                    WHERE table_schema = :schema;
                """)
                rows = await conn.execute(query_tables, {"schema": schema})
                table_list = [{"table_name": r._mapping["table_name"]} for r in rows]

            elif dialect == "sqlite":
                query_tables = text("""
                    SELECT name AS table_name
                    FROM sqlite_master
                    WHERE type='table' AND name NOT LIKE 'sqlite_%';
                """)
                rows = await conn.execute(query_tables)
                table_list = [{"table_name": r._mapping["table_name"]} for r in rows]

            else:
                return {"error": f"Unsupported dialect: {dialect}"}

            # ============================================================
            # 2. PER-TABLE METADATA
            # ============================================================
            for t in table_list:
                table_name = t["table_name"]

                # -----------------------------------
                # Columns
                # -----------------------------------
                if dialect in ("postgresql", "mysql"):
                    query_columns = text("""
                        SELECT
                            column_name,
                            data_type,
                            is_nullable,
                            column_default
                        FROM information_schema.columns
                        WHERE table_schema = :schema
                          AND table_name = :table
                        ORDER BY ordinal_position;
                    """)
                    rows = await conn.execute(
                        query_columns, {"schema": schema, "table": table_name}
                    )

                    columns = []
                    for r in rows:
                        m = r._mapping
                        columns.append({
                            "name": m["column_name"],
                            "type": m["data_type"],
                            "nullable": m["is_nullable"] in ("YES", "yes", True, "1"),
                            "default": m["column_default"]
                        })

                elif dialect == "sqlite":
                    rows = await conn.execute(text(f"PRAGMA table_info({table_name});"))

                    columns = []
                    for r in rows:
                        m = r._mapping
                        columns.append({
                            "name": m["name"],
                            "type": m["type"],
                            "nullable": not m["notnull"],
                            "default": m["dflt_value"]
                        })

                # -----------------------------------
                # DDL
                # -----------------------------------
                if dialect == "postgresql":
                    query_ddl = text("""
                        SELECT
                            'CREATE TABLE ' || table_schema || '.' || table_name || E'\n(\n' ||
                            string_agg('    ' || column_name || ' ' || data_type, E',\n') ||
                            E'\n);' AS ddl
                        FROM information_schema.columns
                        WHERE table_schema = :schema
                          AND table_name = :table
                        GROUP BY table_schema, table_name;
                    """)
                    ddl = (await conn.execute(query_ddl, {"schema": schema, "table": table_name})).scalar()

                elif dialect == "mysql":
                    row = await conn.execute(text(f"SHOW CREATE TABLE `{schema}`.`{table_name}`;"))
                    ddl = row.fetchone()[1]

                elif dialect == "sqlite":
                    row = await conn.execute(
                        text("SELECT sql FROM sqlite_master WHERE name=:name;"),
                        {"name": table_name},
                    )
                    ddl = row.scalar()

                # -----------------------------------
                # Build output
                # -----------------------------------
                final["tables"].append({
                    "name": table_name,
                    "ddl": ddl,
                    "columns": columns
                })

            return final
