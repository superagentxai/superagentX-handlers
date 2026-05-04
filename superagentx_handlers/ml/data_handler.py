import logging
from pathlib import Path
import pandas as pd

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)

class FraudDataHandler(BaseHandler):

    def __init__(
            self,
            *,
            folder_path: str,
            sample_size: int = 1000
    ):
        super().__init__()
        self.folder_path = folder_path
        self.sample_size = sample_size

        self.dfs = {}
        self.relationships = []

    async def _load_all_csvs(self):
        dfs = {}

        for file in Path(self.folder_path).glob("*.csv"):
            df = await sync_to_async(pd.read_csv, file)
            df.columns = [col.lower() for col in df.columns]

            if self.sample_size and len(df) > self.sample_size:
                df = df.sample(self.sample_size, random_state=42)

            table_name = file.stem.lower()
            dfs[table_name] = df
            logger.info(f"Loaded table '{table_name}' with {len(df)} rows.")

        return dfs

    async def _detect_relationships(self, dfs: dict):
        relationships = []

        value_sets = {}
        for table, df in dfs.items():
            for col in df.columns:
                if col in ["name", "description", "address", "email"]:
                    continue

                vals = set(df[col].dropna().astype(str).str.strip())
                if vals:
                    value_sets[(table, col)] = vals

        keys = list(value_sets.keys())

        for i, (table1, col1) in enumerate(keys):
            for table2, col2 in keys[i + 1:]:

                if table1 == table2:
                    continue

                vals1 = value_sets[(table1, col1)]
                vals2 = value_sets[(table2, col2)]

                intersection = vals1 & vals2
                overlap_ratio = len(intersection) / min(len(vals1), len(vals2))

                if overlap_ratio > 0.5:
                    relationships.append({
                        "from_table": table1,
                        "from_column": col1,
                        "to_table": table2,
                        "to_column": col2,
                        "overlap_ratio": overlap_ratio,
                        "common_values": list(intersection)[:10]
                    })

        logger.info(f"Detected {len(relationships)} relationships.")
        return relationships

    @tool
    async def ingest(self):
        """
        Loads all CSV files from the folder and detects relationships between them.
        Stores everything in memory for downstream ML usage.
        """

        try:
            self.dfs = await self._load_all_csvs()
            self.relationships = await self._detect_relationships(self.dfs)

            return {
                "status": "success",
                "tables_loaded": list(self.dfs.keys()),
                "relationships_found": len(self.relationships)
            }

        except Exception as ex:
            logger.error(f"Error during ingestion: {ex}", exc_info=True)
            raise

    @tool
    async def get_tables(self):
        """Returns loaded tables (in-memory)."""
        return list(self.dfs.keys())

    @tool
    async def get_relationships(self):
        """Returns detected relationships."""
        return self.relationships

    @tool
    async def get_table(self, table_name: str):
        """Fetch a specific table as JSON."""
        if table_name not in self.dfs:
            raise ValueError(f"Table '{table_name}' not found")
        return self.dfs[table_name].to_json()