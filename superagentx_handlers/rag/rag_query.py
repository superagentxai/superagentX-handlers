import asyncio
import json
import os
from typing import Optional

import asyncpg
from dotenv import load_dotenv
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.llm.openai import AzureOpenAI

load_dotenv()

DB_URL = os.getenv("DB_URL")
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_API_BASE")
EMBEDDING_MODEL = os.getenv("AZURE_OPENAI_EMBEDDING_MODEL")
OPENAI_API_VERSION = os.getenv("OPENAI_API_VERSION")
DEPLOYMENT_MODEL = os.getenv("AZURE_OPENAI_DEPLOYMENT")


class RAGQueryHandler(BaseHandler):

    def __init__(
            self,
            db_url: str = DB_URL,
            embed_model: str = EMBEDDING_MODEL,
            embedding_dim: int = 1536,
            default_similarity_threshold: float = 1.2
    ):
        super().__init__()
        self.db_url = db_url
        self.embed_model = embed_model
        self.embedding_dim = embedding_dim
        self.default_similarity_threshold = default_similarity_threshold

        self.azure_client = AzureOpenAI(
            api_key=AZURE_OPENAI_API_KEY,
            api_version=OPENAI_API_VERSION,
            azure_endpoint=AZURE_OPENAI_ENDPOINT,
        )

        self.pool: Optional[asyncpg.pool.Pool] = None

    async def init_db(self):
        if not self.pool:
            self.pool = await asyncpg.create_pool(self.db_url, min_size=1, max_size=4)

    def emb_sync(self, text: str):
        r = self.azure_client.embeddings.create(model=self.embed_model, input=text)
        return r.data[0].embedding

    async def embed(self, text: str):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.emb_sync, text)

    def vec(self, arr):
        return "[" + ",".join(map(str, arr)) + "]"

    @tool
    async def retrieve_unified(self, query: str, top_k: int = 10) -> dict:
        """
        Unified retrieval:
        - Embedding search for PDF/TXT chunks (using chunks table)
        - LLM-based content inspection for XLSX/CSV tables (reading table_rows)
        - Combines and returns the most relevant results from ALL sources
        """
        await self.init_db()

        q_emb = await self.embed(query)
        q_vec = self.vec(q_emb)

        sql_chunks = """
            SELECT
                d.filename,
                c.chunk_text,
                (c.embedding <-> $1::vector) AS dist
            FROM chunks c
            JOIN documents d ON c.document_id = d.id
            ORDER BY dist ASC
            LIMIT $2;
            """

        async with self.pool.acquire() as conn:
            chunk_rows = await conn.fetch(sql_chunks, q_vec, top_k)

        doc_results = []
        for r in chunk_rows:
            dist = float(r["dist"])
            similarity = 1.0 / (1.0 + dist)
            doc_results.append({
                "source": "document",
                "filename": r["filename"],
                "content": r["chunk_text"],
                "similarity": similarity
            })

        sql_tables = """
            SELECT d.filename, t.sheet_name, t.row_text
            FROM table_rows t
            JOIN documents d ON t.document_id = d.id
            ORDER BY d.filename, t.sheet_name, t.id;
            """

        async with self.pool.acquire() as conn:
            table_rows = await conn.fetch(sql_tables)

        tables = {}
        for r in table_rows:
            key = (r["filename"], r["sheet_name"])
            tables.setdefault(key, []).append(r["row_text"])

        table_results = []
        for (filename, sheet), rows in tables.items():
            preview = rows[:50]
            prompt = f"""
                        You are an expert table analyst.

                        User question:
                        {query}

                        These are up to 50 example rows from a spreadsheet (File: {filename}, Sheet: {sheet}):

                        {json.dumps(preview, indent=2)}

                        Task:
                        1) State whether this sheet likely contains information answering the user's question.
                        2) If yes, return the most relevant row(s) (as text) and a confidence score between 0 and 1.

                        Return JSON ONLY in the format:
                        {{ "relevant": true/false, "rows": ["..."], "confidence": 0.0 }}
                        """
            llm_response = self.azure_client.chat.completions.create(
                model=DEPLOYMENT_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=1
            )
            try:
                data = json.loads(llm_response.choices[0].message.content)
            except Exception:
                continue
            if data.get("relevant"):
                table_results.append({
                    "source": "table",
                    "filename": filename,
                    "sheet_name": sheet,
                    "content": data.get("rows", []),
                    "similarity": float(data.get("confidence", 0.0))
                })

        combined = doc_results + table_results
        combined.sort(key=lambda x: x["similarity"], reverse=True)

        return {"query": query, "results": combined[:top_k]}