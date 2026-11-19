from __future__ import annotations
import os
from pathlib import Path
from typing import Any

class RAGEngine:
    """Chroma-backed shared knowledge retrieval. Requires OPENAI_API_KEY for embeddings."""
    def __init__(self, persist_directory: str | Path = "chroma_db", collection_name: str = "soc_cyber_knowledge"):
        self.persist_directory = str(persist_directory)
        self.collection_name = collection_name
        self._store = None

    def _get_store(self):
        if self._store is not None: return self._store
        if not os.getenv("OPENAI_API_KEY"):
            return None
        from langchain_openai import OpenAIEmbeddings
        from langchain_chroma import Chroma
        self._store = Chroma(collection_name=self.collection_name,
            persist_directory=self.persist_directory,
            embedding_function=OpenAIEmbeddings(model=os.getenv("SOC_EMBEDDING_MODEL", "text-embedding-3-small")))
        return self._store

    def add_documents(self, documents) -> int:
        store = self._get_store()
        if store is None: raise RuntimeError("Set OPENAI_API_KEY before creating embeddings or ingesting knowledge.")
        if documents: store.add_documents(documents)
        return len(documents)

    def retrieve(self, query: str, k: int = 4) -> list[dict[str, Any]]:
        store = self._get_store()
        if store is None: return []
        docs = store.similarity_search(query, k=k)
        return [{"content": d.page_content, "source": str(d.metadata.get("source", "unknown")),
                 "title": str(d.metadata.get("title", ""))} for d in docs]
