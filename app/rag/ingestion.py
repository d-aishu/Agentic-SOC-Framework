from __future__ import annotations
from pathlib import Path
from langchain_text_splitters import RecursiveCharacterTextSplitter
from app.rag.document_loader import load_knowledge_documents
from app.rag.rag_engine import RAGEngine

def ingest_knowledge(knowledge_dir: str | Path, persist_dir: str | Path) -> int:
    docs = load_knowledge_documents(knowledge_dir)
    splitter = RecursiveCharacterTextSplitter(chunk_size=900, chunk_overlap=150)
    chunks = splitter.split_documents(docs)
    if not chunks:
        raise RuntimeError(f"No supported knowledge documents found under {knowledge_dir}")
    return RAGEngine(persist_dir).add_documents(chunks)
