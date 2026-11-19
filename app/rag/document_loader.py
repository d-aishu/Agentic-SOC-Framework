from __future__ import annotations
from pathlib import Path
from langchain_core.documents import Document

SUPPORTED = {".txt", ".md", ".json", ".csv"}

def load_knowledge_documents(root: str | Path) -> list[Document]:
    root = Path(root)
    docs: list[Document] = []
    if not root.exists(): return docs
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in SUPPORTED and path.name.lower() != "indicators.json":
            try:
                text = path.read_text(encoding="utf-8", errors="ignore").strip()
                if text:
                    docs.append(Document(page_content=text, metadata={"source": str(path), "title": path.stem, "category": path.parent.name}))
            except OSError:
                continue
    return docs
