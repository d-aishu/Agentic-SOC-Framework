from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dotenv import load_dotenv
load_dotenv()
from app.config.settings import get_settings
from app.rag.ingestion import ingest_knowledge

if __name__ == "__main__":
    settings = get_settings()
    count = ingest_knowledge(Path("knowledge"), settings.soc_chroma_dir)
    print(f"Ingested {count} knowledge chunks into {settings.soc_chroma_dir}")
