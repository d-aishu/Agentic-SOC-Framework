from __future__ import annotations
import json, threading, logging
from pathlib import Path
from typing import Any
logger = logging.getLogger(__name__)

class AgentRepository:
    """Append-only JSONL store for per-agent execution results."""
    def __init__(self, directory: Path):
        self.path = Path(directory) / "agent_results.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
    def save_run(self, alert_id: str, results: dict[str, Any]) -> int:
        count = 0
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            for key, value in results.items():
                row = {"alert_id": alert_id, "agent_key": key, **value}
                handle.write(json.dumps(row, default=str) + "\n"); count += 1
        return count
    def list_for_alert(self, alert_id: str) -> list[dict[str, Any]]:
        if not self.path.exists(): return []
        rows = []
        with self._lock:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                    if row.get("alert_id") == alert_id: rows.append(row)
                except json.JSONDecodeError: logger.warning("Skipping malformed agent result row")
        return rows
