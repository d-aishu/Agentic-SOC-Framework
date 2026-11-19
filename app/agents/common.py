from __future__ import annotations
import os, json
from typing import Any
from datetime import datetime, timezone
from app.schemas.soc import AgentResult

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def result(agent: str, findings: list[str], evidence: list[str] | None = None,
           confidence: float = 0.5, status: str = "completed", sources=None, details=None) -> dict:
    return AgentResult(agent_name=agent, findings=findings, evidence=evidence or [],
        confidence=max(0.0, min(1.0, float(confidence))), status=status,
        sources=sources or [], details=details or {}).model_dump(mode="json")

def get_llm():
    """Return an OpenAI chat model only when OPENAI_API_KEY is configured."""
    if not os.getenv("OPENAI_API_KEY"):
        return None
    try:
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=os.getenv("SOC_LLM_MODEL", "gpt-4o-mini"), temperature=0)
    except Exception:
        return None

def invoke_json(llm, system_prompt: str, user_payload: dict[str, Any]) -> dict | None:
    if llm is None:
        return None
    try:
        from langchain_core.messages import SystemMessage, HumanMessage
        response = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=json.dumps(user_payload, default=str))])
        content = response.content if hasattr(response, "content") else str(response)
        if isinstance(content, list):
            content = "".join(str(x.get("text", "")) if isinstance(x, dict) else str(x) for x in content)
        content = str(content).strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        return json.loads(content)
    except Exception:
        return None
