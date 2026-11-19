import pytest
pytest.importorskip("langgraph")
from app.orchestration.graph import create_soc_graph

def test_graph_executes_basic_route():
    graph = create_soc_graph(rag_engine=None)
    state = {"alert": {"alert_id": "ALT-1", "evidence": {"proto": "tcp"},
                       "evidence_summary": "Observed TCP flow", "timestamp": None},
             "routing_context": {"severity": "low", "source": "dataset"},
             "existing_alerts": [], "agent_results": {}, "verification_events": [],
             "response_execution_confirmed": False, "reinvestigation_count": 0,
             "max_reinvestigations": 0}
    result = graph.invoke(state)
    assert "investigation" in result["agent_results"]
    assert "risk_response" in result["agent_results"]
    assert result["verification"]["status"] == "requires_further_investigation"
