from app.agents.verification import verification_node
from app.agents.risk_response import risk_response_node

def test_verification_does_not_claim_stopped_without_data():
    state = {"verification_events": [], "response_execution_confirmed": False,
             "agent_results": {}, "reinvestigation_count": 0}
    out = verification_node(state)
    assert out["verification"]["status"] == "requires_further_investigation"

def test_suspicious_verification_event_is_unresolved():
    state = {"verification_events": [{"suspicious": True}], "response_execution_confirmed": True,
             "agent_results": {}, "reinvestigation_count": 0}
    out = verification_node(state)
    assert out["verification"]["status"] == "unresolved"

def test_high_risk_disruptive_action_requires_approval():
    state = {"alert": {}, "routing_context": {"severity": "critical"},
             "agent_results": {"investigation": {"confidence": 0.9, "evidence": ["a", "b"]}}}
    out = risk_response_node(state)
    disruptive = [a for a in out["recommended_actions"] if a["requires_human_approval"]]
    assert disruptive and disruptive[0]["executed"] is False


def test_verification_can_resolve_simulated_success():
    state = {"verification_events": [{"suspicious": False, "event": "no suspicious activity"}],
             "response_execution_confirmed": True, "agent_results": {}, "reinvestigation_count": 0}
    out = verification_node(state)
    assert out["verification"]["status"] == "resolved"
