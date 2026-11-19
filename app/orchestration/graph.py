from __future__ import annotations
from langgraph.graph import StateGraph, END
from app.orchestration.state import SOCState
from app.orchestration.adaptive_router import choose_route, load_routing_rules
from app.agents.investigation import investigation_node
from app.agents.threat_intel import threat_intel_node
from app.agents.correlation import correlation_node
from app.agents.risk_response import risk_response_node
from app.agents.verification import verification_node

def create_soc_graph(rag_engine=None, routing_rules=None):
    routing_rules = routing_rules or load_routing_rules()
    def router_node(state: SOCState):
        decision = choose_route(state["routing_context"] | {"evidence": state["alert"].get("evidence", {}),
                               "evidence_summary": state["alert"].get("evidence_summary", "")},
                                state.get("existing_alerts", []), routing_rules)
        state["selected_agents"] = decision["selected_agents"]
        state["routing_decision"] = decision
        state["agent_results"] = state.get("agent_results", {})
        state["rag_engine"] = rag_engine
        return state

    def after_investigation(state: SOCState):
        selected = list(state.get("selected_agents", ["investigation"]))
        confidence = float(state.get("agent_results", {}).get("investigation", {}).get("confidence", 0.5))
        # Escalate a seemingly low-risk alert when the first investigation is uncertain.
        threshold = float((routing_rules or {}).get("low_confidence_threshold", 0.45))
        if confidence < threshold:
            selected.extend([name for name in ("threat_intel", "correlation") if name not in selected])
            state["selected_agents"] = selected
        if "threat_intel" in selected or "correlation" in selected:
            return [name for name in ("threat_intel", "correlation") if name in selected]
        return "risk_response"

    def after_verification(state: SOCState):
        if state.get("verification", {}).get("status") == "resolved": return "end"
        if int(state.get("reinvestigation_count", 0)) > int(state.get("max_reinvestigations", 1)): return "end"
        return "investigation"

    graph = StateGraph(SOCState)
    graph.add_node("router", router_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("threat_intel", threat_intel_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("risk_response", risk_response_node)
    graph.add_node("verification", verification_node)
    graph.set_entry_point("router")
    graph.add_edge("router", "investigation")
    graph.add_conditional_edges("investigation", after_investigation,
        {"threat_intel": "threat_intel", "correlation": "correlation", "risk_response": "risk_response"})
    graph.add_edge(["threat_intel", "correlation"], "risk_response")
    graph.add_edge("risk_response", "verification")
    graph.add_conditional_edges("verification", after_verification,
        {"investigation": "investigation", "end": END})
    return graph.compile()
