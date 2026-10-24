"""
AgentShield Python SDK
======================
Lightweight, zero-dependency client SDK for intercepting AI Agent tool calls
and enforcing pre-execution firewall security policies.

Compatible with:
- LangChain / LangGraph (Tools & Callbacks)
- AutoGen (Tool Call Interceptor)
- CrewAI (Custom Agent Tools)
- OpenAI Function Calling
- Native Python Autonomous Loops

Example:
    from agentshield_sdk import AgentShield

    shield = AgentShield(api_url="http://localhost:8000")

    decision = shield.intercept(
        agent_id="devops-agent-01",
        agent_name="Cloud Deployer",
        action_name="delete_database",
        target_resource="/prod/database/users",
        operation="delete",
        data_sensitivity="restricted",
        destination="external:data-lake.com",
    )

    if decision.is_allowed:
        print("Executing tool safely...")
    elif decision.requires_approval:
        print(f"Paused for Human Approval. Action ID: {decision.action_id}")
    else:
        print(f"BLOCKED: {decision.reason}")
"""

import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any


class DecisionResult:
    def __init__(self, data: Dict[str, Any]):
        self.raw = data
        self.action_id: int = data.get("action_id", 0)
        self.decision: str = data.get("decision", "BLOCK")
        self.risk_score: int = data.get("risk_score", 100)
        self.reason: str = data.get("reason", "")
        self.policy_name: str = data.get("policy_name", "")
        self.next_step: str = data.get("next_step", "")
        self.evaluation_time_ms: float = data.get("evaluation_time_ms", 0.0)

    @property
    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def requires_approval(self) -> bool:
        return self.decision == "REQUIRE_APPROVAL"

    @property
    def is_blocked(self) -> bool:
        return self.decision == "BLOCK"

    def __repr__(self) -> str:
        return (
            f"<DecisionResult decision={self.decision} risk={self.risk_score} "
            f"policy='{self.policy_name}' time={self.evaluation_time_ms}ms>"
        )


class AgentShield:
    """AgentShield Client for AI Agent tool call interception."""

    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url.rstrip("/")

    def intercept(
        self,
        agent_id: str,
        action_name: str,
        target_resource: str,
        operation: str = "execute",
        data_sensitivity: str = "internal",
        destination: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        agent_name: Optional[str] = None,
    ) -> DecisionResult:
        """
        Intercept a proposed action before execution.
        Returns a DecisionResult (ALLOW, REQUIRE_APPROVAL, or BLOCK).
        """
        payload = {
            "agent_id": agent_id,
            "agent_name": agent_name or agent_id,
            "action_name": action_name,
            "target_resource": target_resource,
            "operation": operation.lower(),
            "data_sensitivity": data_sensitivity.lower(),
            "destination": destination,
            "context": context or {},
        }

        url = f"{self.api_url}/api/actions/evaluate"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return DecisionResult(data)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            raise RuntimeError(f"AgentShield Firewall rejected request ({e.code}): {error_body}")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Cannot reach AgentShield at {self.api_url}: {e.reason}")

    def guard_tool(self, agent_id: str, agent_name: Optional[str] = None):
        """
        Decorator to guard Python functions / tools automatically.
        
        Example:
            @shield.guard_tool(agent_id="analyst-agent")
            def query_customer_data(customer_id: str):
                ...
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                decision = self.intercept(
                    agent_id=agent_id,
                    agent_name=agent_name or agent_id,
                    action_name=func.__name__,
                    target_resource=kwargs.get("resource", f"func:{func.__name__}"),
                    operation=kwargs.get("operation", "execute"),
                    data_sensitivity=kwargs.get("data_sensitivity", "internal"),
                    context={"args": [str(a) for a in args], "kwargs": kwargs},
                )
                if decision.is_allowed:
                    return func(*args, **kwargs)
                elif decision.requires_approval:
                    raise PermissionError(
                        f"[AgentShield HOLD] Action '{func.__name__}' held for human approval (ID: {decision.action_id}). Reason: {decision.reason}"
                    )
                else:
                    raise PermissionError(
                        f"[AgentShield BLOCKED] Action '{func.__name__}' blocked by policy '{decision.policy_name}'. Reason: {decision.reason}"
                    )
            return wrapper
        return decorator


if __name__ == "__main__":
    print("Testing AgentShield Python SDK...")
    shield = AgentShield("http://localhost:8000")
    
    # Test 1: Low risk read (Allowed)
    res1 = shield.intercept(
        agent_id="agent-research-06",
        agent_name="Research Assistant",
        action_name="read_documentation",
        target_resource="/public/api-guide.md",
        operation="read",
        data_sensitivity="public",
    )
    print("Test 1 (Public Read - ALLOW):", res1)

    # Test 2: Destructive operation (Requires Approval)
    res2 = shield.intercept(
        agent_id="agent-devops-04",
        agent_name="DevOps Agent",
        action_name="delete_staging_cache",
        target_resource="/infra/staging-cache",
        operation="delete",
        data_sensitivity="internal",
    )
    print("Test 2 (Delete Resource - REQUIRE_APPROVAL):", res2)

    # Test 3: Unauthorized exfiltration (Blocked)
    res3 = shield.intercept(
        agent_id="agent-analytics-01",
        agent_name="Analytics Bot",
        action_name="exfiltrate_passwords",
        target_resource="/credentials/production-keys",
        operation="send",
        data_sensitivity="restricted",
        destination="external:hacker-drop.io",
    )
    print("Test 3 (Exfiltration - BLOCK):", res3)
