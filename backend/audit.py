"""
AgentShield — Audit helper module.
Wraps database audit operations for cleaner usage in the API routes.
"""

from datetime import datetime, timezone
from typing import Optional
from database import insert_audit_log


async def record_audit_event(
    agent_id: str,
    agent_name: str,
    action_name: str,
    target_resource: str,
    operation: str,
    data_sensitivity: str,
    decision: str,
    risk_score: int,
    reason: str,
    policy_name: str,
    execution_status: str,
    approval_status: Optional[str] = None,
):
    """Record a complete audit event in the database with hash-linking."""
    await insert_audit_log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "agent_name": agent_name,
        "action_name": action_name,
        "target_resource": target_resource,
        "operation": operation,
        "data_sensitivity": data_sensitivity,
        "decision": decision,
        "risk_score": risk_score,
        "reason": reason,
        "policy_name": policy_name,
        "approval_status": approval_status,
        "execution_status": execution_status,
    })
