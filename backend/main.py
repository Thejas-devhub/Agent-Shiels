"""
AgentShield — FastAPI Application.
AI Action Firewall: monitors, evaluates, and controls AI agent actions.
"""

import time
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from models import (
    ActionRequest, ApprovalDecisionRequest, PolicyDecisionResponse,
    DashboardStats, SimulationSummary, IntegrityReport,
)
from policy_engine import evaluate_action, run_simulation
from database import (
    init_db, seed_policies, seed_demo_data,
    insert_action, insert_approval, get_all_actions,
    get_approval_by_id, update_approval, get_all_approvals,
    get_audit_logs, get_dashboard_stats, get_all_policies,
    toggle_policy, verify_audit_integrity,
)
from audit import record_audit_event


# ── Application lifecycle ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and seed data on startup."""
    await init_db()
    await seed_policies()
    await seed_demo_data()
    yield


app = FastAPI(
    title="AgentShield API",
    description="AI Action Firewall — Security policy engine for autonomous AI agents",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow the Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ─────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "AgentShield API",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Dashboard ──────────────────────────────────────────────────────────

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def dashboard_stats():
    """Get aggregated dashboard statistics."""
    return await get_dashboard_stats()


# ── Action Evaluation ──────────────────────────────────────────────────

@app.post("/api/actions/evaluate", response_model=PolicyDecisionResponse)
async def evaluate_agent_action(action: ActionRequest):
    """
    Evaluate an AI agent's proposed action against the security policy.
    This is the core enforcement endpoint — all actions must pass through here.
    """
    start = time.perf_counter()

    # Evaluate against policy engine
    decision, risk_score, reason, policy_name = evaluate_action(action)

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
    now = datetime.now(timezone.utc).isoformat()

    # Determine execution status based on decision
    if decision.value == "ALLOW":
        execution_status = "EXECUTED"
    elif decision.value == "BLOCK":
        execution_status = "BLOCKED"
    else:
        execution_status = "PENDING_APPROVAL"

    # Determine next step message
    if decision.value == "ALLOW":
        next_step = "Action has been allowed and executed through the controlled simulation layer."
    elif decision.value == "BLOCK":
        next_step = "Action has been blocked. The requested operation was NOT executed. Review the security policy or contact an administrator."
    else:
        next_step = "Action is pending human approval. Visit the Approval Center to review and approve or reject this request."

    # Persist the action
    action_id = await insert_action({
        "timestamp": now,
        "agent_id": action.agent_id,
        "agent_name": action.agent_name,
        "action_name": action.action_name,
        "target_resource": action.target_resource,
        "operation": action.operation.value,
        "data_sensitivity": action.data_sensitivity.value,
        "destination": action.destination,
        "context": action.context,
        "decision": decision.value,
        "risk_score": risk_score,
        "reason": reason,
        "policy_name": policy_name,
        "execution_status": execution_status,
    })

    # Create approval request if needed
    if decision.value == "REQUIRE_APPROVAL":
        await insert_approval({
            "action_id": action_id,
            "agent_id": action.agent_id,
            "agent_name": action.agent_name,
            "action_name": action.action_name,
            "target_resource": action.target_resource,
            "operation": action.operation.value,
            "risk_score": risk_score,
            "reason": reason,
            "created_at": now,
        })

    # Record audit trail
    await record_audit_event(
        agent_id=action.agent_id,
        agent_name=action.agent_name,
        action_name=action.action_name,
        target_resource=action.target_resource,
        operation=action.operation.value,
        data_sensitivity=action.data_sensitivity.value,
        decision=decision.value,
        risk_score=risk_score,
        reason=reason,
        policy_name=policy_name,
        execution_status=execution_status,
        approval_status="PENDING" if decision.value == "REQUIRE_APPROVAL" else None,
    )

    return PolicyDecisionResponse(
        action_id=action_id,
        decision=decision,
        risk_score=risk_score,
        reason=reason,
        policy_name=policy_name,
        next_step=next_step,
        evaluation_time_ms=elapsed_ms,
    )


@app.get("/api/actions")
async def list_actions():
    """List all evaluated actions."""
    return await get_all_actions()


# ── Approvals ──────────────────────────────────────────────────────────

@app.get("/api/approvals")
async def list_approvals():
    """List all approval requests."""
    return await get_all_approvals()


@app.post("/api/approvals/{approval_id}/approve")
async def approve_action(approval_id: int, body: ApprovalDecisionRequest):
    """
    Approve a pending action.
    Only PENDING actions can be approved. Prevents repeated or contradictory decisions.
    """
    approval = await get_approval_by_id(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found.")

    if approval["status"] != "PENDING":
        raise HTTPException(
            status_code=409,
            detail=f"Cannot approve: request is already {approval['status']}. "
                   f"Only PENDING requests can be approved.",
        )

    await update_approval(approval_id, "APPROVED", body.reviewer, body.comment)

    # Record approval in audit log
    await record_audit_event(
        agent_id=approval["agent_id"],
        agent_name=approval["agent_name"],
        action_name=approval["action_name"],
        target_resource=approval["target_resource"],
        operation=approval["operation"],
        data_sensitivity="internal",
        decision="REQUIRE_APPROVAL",
        risk_score=approval["risk_score"],
        reason=f"APPROVED by {body.reviewer}. {body.comment or ''}",
        policy_name="Human Approval Decision",
        execution_status="EXECUTED",
        approval_status="APPROVED",
    )

    return {
        "message": f"Action approved by {body.reviewer}. Simulated execution completed.",
        "approval_id": approval_id,
        "status": "APPROVED",
    }


@app.post("/api/approvals/{approval_id}/reject")
async def reject_action(approval_id: int, body: ApprovalDecisionRequest):
    """
    Reject a pending action.
    Rejected actions are NEVER executed.
    """
    approval = await get_approval_by_id(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found.")

    if approval["status"] != "PENDING":
        raise HTTPException(
            status_code=409,
            detail=f"Cannot reject: request is already {approval['status']}. "
                   f"Only PENDING requests can be rejected.",
        )

    await update_approval(approval_id, "REJECTED", body.reviewer, body.comment)

    # Record rejection in audit log
    await record_audit_event(
        agent_id=approval["agent_id"],
        agent_name=approval["agent_name"],
        action_name=approval["action_name"],
        target_resource=approval["target_resource"],
        operation=approval["operation"],
        data_sensitivity="internal",
        decision="REQUIRE_APPROVAL",
        risk_score=approval["risk_score"],
        reason=f"REJECTED by {body.reviewer}. {body.comment or ''}",
        policy_name="Human Approval Decision",
        execution_status="REJECTED",
        approval_status="REJECTED",
    )

    return {
        "message": f"Action rejected by {body.reviewer}. Operation was NOT executed.",
        "approval_id": approval_id,
        "status": "REJECTED",
    }


# ── Audit Logs ─────────────────────────────────────────────────────────

@app.get("/api/audit-logs")
async def list_audit_logs(
    decision: Optional[str] = Query(None),
    agent_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    """Get audit logs with optional filtering."""
    return await get_audit_logs(decision=decision, agent_id=agent_id, search=search)


@app.get("/api/audit-logs/integrity", response_model=IntegrityReport)
async def audit_integrity():
    """Verify the tamper-evident hash chain of audit logs."""
    return await verify_audit_integrity()


# ── Policies ───────────────────────────────────────────────────────────

@app.get("/api/policies")
async def list_policies():
    """Get all security policies."""
    return await get_all_policies()


@app.patch("/api/policies/{policy_id}")
async def update_policy(policy_id: str, active: bool = Query(...)):
    """Toggle a policy's active state."""
    await toggle_policy(policy_id, active)
    return {"message": f"Policy {policy_id} {'activated' if active else 'deactivated'}."}


# ── Simulation ─────────────────────────────────────────────────────────

@app.post("/api/simulation/run", response_model=SimulationSummary)
async def run_attack_simulation():
    """Run the predefined attack simulation test suite."""
    return run_simulation()


# ── Entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
