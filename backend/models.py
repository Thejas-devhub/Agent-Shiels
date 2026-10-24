"""
AgentShield — Pydantic models for request/response validation.
All data structures used across the API are defined here.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
from datetime import datetime


# ── Enums ──────────────────────────────────────────────────────────────

class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ExecutionStatus(str, Enum):
    NOT_EXECUTED = "NOT_EXECUTED"
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    REJECTED = "REJECTED"


class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Operation(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SEND = "send"
    MODIFY = "modify"
    EXECUTE = "execute"


# ── Request Models ─────────────────────────────────────────────────────

class ActionRequest(BaseModel):
    """An AI agent's proposed tool call to be evaluated by the policy engine."""
    action_name: str = Field(..., min_length=1, max_length=200)
    agent_id: str = Field(..., min_length=1, max_length=100)
    agent_name: str = Field(default="Unknown Agent", max_length=100)
    target_resource: str = Field(..., min_length=1, max_length=300)
    operation: Operation
    data_sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    destination: Optional[str] = Field(default=None, max_length=300)
    context: Optional[dict] = None


class ApprovalDecisionRequest(BaseModel):
    """Human decision on a pending approval request."""
    reviewer: str = Field(default="Security Admin", max_length=100)
    comment: Optional[str] = Field(default=None, max_length=500)


# ── Response Models ────────────────────────────────────────────────────

class PolicyDecisionResponse(BaseModel):
    """Result of a policy evaluation."""
    action_id: int
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    reason: str
    policy_name: str
    next_step: str
    evaluation_time_ms: float


class ApprovalItem(BaseModel):
    """An item in the approval queue."""
    id: int
    action_id: int
    agent_id: str
    agent_name: str
    action_name: str
    target_resource: str
    operation: str
    risk_score: int
    reason: str
    status: ApprovalStatus
    created_at: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_comment: Optional[str] = None


class AuditLogEntry(BaseModel):
    """A single audit log record."""
    id: int
    timestamp: str
    agent_id: str
    agent_name: str
    action_name: str
    target_resource: str
    operation: str
    data_sensitivity: str
    decision: str
    risk_score: int
    reason: str
    policy_name: str
    approval_status: Optional[str] = None
    execution_status: str
    record_hash: Optional[str] = None
    previous_hash: Optional[str] = None


class DashboardStats(BaseModel):
    """Aggregated dashboard metrics."""
    total_actions: int
    allowed_actions: int
    blocked_actions: int
    pending_approvals: int
    approved_actions: int
    rejected_actions: int
    avg_risk_score: float
    risk_distribution: dict
    recent_activity: List[dict]
    security_status: str


class PolicyInfo(BaseModel):
    """A security policy displayed in the policy page."""
    id: str
    name: str
    category: str
    description: str
    active: bool
    severity: str
    conditions: str
    action_on_match: str


class SimulationResult(BaseModel):
    """Result of a single test scenario."""
    scenario: str
    action_name: str
    expected_decision: str
    actual_decision: str
    passed: bool
    risk_score: int
    reason: str
    evaluation_time_ms: float


class SimulationSummary(BaseModel):
    """Overall simulation/test suite summary."""
    total_tests: int
    passed: int
    failed: int
    unauthorized_blocked: int
    legitimate_allowed: int
    false_positives: int
    avg_evaluation_time_ms: float
    results: List[SimulationResult]
    disclaimer: str


class IntegrityReport(BaseModel):
    """Audit log integrity verification report."""
    total_records: int
    verified_records: int
    broken_links: int
    integrity_status: str
    details: str
