"""
AgentShield — SQLite database layer.
Handles initialization, seeding, and all CRUD operations.
Uses aiosqlite for async access.
"""

import aiosqlite
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Optional, List

DB_PATH = os.path.join(os.path.dirname(__file__), "agentshield.db")


def _compute_hash(record_data: str, previous_hash: str = "") -> str:
    """Compute SHA-256 hash for tamper-evident audit chain."""
    payload = f"{previous_hash}|{record_data}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def get_db() -> aiosqlite.Connection:
    """Get a database connection with row_factory enabled."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db():
    """Create tables if they don't exist."""
    db = await get_db()
    try:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL DEFAULT 'Unknown Agent',
                action_name TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                operation TEXT NOT NULL,
                data_sensitivity TEXT NOT NULL DEFAULT 'internal',
                destination TEXT,
                context TEXT,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL,
                policy_name TEXT NOT NULL,
                execution_status TEXT NOT NULL DEFAULT 'NOT_EXECUTED'
            );

            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id INTEGER NOT NULL UNIQUE,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL DEFAULT 'Unknown Agent',
                action_name TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                operation TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                created_at TEXT NOT NULL,
                reviewed_by TEXT,
                reviewed_at TEXT,
                review_comment TEXT,
                FOREIGN KEY (action_id) REFERENCES actions(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL DEFAULT 'Unknown Agent',
                action_name TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                operation TEXT NOT NULL,
                data_sensitivity TEXT NOT NULL DEFAULT 'internal',
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL,
                policy_name TEXT NOT NULL,
                approval_status TEXT,
                execution_status TEXT NOT NULL DEFAULT 'NOT_EXECUTED',
                record_hash TEXT,
                previous_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                severity TEXT NOT NULL DEFAULT 'medium',
                conditions TEXT NOT NULL,
                action_on_match TEXT NOT NULL
            );
        """)
        await db.commit()
    finally:
        await db.close()


async def seed_policies():
    """Insert default security policies if the table is empty."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM policies")
        row = await cursor.fetchone()
        if row["cnt"] > 0:
            return

        policies = [
            ("POL-AC-001", "Authorized Resource Access", "access_control",
             "Allow read access to resources the requesting agent is authorized to access.",
             1, "low",
             "Operation is READ and agent has authorization for the target resource",
             "ALLOW"),
            ("POL-AC-002", "Unauthorized Resource Block", "access_control",
             "Block access to restricted resources when the agent lacks proper authorization.",
             1, "critical",
             "Agent lacks authorization for the target resource OR resource is marked restricted",
             "BLOCK"),
            ("POL-DP-001", "Confidential Data Transfer Block", "data_privacy",
             "Block transfers of confidential or restricted data to external destinations.",
             1, "critical",
             "Data sensitivity is CONFIDENTIAL or RESTRICTED and destination is external",
             "BLOCK"),
            ("POL-DP-002", "Internal Data Sharing", "data_privacy",
             "Allow sharing of public or internal data within authorized internal channels.",
             1, "low",
             "Data sensitivity is PUBLIC or INTERNAL and destination is internal or absent",
             "ALLOW"),
            ("POL-ET-001", "External Transfer Review", "external_transfers",
             "Require human approval for any data transfer to external email domains.",
             1, "high",
             "Destination contains external email domain and data is INTERNAL sensitivity",
             "REQUIRE_APPROVAL"),
            ("POL-DA-001", "Destructive Action Approval", "destructive_actions",
             "Require human approval before executing any delete operation on shared resources.",
             1, "high",
             "Operation is DELETE on any shared or team resource",
             "REQUIRE_APPROVAL"),
            ("POL-DA-002", "Critical Record Modification", "destructive_actions",
             "Require human approval for modifications to business-critical records.",
             1, "high",
             "Operation is MODIFY on records tagged as important or critical",
             "REQUIRE_APPROVAL"),
            ("POL-HA-001", "High Risk Score Escalation", "human_approval",
             "Escalate any action with a computed risk score above 70 for human review.",
             1, "high",
             "Computed risk score exceeds 70 and action is not already blocked",
             "REQUIRE_APPROVAL"),
            ("POL-GEN-001", "Public Document Access", "access_control",
             "Allow unrestricted read access to public documents and summaries.",
             1, "low",
             "Data sensitivity is PUBLIC and operation is READ or EXECUTE (summarize)",
             "ALLOW"),
            ("POL-GEN-002", "Write to Authorized Resources", "access_control",
             "Allow write operations to resources the agent owns or is authorized to modify.",
             1, "medium",
             "Operation is WRITE and agent has write authorization for the target",
             "ALLOW"),
        ]

        await db.executemany(
            """INSERT INTO policies (id, name, category, description, active, severity, conditions, action_on_match)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            policies,
        )
        await db.commit()
    finally:
        await db.close()


async def seed_demo_data():
    """Insert realistic demo data so the dashboard isn't empty on first load."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM audit_logs")
        row = await cursor.fetchone()
        if row["cnt"] > 0:
            return

        now = datetime.now(timezone.utc)
        demo_events = [
            {
                "agent_id": "agent-analytics-01",
                "agent_name": "Analytics Bot",
                "action_name": "Read Q3 Revenue Report",
                "target_resource": "/reports/q3-revenue-2026.pdf",
                "operation": "read",
                "data_sensitivity": "internal",
                "decision": "ALLOW",
                "risk_score": 12,
                "reason": "Agent is authorized to read internal reports. No policy violation detected.",
                "policy_name": "Authorized Resource Access",
                "execution_status": "EXECUTED",
            },
            {
                "agent_id": "agent-hr-02",
                "agent_name": "HR Assistant",
                "action_name": "Access Employee Salary Records",
                "target_resource": "/hr/salaries/2026-all.xlsx",
                "operation": "read",
                "data_sensitivity": "restricted",
                "decision": "BLOCK",
                "risk_score": 92,
                "reason": "HR Assistant lacks authorization for restricted salary data. Access denied by policy POL-AC-002.",
                "policy_name": "Unauthorized Resource Block",
                "execution_status": "BLOCKED",
            },
            {
                "agent_id": "agent-comms-03",
                "agent_name": "Communications Bot",
                "action_name": "Send Press Release Draft",
                "target_resource": "/comms/press-release-draft.docx",
                "operation": "send",
                "data_sensitivity": "internal",
                "decision": "ALLOW",
                "risk_score": 25,
                "reason": "Internal document sent to authorized internal channel. Permitted by policy.",
                "policy_name": "Internal Data Sharing",
                "execution_status": "EXECUTED",
            },
            {
                "agent_id": "agent-devops-04",
                "agent_name": "DevOps Agent",
                "action_name": "Delete Staging Environment Logs",
                "target_resource": "/logs/staging/2026-09/",
                "operation": "delete",
                "data_sensitivity": "internal",
                "decision": "REQUIRE_APPROVAL",
                "risk_score": 65,
                "reason": "Destructive operation on shared infrastructure resource. Requires human approval per policy POL-DA-001.",
                "policy_name": "Destructive Action Approval",
                "approval_status": "APPROVED",
                "execution_status": "EXECUTED",
            },
            {
                "agent_id": "agent-sales-05",
                "agent_name": "Sales Copilot",
                "action_name": "Export Client List to External CRM",
                "target_resource": "/sales/client-list-2026.csv",
                "operation": "send",
                "data_sensitivity": "confidential",
                "decision": "BLOCK",
                "risk_score": 95,
                "reason": "Attempted transfer of confidential client data to external system. Blocked by data privacy policy POL-DP-001.",
                "policy_name": "Confidential Data Transfer Block",
                "execution_status": "BLOCKED",
            },
            {
                "agent_id": "agent-research-06",
                "agent_name": "Research Assistant",
                "action_name": "Summarize Public Whitepaper",
                "target_resource": "/public/whitepapers/ai-safety-2026.pdf",
                "operation": "read",
                "data_sensitivity": "public",
                "decision": "ALLOW",
                "risk_score": 5,
                "reason": "Public document. No restrictions apply.",
                "policy_name": "Public Document Access",
                "execution_status": "EXECUTED",
            },
            {
                "agent_id": "agent-finance-07",
                "agent_name": "Finance Bot",
                "action_name": "Modify Q2 Financial Projections",
                "target_resource": "/finance/projections-q2-2026.xlsx",
                "operation": "modify",
                "data_sensitivity": "confidential",
                "decision": "REQUIRE_APPROVAL",
                "risk_score": 78,
                "reason": "Modification of critical financial record. Human approval required per POL-DA-002.",
                "policy_name": "Critical Record Modification",
                "approval_status": "PENDING",
                "execution_status": "PENDING_APPROVAL",
            },
        ]

        previous_hash = ""
        for i, evt in enumerate(demo_events):
            ts = now.isoformat()
            record_data = f"{ts}|{evt['agent_id']}|{evt['action_name']}|{evt['decision']}"
            record_hash = _compute_hash(record_data, previous_hash)

            # Insert action
            cursor = await db.execute(
                """INSERT INTO actions
                   (timestamp, agent_id, agent_name, action_name, target_resource, operation,
                    data_sensitivity, decision, risk_score, reason, policy_name, execution_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, evt["agent_id"], evt["agent_name"], evt["action_name"],
                 evt["target_resource"], evt["operation"], evt["data_sensitivity"],
                 evt["decision"], evt["risk_score"], evt["reason"], evt["policy_name"],
                 evt["execution_status"]),
            )
            action_id = cursor.lastrowid

            # Insert audit log
            await db.execute(
                """INSERT INTO audit_logs
                   (timestamp, agent_id, agent_name, action_name, target_resource, operation,
                    data_sensitivity, decision, risk_score, reason, policy_name,
                    approval_status, execution_status, record_hash, previous_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, evt["agent_id"], evt["agent_name"], evt["action_name"],
                 evt["target_resource"], evt["operation"], evt["data_sensitivity"],
                 evt["decision"], evt["risk_score"], evt["reason"], evt["policy_name"],
                 evt.get("approval_status"), evt["execution_status"],
                 record_hash, previous_hash if previous_hash else None),
            )

            # Insert approval if needed
            if evt["decision"] == "REQUIRE_APPROVAL":
                await db.execute(
                    """INSERT INTO approvals
                       (action_id, agent_id, agent_name, action_name, target_resource,
                        operation, risk_score, reason, status, created_at,
                        reviewed_by, reviewed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (action_id, evt["agent_id"], evt["agent_name"], evt["action_name"],
                     evt["target_resource"], evt["operation"], evt["risk_score"],
                     evt["reason"], evt.get("approval_status", "PENDING"), ts,
                     "Security Admin" if evt.get("approval_status") == "APPROVED" else None,
                     ts if evt.get("approval_status") == "APPROVED" else None),
                )

            previous_hash = record_hash

        await db.commit()
    finally:
        await db.close()


# ── CRUD Operations ───────────────────────────────────────────────────

async def insert_action(data: dict) -> int:
    """Insert a new action record and return its ID."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO actions
               (timestamp, agent_id, agent_name, action_name, target_resource, operation,
                data_sensitivity, destination, context, decision, risk_score, reason,
                policy_name, execution_status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data["timestamp"], data["agent_id"], data["agent_name"],
             data["action_name"], data["target_resource"], data["operation"],
             data["data_sensitivity"], data.get("destination"),
             json.dumps(data.get("context")) if data.get("context") else None,
             data["decision"], data["risk_score"], data["reason"],
             data["policy_name"], data["execution_status"]),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def insert_approval(data: dict) -> int:
    """Insert a new approval request."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO approvals
               (action_id, agent_id, agent_name, action_name, target_resource,
                operation, risk_score, reason, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data["action_id"], data["agent_id"], data["agent_name"],
             data["action_name"], data["target_resource"], data["operation"],
             data["risk_score"], data["reason"], "PENDING", data["created_at"]),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def insert_audit_log(data: dict) -> int:
    """Insert an audit log entry with hash-linked integrity."""
    db = await get_db()
    try:
        # Get previous hash for chain
        cursor = await db.execute(
            "SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        )
        prev = await cursor.fetchone()
        previous_hash = prev["record_hash"] if prev else ""

        record_data = (
            f"{data['timestamp']}|{data['agent_id']}|"
            f"{data['action_name']}|{data['decision']}"
        )
        record_hash = _compute_hash(record_data, previous_hash)

        cursor = await db.execute(
            """INSERT INTO audit_logs
               (timestamp, agent_id, agent_name, action_name, target_resource, operation,
                data_sensitivity, decision, risk_score, reason, policy_name,
                approval_status, execution_status, record_hash, previous_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data["timestamp"], data["agent_id"], data["agent_name"],
             data["action_name"], data["target_resource"], data["operation"],
             data["data_sensitivity"], data["decision"], data["risk_score"],
             data["reason"], data["policy_name"], data.get("approval_status"),
             data["execution_status"], record_hash,
             previous_hash if previous_hash else None),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def get_approval_by_id(approval_id: int) -> Optional[dict]:
    """Get a single approval request by ID."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def update_approval(approval_id: int, status: str, reviewer: str,
                          comment: Optional[str] = None):
    """Update an approval's status (APPROVED or REJECTED)."""
    db = await get_db()
    try:
        reviewed_at = datetime.now(timezone.utc).isoformat()
        await db.execute(
            """UPDATE approvals SET status = ?, reviewed_by = ?, reviewed_at = ?,
               review_comment = ? WHERE id = ?""",
            (status, reviewer, reviewed_at, comment, approval_id),
        )

        # Also update the action's execution status
        cursor = await db.execute(
            "SELECT action_id FROM approvals WHERE id = ?", (approval_id,)
        )
        row = await cursor.fetchone()
        if row:
            action_id = row["action_id"]
            exec_status = "EXECUTED" if status == "APPROVED" else "REJECTED"
            await db.execute(
                "UPDATE actions SET execution_status = ? WHERE id = ?",
                (exec_status, action_id),
            )

            # Update corresponding audit log
            await db.execute(
                """UPDATE audit_logs SET approval_status = ?, execution_status = ?
                   WHERE action_name = (SELECT action_name FROM actions WHERE id = ?)
                   AND decision = 'REQUIRE_APPROVAL'
                   AND (approval_status = 'PENDING' OR approval_status IS NULL)""",
                (status, exec_status, action_id),
            )

        await db.commit()
    finally:
        await db.close()


async def get_all_approvals() -> List[dict]:
    """Get all approval requests, newest first."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM approvals ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_all_actions() -> List[dict]:
    """Get all actions, newest first."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM actions ORDER BY timestamp DESC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_audit_logs(
    decision: Optional[str] = None,
    agent_id: Optional[str] = None,
    search: Optional[str] = None,
) -> List[dict]:
    """Get audit logs with optional filtering."""
    db = await get_db()
    try:
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []

        if decision:
            query += " AND decision = ?"
            params.append(decision)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if search:
            query += " AND (action_name LIKE ? OR target_resource LIKE ? OR agent_name LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        query += " ORDER BY timestamp DESC"
        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_dashboard_stats() -> dict:
    """Compute dashboard statistics from the database."""
    db = await get_db()
    try:
        # Total actions
        c = await db.execute("SELECT COUNT(*) as cnt FROM actions")
        total = (await c.fetchone())["cnt"]

        # By decision
        c = await db.execute("SELECT COUNT(*) as cnt FROM actions WHERE decision = 'ALLOW'")
        allowed = (await c.fetchone())["cnt"]

        c = await db.execute("SELECT COUNT(*) as cnt FROM actions WHERE decision = 'BLOCK'")
        blocked = (await c.fetchone())["cnt"]

        c = await db.execute(
            "SELECT COUNT(*) as cnt FROM approvals WHERE status = 'PENDING'"
        )
        pending = (await c.fetchone())["cnt"]

        c = await db.execute(
            "SELECT COUNT(*) as cnt FROM approvals WHERE status = 'APPROVED'"
        )
        approved = (await c.fetchone())["cnt"]

        c = await db.execute(
            "SELECT COUNT(*) as cnt FROM approvals WHERE status = 'REJECTED'"
        )
        rejected = (await c.fetchone())["cnt"]

        # Average risk score
        c = await db.execute("SELECT AVG(risk_score) as avg_rs FROM actions")
        avg_row = await c.fetchone()
        avg_risk = round(avg_row["avg_rs"], 1) if avg_row["avg_rs"] else 0.0

        # Risk distribution
        risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        c = await db.execute("SELECT risk_score FROM actions")
        rows = await c.fetchall()
        for r in rows:
            score = r["risk_score"]
            if score <= 25:
                risk_dist["low"] += 1
            elif score <= 50:
                risk_dist["medium"] += 1
            elif score <= 75:
                risk_dist["high"] += 1
            else:
                risk_dist["critical"] += 1

        # Recent activity
        c = await db.execute(
            "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10"
        )
        recent = [dict(r) for r in await c.fetchall()]

        # Security status
        if blocked > 0 and pending == 0:
            status = "PROTECTED"
        elif pending > 0:
            status = "ATTENTION_NEEDED"
        elif total == 0:
            status = "NO_DATA"
        else:
            status = "OPERATIONAL"

        return {
            "total_actions": total,
            "allowed_actions": allowed,
            "blocked_actions": blocked,
            "pending_approvals": pending,
            "approved_actions": approved,
            "rejected_actions": rejected,
            "avg_risk_score": avg_risk,
            "risk_distribution": risk_dist,
            "recent_activity": recent,
            "security_status": status,
        }
    finally:
        await db.close()


async def get_all_policies() -> List[dict]:
    """Get all security policies."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM policies ORDER BY category, id")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def toggle_policy(policy_id: str, active: bool):
    """Enable or disable a policy."""
    db = await get_db()
    try:
        await db.execute(
            "UPDATE policies SET active = ? WHERE id = ?",
            (1 if active else 0, policy_id),
        )
        await db.commit()
    finally:
        await db.close()


async def verify_audit_integrity() -> dict:
    """Verify the hash chain of audit logs."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        rows = await cursor.fetchall()
        total = len(rows)

        if total == 0:
            return {
                "total_records": 0,
                "verified_records": 0,
                "broken_links": 0,
                "integrity_status": "NO_DATA",
                "details": "No audit records to verify.",
            }

        verified = 0
        broken = 0
        previous_hash = ""

        for row in rows:
            row = dict(row)
            record_data = (
                f"{row['timestamp']}|{row['agent_id']}|"
                f"{row['action_name']}|{row['decision']}"
            )
            expected_hash = _compute_hash(record_data, previous_hash)

            if row["record_hash"] == expected_hash:
                verified += 1
            else:
                broken += 1

            previous_hash = row["record_hash"] or ""

        status = "INTACT" if broken == 0 else "COMPROMISED"
        details = (
            f"Verified {verified}/{total} records. "
            f"{'All hash links are valid.' if broken == 0 else f'{broken} broken link(s) detected.'} "
            f"Note: Hash linking provides tamper evidence but cannot prevent a determined attacker "
            f"from recomputing the entire chain."
        )

        return {
            "total_records": total,
            "verified_records": verified,
            "broken_links": broken,
            "integrity_status": status,
            "details": details,
        }
    finally:
        await db.close()
