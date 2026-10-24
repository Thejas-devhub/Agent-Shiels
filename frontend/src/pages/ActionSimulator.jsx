import { useState } from 'react';
import { api } from '../services/api';

const SCENARIOS = [
  {
    id: 1,
    title: 'Read Authorized Project Report',
    action_name: 'Read Q3 Project Report',
    agent_id: 'agent-analytics-01',
    agent_name: 'Analytics Bot',
    target_resource: '/reports/q3-project-status.pdf',
    operation: 'read',
    data_sensitivity: 'internal',
    description: 'An analytics agent requests read access to an internal project report it is authorized to access.',
  },
  {
    id: 2,
    title: 'Send Confidential Data to External Email',
    action_name: 'Send Confidential Report Externally',
    agent_id: 'agent-sales-05',
    agent_name: 'Sales Copilot',
    target_resource: '/sales/client-contracts-2026.pdf',
    operation: 'send',
    data_sensitivity: 'confidential',
    destination: 'partner@external.com',
    description: 'A sales agent attempts to send confidential client contracts to an unauthorized external email address.',
  },
  {
    id: 3,
    title: 'Delete Shared Company Folder',
    action_name: 'Delete Shared Team Archive',
    agent_id: 'agent-devops-04',
    agent_name: 'DevOps Agent',
    target_resource: '/logs/shared-archive/2026/',
    operation: 'delete',
    data_sensitivity: 'internal',
    description: 'A DevOps agent requests deletion of a shared team archive folder.',
  },
  {
    id: 4,
    title: 'Access Restricted Database Record',
    action_name: 'Access Employee Salary Records',
    agent_id: 'agent-hr-02',
    agent_name: 'HR Assistant',
    target_resource: '/hr/salaries/employee-compensation.xlsx',
    operation: 'read',
    data_sensitivity: 'restricted',
    description: 'An HR assistant agent attempts to access restricted salary records it does not have authorization for.',
  },
  {
    id: 5,
    title: 'Summarize a Public Document',
    action_name: 'Summarize Public AI Safety Whitepaper',
    agent_id: 'agent-research-06',
    agent_name: 'Research Assistant',
    target_resource: '/public/whitepapers/ai-safety-2026.pdf',
    operation: 'read',
    data_sensitivity: 'public',
    description: 'A research agent requests access to read and summarize a publicly available whitepaper.',
  },
  {
    id: 6,
    title: 'Modify Important Business Record',
    action_name: 'Modify Revenue Projections',
    agent_id: 'agent-finance-07',
    agent_name: 'Finance Bot',
    target_resource: '/finance/reports/revenue-projections-q2.xlsx',
    operation: 'modify',
    data_sensitivity: 'confidential',
    description: 'A finance agent requests to modify critical revenue projection records.',
  },
];

const sensitivityColors = {
  public: 'badge-info',
  internal: 'badge-approval',
  confidential: 'badge-block',
  restricted: 'badge-block',
};

export default function ActionSimulator() {
  const [selected, setSelected] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function evaluateAction() {
    if (!selected) return;
    try {
      setLoading(true);
      setError(null);
      setResult(null);
      const payload = {
        action_name: selected.action_name,
        agent_id: selected.agent_id,
        agent_name: selected.agent_name,
        target_resource: selected.target_resource,
        operation: selected.operation,
        data_sensitivity: selected.data_sensitivity,
      };
      if (selected.destination) {
        payload.destination = selected.destination;
      }
      const data = await api.evaluateAction(payload);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const decisionClass =
    result?.decision === 'ALLOW' ? 'allow' :
    result?.decision === 'BLOCK' ? 'block' : 'approval';

  const decisionIcon =
    result?.decision === 'ALLOW' ? '\u2714' :
    result?.decision === 'BLOCK' ? '\u2718' : '\u23F3';

  const decisionLabel =
    result?.decision === 'ALLOW' ? 'ACTION ALLOWED' :
    result?.decision === 'BLOCK' ? 'ACTION BLOCKED' : 'APPROVAL REQUIRED';

  return (
    <div className="page">
      <div className="page-header">
        <h2>Action Simulator</h2>
        <p>Select an AI agent action scenario and evaluate it against the security policy engine</p>
      </div>

      {error && (
        <div className="error-banner">
          <span>&#x26A0;</span>
          <span>{error}</span>
        </div>
      )}

      {/* Scenario Cards */}
      <div className="scenario-grid">
        {SCENARIOS.map((s) => (
          <div
            key={s.id}
            className={`scenario-card ${selected?.id === s.id ? 'selected' : ''}`}
            onClick={() => { setSelected(s); setResult(null); }}
          >
            <div className="scenario-number">#{s.id}</div>
            <div className="scenario-title">{s.title}</div>
            <div className="scenario-meta">
              <div className="scenario-meta-item">
                <span>Agent:</span>
                <span>{s.agent_name}</span>
              </div>
              <div className="scenario-meta-item">
                <span>Operation:</span>
                <span style={{ textTransform: 'uppercase', fontWeight: 600 }}>{s.operation}</span>
              </div>
              <div className="scenario-meta-item">
                <span>Sensitivity:</span>
                <span className={`badge ${sensitivityColors[s.data_sensitivity]}`}>
                  {s.data_sensitivity}
                </span>
              </div>
              <div className="scenario-meta-item">
                <span>Resource:</span>
                <span className="text-mono" style={{ fontSize: 11 }}>{s.target_resource}</span>
              </div>
              {s.destination && (
                <div className="scenario-meta-item">
                  <span>Send to:</span>
                  <span className="text-block" style={{ fontWeight: 600 }}>{s.destination}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Selected Action Details & Evaluate Button */}
      {selected && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-header">
            <h3 className="card-title">Selected Action: {selected.title}</h3>
          </div>
          <p className="text-secondary mb-2" style={{ fontSize: 13 }}>{selected.description}</p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
            <div>
              <div className="form-label">Agent ID</div>
              <div className="text-mono">{selected.agent_id}</div>
            </div>
            <div>
              <div className="form-label">Operation</div>
              <div style={{ textTransform: 'uppercase', fontWeight: 600 }}>{selected.operation}</div>
            </div>
            <div>
              <div className="form-label">Data Sensitivity</div>
              <span className={`badge ${sensitivityColors[selected.data_sensitivity]}`}>
                {selected.data_sensitivity}
              </span>
            </div>
          </div>
          <button
            className="btn btn-primary"
            onClick={evaluateAction}
            disabled={loading}
          >
            {loading ? (
              <>
                <div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }}></div>
                Evaluating...
              </>
            ) : (
              <>Evaluate Action</>
            )}
          </button>
        </div>
      )}

      {/* Decision Result */}
      {result && (
        <div className={`decision-panel ${decisionClass}`}>
          <div className="decision-header">
            <span className="decision-icon">{decisionIcon}</span>
            <span className="decision-title">{decisionLabel}</span>
            <span className="badge badge-info" style={{ marginLeft: 'auto' }}>
              {result.evaluation_time_ms}ms
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="decision-detail">
              <div className="decision-detail-label">Reason</div>
              <div className="decision-detail-value">{result.reason}</div>
            </div>
            <div className="decision-detail">
              <div className="decision-detail-label">Matched Policy</div>
              <div className="decision-detail-value">{result.policy_name}</div>
            </div>
            <div className="decision-detail">
              <div className="decision-detail-label">Risk Score</div>
              <div className="risk-meter">
                <div className="risk-bar" style={{ maxWidth: 200 }}>
                  <div
                    className={`risk-fill ${
                      result.risk_score <= 25 ? 'low' :
                      result.risk_score <= 50 ? 'medium' :
                      result.risk_score <= 75 ? 'high' : 'critical'
                    }`}
                    style={{ width: `${result.risk_score}%` }}
                  />
                </div>
                <span className="risk-value" style={{ fontSize: 18 }}>{result.risk_score}/100</span>
              </div>
            </div>
            <div className="decision-detail">
              <div className="decision-detail-label">Next Step</div>
              <div className="decision-detail-value">{result.next_step}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
