import { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function ApprovalCenter() {
  const [approvals, setApprovals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(null);
  const [feedback, setFeedback] = useState(null);

  useEffect(() => {
    loadApprovals();
  }, []);

  async function loadApprovals() {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getApprovals();
      setApprovals(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleDecision(id, action) {
    try {
      setActionLoading(id);
      setFeedback(null);
      if (action === 'approve') {
        await api.approveAction(id, { reviewer: 'Security Admin', comment: 'Approved during review' });
        setFeedback({ type: 'allow', msg: `Request #${id} approved. Simulated execution completed.` });
      } else {
        await api.rejectAction(id, { reviewer: 'Security Admin', comment: 'Rejected during review' });
        setFeedback({ type: 'block', msg: `Request #${id} rejected. Operation was NOT executed.` });
      }
      await loadApprovals();
    } catch (err) {
      setFeedback({ type: 'error', msg: err.message });
    } finally {
      setActionLoading(null);
    }
  }

  const pending = approvals.filter(a => a.status === 'PENDING');
  const resolved = approvals.filter(a => a.status !== 'PENDING');

  if (loading) {
    return (
      <div className="page">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <span>Loading approval queue...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Approval Center</h2>
        <p>Review and authorize high-risk AI agent actions requiring human approval</p>
      </div>

      {error && (
        <div className="error-banner">
          <span>&#x26A0;</span>
          <span>{error}</span>
        </div>
      )}

      {feedback && (
        <div className={`error-banner`} style={{
          background: feedback.type === 'allow' ? 'var(--color-allow-bg)' : feedback.type === 'error' ? 'var(--color-block-bg)' : 'var(--color-block-bg)',
          borderColor: feedback.type === 'allow' ? 'var(--color-allow-border)' : 'var(--color-block-border)',
          color: feedback.type === 'allow' ? 'var(--color-allow)' : 'var(--color-block)',
        }}>
          <span>{feedback.type === 'allow' ? '\u2714' : feedback.type === 'error' ? '\u26A0' : '\u2718'}</span>
          <span>{feedback.msg}</span>
        </div>
      )}

      {/* Pending Approvals */}
      <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: 'var(--color-approval)' }}>
        Pending Approvals ({pending.length})
      </h3>

      {pending.length === 0 ? (
        <div className="empty-state" style={{ padding: 40 }}>
          <div className="empty-state-icon">&#x2714;</div>
          <h3>No Pending Approvals</h3>
          <p>All approval requests have been resolved. Use the Action Simulator to trigger new approval scenarios.</p>
        </div>
      ) : (
        pending.map(item => (
          <div key={item.id} className="approval-card pending">
            <div className="approval-card-header">
              <div>
                <h3>{item.action_name}</h3>
                <span className="text-muted" style={{ fontSize: 12 }}>
                  Request #{item.id} &middot; Action #{item.action_id}
                </span>
              </div>
              <span className="badge badge-pending">PENDING</span>
            </div>

            <div className="approval-info-grid">
              <div className="approval-info-item">
                <div className="label">Requesting Agent</div>
                <div className="value">{item.agent_name} ({item.agent_id})</div>
              </div>
              <div className="approval-info-item">
                <div className="label">Target Resource</div>
                <div className="value text-mono" style={{ fontSize: 12 }}>{item.target_resource}</div>
              </div>
              <div className="approval-info-item">
                <div className="label">Operation</div>
                <div className="value" style={{ textTransform: 'uppercase', fontWeight: 600 }}>{item.operation}</div>
              </div>
              <div className="approval-info-item">
                <div className="label">Risk Score</div>
                <div className="value">
                  <div className="risk-meter">
                    <div className="risk-bar">
                      <div
                        className={`risk-fill ${
                          item.risk_score <= 25 ? 'low' :
                          item.risk_score <= 50 ? 'medium' :
                          item.risk_score <= 75 ? 'high' : 'critical'
                        }`}
                        style={{ width: `${item.risk_score}%` }}
                      />
                    </div>
                    <span className="risk-value">{item.risk_score}</span>
                  </div>
                </div>
              </div>
              <div className="approval-info-item" style={{ gridColumn: '1 / -1' }}>
                <div className="label">Reason for Approval</div>
                <div className="value">{item.reason}</div>
              </div>
              <div className="approval-info-item">
                <div className="label">Request Time</div>
                <div className="value text-mono" style={{ fontSize: 12 }}>
                  {new Date(item.created_at).toLocaleString()}
                </div>
              </div>
            </div>

            <div className="approval-actions">
              <button
                className="btn btn-allow btn-sm"
                onClick={() => handleDecision(item.id, 'approve')}
                disabled={actionLoading === item.id}
              >
                {actionLoading === item.id ? 'Processing...' : 'Approve'}
              </button>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => handleDecision(item.id, 'reject')}
                disabled={actionLoading === item.id}
              >
                {actionLoading === item.id ? 'Processing...' : 'Reject'}
              </button>
            </div>
          </div>
        ))
      )}

      {/* Resolved */}
      {resolved.length > 0 && (
        <>
          <h3 style={{ fontSize: 16, fontWeight: 600, marginTop: 32, marginBottom: 16, color: 'var(--text-secondary)' }}>
            Resolved Requests ({resolved.length})
          </h3>
          {resolved.map(item => (
            <div key={item.id} className={`approval-card ${item.status.toLowerCase()}`}>
              <div className="approval-card-header">
                <div>
                  <h3>{item.action_name}</h3>
                  <span className="text-muted" style={{ fontSize: 12 }}>
                    Request #{item.id} &middot; Reviewed by {item.reviewed_by || 'N/A'}
                  </span>
                </div>
                <span className={`badge badge-${item.status.toLowerCase()}`}>
                  {item.status}
                </span>
              </div>
              <div className="approval-info-grid">
                <div className="approval-info-item">
                  <div className="label">Agent</div>
                  <div className="value">{item.agent_name}</div>
                </div>
                <div className="approval-info-item">
                  <div className="label">Resource</div>
                  <div className="value text-mono" style={{ fontSize: 12 }}>{item.target_resource}</div>
                </div>
                <div className="approval-info-item">
                  <div className="label">Risk Score</div>
                  <div className="value">{item.risk_score}</div>
                </div>
                <div className="approval-info-item">
                  <div className="label">Reviewed At</div>
                  <div className="value text-mono" style={{ fontSize: 12 }}>
                    {item.reviewed_at ? new Date(item.reviewed_at).toLocaleString() : 'N/A'}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </>
      )}
    </div>
  );
}
