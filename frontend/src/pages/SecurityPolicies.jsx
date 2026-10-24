import { useState, useEffect } from 'react';
import { api } from '../services/api';

const CATEGORY_LABELS = {
  access_control: 'Access Control',
  data_privacy: 'Data Privacy',
  external_transfers: 'External Data Transfers',
  destructive_actions: 'Destructive Actions',
  human_approval: 'Human Approval Requirements',
};

const SEVERITY_STYLES = {
  low: 'badge-allow',
  medium: 'badge-info',
  high: 'badge-approval',
  critical: 'badge-block',
};

export default function SecurityPolicies() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toggling, setToggling] = useState(null);

  useEffect(() => {
    loadPolicies();
  }, []);

  async function loadPolicies() {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getPolicies();
      setPolicies(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleToggle(policyId, currentActive) {
    try {
      setToggling(policyId);
      await api.togglePolicy(policyId, !currentActive);
      setPolicies(prev =>
        prev.map(p => p.id === policyId ? { ...p, active: !currentActive ? 1 : 0 } : p)
      );
    } catch (err) {
      setError(err.message);
    } finally {
      setToggling(null);
    }
  }

  // Group by category
  const grouped = policies.reduce((acc, p) => {
    const cat = p.category;
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(p);
    return acc;
  }, {});

  if (loading) {
    return (
      <div className="page">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <span>Loading security policies...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Security Policies</h2>
        <p>View and configure the rules governing AI agent behavior within your organization</p>
      </div>

      {error && (
        <div className="error-banner">
          <span>&#x26A0;</span>
          <span>{error}</span>
        </div>
      )}

      {Object.entries(grouped).map(([category, catPolicies]) => (
        <div key={category} style={{ marginBottom: 32 }}>
          <h3 style={{
            fontSize: 15,
            fontWeight: 600,
            marginBottom: 14,
            color: 'var(--accent-primary-hover)',
            textTransform: 'uppercase',
            letterSpacing: 1,
          }}>
            {CATEGORY_LABELS[category] || category}
          </h3>

          <div className="policy-grid">
            {catPolicies.map(policy => (
              <div key={policy.id} className="policy-card">
                <div className="policy-card-header">
                  <div>
                    <h3>{policy.name}</h3>
                    <span className="text-mono text-muted" style={{ fontSize: 11 }}>
                      {policy.id}
                    </span>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={!!policy.active}
                      onChange={() => handleToggle(policy.id, policy.active)}
                      disabled={toggling === policy.id}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <p>{policy.description}</p>

                <div style={{ marginBottom: 12 }}>
                  <div className="form-label" style={{ marginBottom: 4 }}>Conditions</div>
                  <div style={{
                    fontSize: 12,
                    color: 'var(--text-secondary)',
                    background: 'var(--bg-input)',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: 1.5,
                  }}>
                    {policy.conditions}
                  </div>
                </div>

                <div className="policy-meta">
                  <span className={`policy-tag ${SEVERITY_STYLES[policy.severity]}`}>
                    {policy.severity}
                  </span>
                  <span className="policy-tag category">
                    {CATEGORY_LABELS[policy.category] || policy.category}
                  </span>
                  <span className={`policy-tag ${
                    policy.action_on_match === 'ALLOW' ? 'badge-allow' :
                    policy.action_on_match === 'BLOCK' ? 'badge-block' :
                    'badge-approval'
                  }`}>
                    {policy.action_on_match}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
