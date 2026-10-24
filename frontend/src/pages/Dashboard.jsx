import { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadStats();
  }, []);

  async function loadStats() {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getStats();
      setStats(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="page">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <span>Loading dashboard...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page">
        <div className="error-banner">
          <span>&#x26A0;</span>
          <span>{error}</span>
        </div>
        <button className="btn btn-outline" onClick={loadStats}>Retry</button>
      </div>
    );
  }

  const securityClass =
    stats.security_status === 'PROTECTED' ? 'protected' :
    stats.security_status === 'ATTENTION_NEEDED' ? 'attention' : 'operational';

  const securityLabel =
    stats.security_status === 'PROTECTED' ? 'All Threats Blocked' :
    stats.security_status === 'ATTENTION_NEEDED' ? 'Pending Approvals Require Attention' :
    'System Operational';

  const securityIcon =
    stats.security_status === 'PROTECTED' ? '\u2714' :
    stats.security_status === 'ATTENTION_NEEDED' ? '\u26A0' : '\u2139';

  const maxRisk = Math.max(
    stats.risk_distribution.low || 0,
    stats.risk_distribution.medium || 0,
    stats.risk_distribution.high || 0,
    stats.risk_distribution.critical || 0,
    1
  );

  return (
    <div className="page">
      <div className="page-header">
        <h2>Security Dashboard</h2>
        <p>Real-time monitoring of AI agent actions and security decisions</p>
      </div>

      {/* Security Status */}
      <div className={`security-status ${securityClass}`} style={{ marginBottom: 24 }}>
        <span className="security-status-icon">{securityIcon}</span>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700 }}>
            {stats.security_status.replace('_', ' ')}
          </div>
          <div style={{ fontSize: 12, opacity: 0.8 }}>{securityLabel}</div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card info">
          <div className="stat-icon">#</div>
          <div className="stat-value">{stats.total_actions}</div>
          <div className="stat-label">Total Actions</div>
        </div>
        <div className="stat-card allow">
          <div className="stat-icon">&#x2714;</div>
          <div className="stat-value">{stats.allowed_actions}</div>
          <div className="stat-label">Allowed</div>
        </div>
        <div className="stat-card block">
          <div className="stat-icon">&#x2718;</div>
          <div className="stat-value">{stats.blocked_actions}</div>
          <div className="stat-label">Blocked</div>
        </div>
        <div className="stat-card approval">
          <div className="stat-icon">&#x23F3;</div>
          <div className="stat-value">{stats.pending_approvals}</div>
          <div className="stat-label">Pending Approvals</div>
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Recent Activity */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Activity</h3>
            <span className="text-muted" style={{ fontSize: 12 }}>
              Last {stats.recent_activity.length} events
            </span>
          </div>
          {stats.recent_activity.length === 0 ? (
            <div className="empty-state">
              <p>No activity recorded yet. Use the Action Simulator to generate events.</p>
            </div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Action</th>
                    <th>Decision</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_activity.map((evt, i) => (
                    <tr key={i}>
                      <td style={{ fontSize: 12 }}>{evt.agent_name}</td>
                      <td className="cell-truncate">{evt.action_name}</td>
                      <td>
                        <span className={`badge badge-${
                          evt.decision === 'ALLOW' ? 'allow' :
                          evt.decision === 'BLOCK' ? 'block' : 'approval'
                        }`}>
                          {evt.decision}
                        </span>
                      </td>
                      <td>
                        <div className="risk-meter">
                          <div className="risk-bar">
                            <div
                              className={`risk-fill ${
                                evt.risk_score <= 25 ? 'low' :
                                evt.risk_score <= 50 ? 'medium' :
                                evt.risk_score <= 75 ? 'high' : 'critical'
                              }`}
                              style={{ width: `${evt.risk_score}%` }}
                            />
                          </div>
                          <span className="risk-value">{evt.risk_score}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column */}
        <div>
          {/* Risk Distribution */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-header">
              <h3 className="card-title">Risk Distribution</h3>
            </div>
            <div className="risk-dist-bars">
              {['low', 'medium', 'high', 'critical'].map(level => {
                const count = stats.risk_distribution[level] || 0;
                const height = maxRisk > 0 ? (count / maxRisk) * 100 : 0;
                return (
                  <div className="risk-dist-bar" key={level}>
                    <div className="risk-dist-count">{count}</div>
                    <div
                      className={`risk-dist-fill ${level}`}
                      style={{ height: `${Math.max(height, 4)}%` }}
                    />
                    <div className="risk-dist-label">{level}</div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Stats */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Summary</h3>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="flex justify-between items-center">
                <span className="text-secondary" style={{ fontSize: 13 }}>Avg Risk Score</span>
                <span className="font-bold">{stats.avg_risk_score}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-secondary" style={{ fontSize: 13 }}>Approved Actions</span>
                <span className="font-bold text-allow">{stats.approved_actions}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-secondary" style={{ fontSize: 13 }}>Rejected Actions</span>
                <span className="font-bold text-block">{stats.rejected_actions}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-secondary" style={{ fontSize: 13 }}>Block Rate</span>
                <span className="font-bold">
                  {stats.total_actions > 0
                    ? Math.round((stats.blocked_actions / stats.total_actions) * 100)
                    : 0}%
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
