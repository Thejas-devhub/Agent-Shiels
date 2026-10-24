import { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [integrity, setIntegrity] = useState(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({ decision: '', search: '' });
  const [selectedLog, setSelectedLog] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      setLoading(true);
      setError(null);
      const [logsData, integrityData] = await Promise.all([
        api.getAuditLogs(filters),
        api.getAuditIntegrity(),
      ]);
      setLogs(logsData);
      setIntegrity(integrityData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyIntegrity() {
    try {
      setVerifying(true);
      const integrityData = await api.getAuditIntegrity();
      setIntegrity(integrityData);
    } catch (err) {
      setError(err.message);
    } finally {
      setVerifying(false);
    }
  }

  async function applyFilters() {
    try {
      setLoading(true);
      const data = await api.getAuditLogs(filters);
      setLogs(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function handleFilterChange(key, value) {
    const newFilters = { ...filters, [key]: value };
    setFilters(newFilters);
  }

  useEffect(() => {
    if (!loading) {
      const timer = setTimeout(applyFilters, 300);
      return () => clearTimeout(timer);
    }
  }, [filters.decision, filters.search]);

  function exportJSON() {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agentshield-audit-logs-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportCSV() {
    if (logs.length === 0) return;
    const headers = ['ID', 'Timestamp', 'Agent', 'Action', 'Resource', 'Operation', 'Sensitivity', 'Decision', 'Risk Score', 'Policy', 'Status', 'Record Hash', 'Previous Hash'];
    const rows = logs.map(l => [
      l.id,
      `"${l.timestamp}"`,
      `"${l.agent_name || l.agent_id}"`,
      `"${l.action_name}"`,
      `"${l.target_resource}"`,
      `"${l.operation}"`,
      `"${l.data_sensitivity}"`,
      `"${l.decision}"`,
      l.risk_score,
      `"${(l.policy_name || '').replace(/"/g, '""')}"`,
      `"${l.execution_status}"`,
      `"${l.record_hash || ''}"`,
      `"${l.previous_hash || ''}"`
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agentshield-audit-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading && logs.length === 0) {
    return (
      <div className="page">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <span>Loading audit logs...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h2>Audit Logs</h2>
          <p>Cryptographically linked SHA-256 tamper-evident record of all AI agent operations</p>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-outline btn-sm" onClick={exportCSV} title="Export as CSV">
            <span>&#x1F4E5;</span> Export CSV
          </button>
          <button className="btn btn-outline btn-sm" onClick={exportJSON} title="Export as JSON">
            <span>&#x1F4CB;</span> Export JSON
          </button>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleVerifyIntegrity}
            disabled={verifying}
          >
            {verifying ? 'Verifying...' : '⚡ Verify Chain'}
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <span>&#x26A0;</span>
          <span>{error}</span>
        </div>
      )}

      {/* Integrity Status */}
      {integrity && (
        <div className={`integrity-panel ${integrity.integrity_status === 'INTACT' ? 'intact' : 'compromised'}`}>
          <div className="flex items-center gap-3" style={{ marginBottom: 8 }}>
            <span style={{ fontSize: 20 }}>
              {integrity.integrity_status === 'INTACT' ? '\u2714' : '\u26A0'}
            </span>
            <strong style={{ fontSize: 15 }}>
              Cryptographic Audit Chain: {integrity.integrity_status}
            </strong>
            <span className="badge badge-allow" style={{ fontSize: 11, marginLeft: 'auto' }}>
              {integrity.verified_records} / {integrity.total_records} Verified
            </span>
          </div>
          <p style={{ fontSize: 13, opacity: 0.9 }}>{integrity.details}</p>
        </div>
      )}

      {/* Filters */}
      <div className="filter-bar">
        <div className="search-bar">
          <span className="search-icon">&#x1F50D;</span>
          <input
            type="text"
            className="form-input"
            placeholder="Search actions, resources, agents..."
            value={filters.search}
            onChange={e => handleFilterChange('search', e.target.value)}
            style={{ paddingLeft: 38 }}
          />
        </div>
        <select
          className="form-select"
          value={filters.decision}
          onChange={e => handleFilterChange('decision', e.target.value)}
          style={{ width: 180 }}
        >
          <option value="">All Decisions</option>
          <option value="ALLOW">Allowed</option>
          <option value="BLOCK">Blocked</option>
          <option value="REQUIRE_APPROVAL">Require Approval</option>
        </select>
        <span className="text-muted" style={{ fontSize: 12, marginLeft: 'auto' }}>
          Showing {logs.length} records • Click any row for cryptographic proof
        </span>
      </div>

      {/* Logs Table */}
      <div className="card">
        {logs.length === 0 ? (
          <div className="empty-state">
            <h3>No Audit Records Found</h3>
            <p>No records match your current filters. Try adjusting your search or use the Action Simulator to create events.</p>
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Agent</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Operation</th>
                  <th>Decision</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>Proof</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    style={{ cursor: 'pointer', transition: 'background var(--transition-fast)' }}
                    className={selectedLog?.id === log.id ? 'active-row' : ''}
                  >
                    <td className="cell-mono">#{log.id}</td>
                    <td className="cell-mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td style={{ fontSize: 12 }}>{log.agent_name || log.agent_id}</td>
                    <td className="cell-truncate">{log.action_name}</td>
                    <td className="cell-truncate cell-mono" style={{ fontSize: 11 }}>
                      {log.target_resource}
                    </td>
                    <td style={{ textTransform: 'uppercase', fontSize: 11, fontWeight: 600 }}>
                      {log.operation}
                    </td>
                    <td>
                      <span className={`badge badge-${
                        log.decision === 'ALLOW' ? 'allow' :
                        log.decision === 'BLOCK' ? 'block' : 'approval'
                      }`}>
                        {log.decision}
                      </span>
                    </td>
                    <td>
                      <span className={`risk-value ${
                        log.risk_score <= 25 ? 'text-allow' :
                        log.risk_score <= 50 ? 'text-approval' :
                        'text-block'
                      }`}>{log.risk_score}</span>
                    </td>
                    <td>
                      <span className={`badge ${
                        log.execution_status === 'EXECUTED' ? 'badge-allow' :
                        log.execution_status === 'BLOCKED' ? 'badge-block' :
                        log.execution_status === 'REJECTED' ? 'badge-rejected' :
                        'badge-pending'
                      }`} style={{ fontSize: 10 }}>
                        {log.execution_status}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-outline" style={{ fontSize: 10, fontFamily: 'var(--font-mono)' }}>
                        {log.record_hash ? `${log.record_hash.slice(0, 8)}...` : 'N/A'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected Log Cryptographic Proof Drawer / Modal */}
      {selectedLog && (
        <div className="card" style={{ marginTop: 24, border: '1px solid var(--color-border-hover)', background: 'var(--color-bg-card)' }}>
          <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ fontSize: 16 }}>Cryptographic Proof & Enforcement Details — #{selectedLog.id}</h3>
              <p style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                Immutable audit ledger entry verified by SHA-256 hash chaining
              </p>
            </div>
            <button className="btn btn-outline btn-sm" onClick={() => setSelectedLog(null)}>
              Close
            </button>
          </div>
          <div style={{ padding: 20, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            <div>
              <span className="form-label">Current SHA-256 Hash</span>
              <div style={{
                background: 'rgba(0,0,0,0.4)',
                padding: '8px 12px',
                borderRadius: 6,
                fontFamily: 'var(--font-mono)',
                fontSize: 12,
                color: 'var(--color-allow)',
                wordBreak: 'break-all'
              }}>
                {selectedLog.record_hash || 'Pending hash derivation'}
              </div>
            </div>
            <div>
              <span className="form-label">Parent SHA-256 Link (Previous Hash)</span>
              <div style={{
                background: 'rgba(0,0,0,0.4)',
                padding: '8px 12px',
                borderRadius: 6,
                fontFamily: 'var(--font-mono)',
                fontSize: 12,
                color: 'var(--color-text-muted)',
                wordBreak: 'break-all'
              }}>
                {selectedLog.previous_hash || 'Genesis Block (Initial Record)'}
              </div>
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <span className="form-label">Triggered Policy Rule & Reason</span>
              <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 6, fontSize: 13 }}>
                <strong style={{ color: 'var(--color-text-primary)' }}>{selectedLog.policy_name || 'Standard Access Evaluation'}</strong>:
                <span style={{ marginLeft: 8, color: 'var(--color-text-secondary)' }}>{selectedLog.reason}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
