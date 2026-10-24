/**
 * AgentShield — API Service
 * All backend communication goes through here.
 */

const API_BASE = 'http://localhost:8000/api';

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  } catch (err) {
    if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
      throw new Error('Cannot connect to AgentShield API. Is the backend running on port 8000?');
    }
    throw err;
  }
}

export const api = {
  // Health
  health: () => request('/health'),

  // Dashboard
  getStats: () => request('/dashboard/stats'),

  // Actions
  evaluateAction: (action) =>
    request('/actions/evaluate', {
      method: 'POST',
      body: JSON.stringify(action),
    }),
  getActions: () => request('/actions'),

  // Approvals
  getApprovals: () => request('/approvals'),
  approveAction: (id, data = {}) =>
    request(`/approvals/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ reviewer: data.reviewer || 'Security Admin', comment: data.comment }),
    }),
  rejectAction: (id, data = {}) =>
    request(`/approvals/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reviewer: data.reviewer || 'Security Admin', comment: data.comment }),
    }),

  // Audit
  getAuditLogs: (params = {}) => {
    const qs = new URLSearchParams();
    if (params.decision) qs.set('decision', params.decision);
    if (params.agent_id) qs.set('agent_id', params.agent_id);
    if (params.search) qs.set('search', params.search);
    const suffix = qs.toString() ? `?${qs}` : '';
    return request(`/audit-logs${suffix}`);
  },
  getAuditIntegrity: () => request('/audit-logs/integrity'),

  // Policies
  getPolicies: () => request('/policies'),
  togglePolicy: (id, active) =>
    request(`/policies/${id}?active=${active}`, { method: 'PATCH' }),

  // Simulation
  runSimulation: () =>
    request('/simulation/run', { method: 'POST' }),
};
