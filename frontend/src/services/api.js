/**
 * AgentShield — API Service
 * All backend communication goes through here.
 */

// Strip trailing slash from the base URL, then append /api exactly once.
// Priority: VITE_API_BASE_URL (production) → VITE_API_URL (legacy) → localhost dev fallback
const _rawBase =
  import.meta.env.VITE_API_BASE_URL ||
  import.meta.env.VITE_API_URL ||
  'http://localhost:8000';

const API_BASE = _rawBase.replace(/\/+$/, '') + '/api';

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
      throw new Error(
        'Cannot connect to backend API. ' +
        (import.meta.env.PROD
          ? 'The backend service may be starting up — please retry in a moment.'
          : 'Please start the backend server: cd backend && python main.py')
      );
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
