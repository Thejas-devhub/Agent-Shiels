import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Dashboard from './pages/Dashboard';
import ActionSimulator from './pages/ActionSimulator';
import ApprovalCenter from './pages/ApprovalCenter';
import AuditLogs from './pages/AuditLogs';
import SecurityPolicies from './pages/SecurityPolicies';
import AttackSimulation from './pages/AttackSimulation';
import { api } from './services/api';
import './index.css';

const NAV_ITEMS = [
  { path: '/dashboard', label: 'Dashboard', icon: '\u2302' },
  { path: '/simulator', label: 'Action Simulator', icon: '\u26A1' },
  { path: '/approvals', label: 'Approval Center', icon: '\u2714' },
  { path: '/audit', label: 'Audit Logs', icon: '\u2630' },
  { path: '/policies', label: 'Security Policies', icon: '\u2699' },
  { path: '/simulation', label: 'Attack Simulation', icon: '\u2620' },
];

export default function App() {
  const [pendingCount, setPendingCount] = useState(0);
  const [backendOk, setBackendOk] = useState(true);

  useEffect(() => {
    checkBackend();
    const interval = setInterval(fetchPending, 5000);
    return () => clearInterval(interval);
  }, []);

  async function checkBackend() {
    try {
      await api.health();
      setBackendOk(true);
      fetchPending();
    } catch {
      setBackendOk(false);
    }
  }

  async function fetchPending() {
    try {
      const approvals = await api.getApprovals();
      const count = approvals.filter(a => a.status === 'PENDING').length;
      setPendingCount(count);
    } catch {
      // silently fail for badge count
    }
  }

  return (
    <BrowserRouter>
      <div className="app-layout">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="sidebar-brand">
            <div className="sidebar-logo">AS</div>
            <div>
              <h1>AgentShield</h1>
              <span>AI Action Firewall</span>
            </div>
          </div>

          <nav className="sidebar-nav">
            {NAV_ITEMS.map(item => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <span className="nav-icon">{item.icon}</span>
                <span>{item.label}</span>
                {item.path === '/approvals' && pendingCount > 0 && (
                  <span className="nav-badge">{pendingCount}</span>
                )}
              </NavLink>
            ))}
          </nav>

          <div className="sidebar-footer">
            <div className="sidebar-status">
              <div className={`status-dot ${backendOk ? '' : 'status-dot-error'}`}
                   style={!backendOk ? { background: 'var(--color-block)', boxShadow: '0 0 8px var(--color-block)' } : {}}>
              </div>
              <span>{backendOk ? 'Backend Connected' : 'Backend Offline'}</span>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="main-content">
          {!backendOk && (
            <div className="error-banner" style={{ margin: '16px 32px 0' }}>
              <span>&#x26A0;</span>
              <span>
                Cannot connect to backend API.{' '}
                {import.meta.env.PROD ? (
                  'The backend service may be starting up — please retry in a moment.'
                ) : (
                  <>
                    Please start the backend server:
                    <code style={{
                      marginLeft: 8,
                      padding: '2px 8px',
                      background: 'rgba(0,0,0,0.3)',
                      borderRadius: 4,
                      fontFamily: 'var(--font-mono)',
                      fontSize: 12,
                    }}>
                      cd backend &amp;&amp; python main.py
                    </code>
                  </>
                )}
              </span>
              <button className="btn btn-outline btn-sm" onClick={checkBackend} style={{ marginLeft: 'auto' }}>
                Retry
              </button>
            </div>
          )}

          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/simulator" element={<ActionSimulator />} />
            <Route path="/approvals" element={<ApprovalCenter />} />
            <Route path="/audit" element={<AuditLogs />} />
            <Route path="/policies" element={<SecurityPolicies />} />
            <Route path="/simulation" element={<AttackSimulation />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
