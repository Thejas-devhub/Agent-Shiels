import { useState } from 'react';
import { api } from '../services/api';

export default function AttackSimulation() {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function runTests() {
    try {
      setLoading(true);
      setError(null);
      setResults(null);
      const data = await api.runSimulation();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Attack Simulation</h2>
        <p>Run predefined security test scenarios to validate the policy engine</p>
      </div>

      {error && (
        <div className="error-banner">
          <span>&#x26A0;</span>
          <span>{error}</span>
        </div>
      )}

      <button
        className="btn btn-primary"
        onClick={runTests}
        disabled={loading}
        style={{ marginBottom: 24 }}
      >
        {loading ? (
          <>
            <div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }}></div>
            Running Security Tests...
          </>
        ) : (
          <>Run All Tests</>
        )}
      </button>

      {results && (
        <div className="sim-results">
          {/* Summary Metrics */}
          <div className="sim-summary">
            <div className="sim-metric">
              <div className="sim-metric-value" style={{ color: 'var(--accent-primary-hover)' }}>
                {results.total_tests}
              </div>
              <div className="sim-metric-label">Total Tests</div>
            </div>
            <div className="sim-metric">
              <div className="sim-metric-value" style={{ color: 'var(--color-allow)' }}>
                {results.passed}
              </div>
              <div className="sim-metric-label">Passed</div>
            </div>
            <div className="sim-metric">
              <div className="sim-metric-value" style={{ color: 'var(--color-block)' }}>
                {results.failed}
              </div>
              <div className="sim-metric-label">Failed</div>
            </div>
            <div className="sim-metric">
              <div className="sim-metric-value" style={{ color: 'var(--color-block)' }}>
                {results.unauthorized_blocked}
              </div>
              <div className="sim-metric-label">Unauthorized Blocked</div>
            </div>
            <div className="sim-metric">
              <div className="sim-metric-value" style={{ color: 'var(--color-allow)' }}>
                {results.legitimate_allowed}
              </div>
              <div className="sim-metric-label">Legitimate Allowed</div>
            </div>
            <div className="sim-metric">
              <div className="sim-metric-value" style={{ color: 'var(--color-approval)' }}>
                {results.false_positives}
              </div>
              <div className="sim-metric-label">False Positives</div>
            </div>
            <div className="sim-metric">
              <div className="sim-metric-value" style={{ color: 'var(--text-secondary)' }}>
                {results.avg_evaluation_time_ms}
              </div>
              <div className="sim-metric-label">Avg Eval Time (ms)</div>
            </div>
          </div>

          {/* Pass rate bar */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="flex justify-between items-center mb-1">
              <span className="card-title">Pass Rate</span>
              <span className="font-bold" style={{ fontSize: 20 }}>
                {results.total_tests > 0
                  ? Math.round((results.passed / results.total_tests) * 100)
                  : 0}%
              </span>
            </div>
            <div style={{
              width: '100%',
              height: 12,
              background: 'var(--bg-elevated)',
              borderRadius: 6,
              overflow: 'hidden',
            }}>
              <div style={{
                width: `${(results.passed / results.total_tests) * 100}%`,
                height: '100%',
                background: results.failed === 0
                  ? 'var(--color-allow)'
                  : 'linear-gradient(90deg, var(--color-allow), var(--color-approval))',
                borderRadius: 6,
                transition: 'width 0.5s ease',
              }} />
            </div>
          </div>

          {/* Individual Test Results */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Test Results</h3>
            </div>
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Scenario</th>
                    <th>Action</th>
                    <th>Expected</th>
                    <th>Actual</th>
                    <th>Risk</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {results.results.map((r, i) => (
                    <tr key={i}>
                      <td>
                        <span className={r.passed ? 'sim-test-pass' : 'sim-test-fail'}
                              style={{ fontSize: 18, fontWeight: 800 }}>
                          {r.passed ? '\u2714' : '\u2718'}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, maxWidth: 200 }}>{r.scenario}</td>
                      <td className="cell-truncate">{r.action_name}</td>
                      <td>
                        <span className={`badge badge-${
                          r.expected_decision === 'ALLOW' ? 'allow' :
                          r.expected_decision === 'BLOCK' ? 'block' : 'approval'
                        }`}>
                          {r.expected_decision}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${
                          r.actual_decision === 'ALLOW' ? 'allow' :
                          r.actual_decision === 'BLOCK' ? 'block' : 'approval'
                        }`}>
                          {r.actual_decision}
                        </span>
                      </td>
                      <td>
                        <span className="risk-value">{r.risk_score}</span>
                      </td>
                      <td className="cell-mono" style={{ fontSize: 11 }}>
                        {r.evaluation_time_ms}ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Disclaimer */}
          <div className="disclaimer">
            <strong>Disclaimer:</strong> {results.disclaimer}
          </div>
        </div>
      )}
    </div>
  );
}
