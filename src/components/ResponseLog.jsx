/**
 * ThreatShield — ResponseLog Component
 *
 * Displays a tabular historical audit log of all automated responses triggered by the AI engine.
 * Supports filtering by Action type.
 */

import { useState } from 'react';
import './ResponseLog.css';

export default function ResponseLog({ logs }) {
  const [filterAction, setFilterAction] = useState('ALL');

  const actions = ['ALL', 'BLOCK_IP', 'ISOLATE_DEVICE', 'KILL_PROCESS'];

  const filteredLogs = filterAction === 'ALL'
    ? logs
    : logs.filter((log) => log.recommended_action === filterAction);

  const formatTime = (isoString) => {
    if (!isoString) return '';
    const date = new Date(isoString);
    return date.toLocaleTimeString('en-US', { hour12: false });
  };

  return (
    <div className="response-log glass-panel" id="response-log">
      <div className="response-log__header">
        <div>
          <h2 className="response-log__title">Mitigation Response Log</h2>
          <p className="response-log__subtitle">Historical record of automated mitigation actions executed by ThreatShield</p>
        </div>

        <div className="response-log__filters">
          <label htmlFor="action-filter" className="filter-label">Filter Action:</label>
          <select
            id="action-filter"
            className="filter-select mono"
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
          >
            {actions.map((act) => (
              <option key={act} value={act}>
                {act.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="response-log__table-wrapper">
        <table className="response-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Event ID</th>
              <th>Action Triggered</th>
              <th>Target Asset / IP</th>
              <th>Trigger Severity</th>
              <th>MITRE Technique</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="7" className="response-table__empty">
                  No automated responses logged matching the current criteria.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => (
                <tr key={log.event_id} id={`response-log-row-${log.event_id}`}>
                  <td className="mono">{formatTime(log._analyzed_at)}</td>
                  <td className="mono text-muted">{log.event_id}</td>
                  <td>
                    <span className="response-action-tag mono">
                      {log.recommended_action}
                    </span>
                  </td>
                  <td className="mono">{log.affected_asset}</td>
                  <td>
                    <span className={`badge badge-${log.severity.toLowerCase()}`}>
                      {log.severity}
                    </span>
                  </td>
                  <td className="mono text-muted">{log.mitre_technique || 'N/A'}</td>
                  <td>
                    <span className="status-indicator status-indicator--executed">
                      ● EXECUTED
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
