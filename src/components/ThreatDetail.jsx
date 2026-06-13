/**
 * ThreatShield — ThreatDetail Component
 *
 * Detailed panel for the selected threat event.
 * Shows detailed parameters, MITRE mapping, full reasoning, and manual action controls.
 */

import { useState } from 'react';
import './ThreatDetail.css';

export default function ThreatDetail({ event, onClose }) {
  const [isExecuting, setIsExecuting] = useState(false);
  const [executed, setExecuted] = useState(false);

  if (!event) {
    return (
      <div className="threat-detail-empty glass-panel" id="threat-detail">
        <span className="threat-detail-empty__icon">🛡️</span>
        <h3>No Event Selected</h3>
        <p>Select a threat event from the activity feed to view detailed telemetry, MITRE ATT&CK mapping, and mitigation actions.</p>
      </div>
    );
  }

  const raw = event._raw_event || {};

  const handleExecuteAction = () => {
    setIsExecuting(true);
    setTimeout(() => {
      setIsExecuting(false);
      setExecuted(true);
    }, 1500);
  };

  const getSeverityClass = (sev) => {
    return `severity-${sev?.toLowerCase()}`;
  };

  return (
    <div className="threat-detail glass-panel" id="threat-detail">
      <div className="threat-detail__header">
        <div className="threat-detail__title-group">
          <span className={`badge badge-${event.severity.toLowerCase()}`}>
            {event.severity}
          </span>
          <h2 className="threat-detail__title">{event.threat_type}</h2>
        </div>
        <button className="threat-detail__close-btn" onClick={onClose} aria-label="Close detail panel">
          ✕
        </button>
      </div>

      <div className="threat-detail__content">
        {/* Core Metrics */}
        <div className="threat-detail__grid-metrics">
          <div className="metric-box">
            <span className="metric-box__label">Priority Score</span>
            <span className="metric-box__val mono text-primary">{event.priority_score}/10</span>
          </div>
          <div className="metric-box">
            <span className="metric-box__label">Confidence</span>
            <span className="metric-box__val mono text-primary">{event.confidence}%</span>
          </div>
          <div className="metric-box">
            <span className="metric-box__label">Auto-Responded</span>
            <span className={`metric-box__val mono ${event.auto_respond ? 'severity-low' : 'severity-high'}`}>
              {event.auto_respond ? 'YES' : 'NO'}
            </span>
          </div>
        </div>

        {/* Intelligence Reasoning */}
        <div className="detail-section">
          <h4 className="detail-section__title">AI Decision Reasoning</h4>
          <div className="detail-section__card bg-secondary">
            <p className="reasoning-text">{event.reasoning}</p>
          </div>
        </div>

        {/* MITRE ATT&CK Mapping */}
        <div className="detail-section">
          <h4 className="detail-section__title">MITRE ATT&CK Mapping</h4>
          <div className="detail-section__card bg-secondary mitre-mapping-card">
            <div>
              <span className="mitre-label">Tactic</span>
              <span className="mitre-val">{event.mitre_tactic}</span>
            </div>
            <div>
              <span className="mitre-label">Technique ID</span>
              <span className="mitre-val mono">{event.mitre_technique}</span>
            </div>
          </div>
        </div>

        {/* Assets & Telemetry details */}
        <div className="detail-section">
          <h4 className="detail-section__title">Endpoint & Network Details</h4>
          <div className="detail-section__card telemetry-card">
            <div className="telemetry-row">
              <span className="telemetry-label">Hostname:</span>
              <span className="telemetry-val mono">{raw.endpoint?.hostname || 'N/A'}</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">OS version:</span>
              <span className="telemetry-val">{raw.endpoint?.os || 'N/A'}</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">Process Name:</span>
              <span className="telemetry-val mono">{raw.endpoint?.process_name} (PID: {raw.endpoint?.process_id})</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">Endpoint Action:</span>
              <span className="telemetry-val mono">{raw.endpoint?.action || 'N/A'}</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">Affected Files:</span>
              <span className="telemetry-val">{raw.endpoint?.files_affected}</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">Src IP / Dst IP:</span>
              <span className="telemetry-val mono">{raw.network?.src_ip}:{raw.network?.src_port} → {raw.network?.dst_ip}:{raw.network?.dst_port}</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">Bytes Transferred:</span>
              <span className="telemetry-val mono">{(raw.network?.bytes_transferred || 0).toLocaleString()} bytes</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">Traffic Rate:</span>
              <span className="telemetry-val mono">{raw.network?.packets_per_second} pps ({raw.network?.protocol})</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">Geo Location:</span>
              <span className="telemetry-val">{raw.network?.geo_location}</span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-label">Environment:</span>
              <span className="telemetry-val uppercase text-primary font-bold">{raw.context?.environment}</span>
            </div>
          </div>
        </div>

        {/* Escalation note if analyst escalation is required */}
        {event.escalation_note && (
          <div className="detail-section">
            <h4 className="detail-section__title">Analyst Action Steps</h4>
            <div className="detail-section__card border-warning bg-warning-subtle">
              <p className="escalation-text">{event.escalation_note}</p>
            </div>
          </div>
        )}

        {/* Mitigation & Response action control */}
        <div className="detail-section detail-section--action">
          <h4 className="detail-section__title">Incident Mitigation Response</h4>
          <div className="action-control">
            <div className="action-control__info">
              <span className="action-control__label">Recommended Action</span>
              <span className="action-control__val mono">{event.recommended_action.replace(/_/g, ' ')}</span>
            </div>

            {executed ? (
              <div className="action-success-msg">
                ✓ Mitigation Executed Successfully
              </div>
            ) : (
              <button
                className={`action-btn ${isExecuting ? 'action-btn--loading' : ''} action-btn--${event.severity.toLowerCase()}`}
                onClick={handleExecuteAction}
                disabled={isExecuting}
                id="btn-execute-mitigation"
              >
                {isExecuting ? 'Executing Mitigation...' : `Execute ${event.recommended_action.replace(/_/g, ' ')}`}
              </button>
            )}
          </div>
        </div>

        {/* Raw telemetry JSON */}
        <div className="detail-section">
          <h4 className="detail-section__title">Raw Event JSON</h4>
          <div className="raw-json-container">
            <pre className="mono raw-json">{JSON.stringify(raw, null, 2)}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}
