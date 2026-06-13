/**
 * ThreatShield — ActivityTimeline Component
 *
 * Displays a rolling vertical timeline of auto-response mitigation activities.
 */

import './ActivityTimeline.css';

export default function ActivityTimeline({ autoResponseLog }) {
  const formatTime = (isoString) => {
    if (!isoString) return '';
    const date = new Date(isoString);
    return date.toLocaleTimeString('en-US', { hour12: false });
  };

  const latestLogs = autoResponseLog.slice(0, 5); // Show top 5 latest responses

  return (
    <div className="activity-timeline glass-panel" id="activity-timeline">
      <div className="activity-timeline__header">
        <h3 className="activity-timeline__title">Mitigation Timeline</h3>
      </div>

      <div className="activity-timeline__content">
        {latestLogs.length === 0 ? (
          <div className="timeline-empty">
            <span className="timeline-empty__icon">🛡️</span>
            <p>No automatic mitigations triggered yet.</p>
          </div>
        ) : (
          <div className="timeline-list">
            {latestLogs.map((log) => (
              <div className="timeline-item" key={log.event_id}>
                <div className="timeline-item__marker">
                  <div className="timeline-item__pulse" />
                  <div className="timeline-item__dot" />
                </div>
                <div className="timeline-item__details">
                  <div className="timeline-item__meta">
                    <span className="timeline-item__time mono">{formatTime(log._analyzed_at)}</span>
                    <span className={`badge badge-${log.severity.toLowerCase()} timeline-item__severity`}>
                      {log.severity}
                    </span>
                  </div>
                  <h4 className="timeline-item__action">{log.recommended_action.replace(/_/g, ' ')}</h4>
                  <p className="timeline-item__desc">
                    Triggered on <span className="mono text-secondary">{log.affected_asset}</span> due to {log.threat_type}.
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
