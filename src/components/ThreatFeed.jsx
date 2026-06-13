/**
 * ThreatShield — ThreatFeed Component
 *
 * Real-time list of threat cards. Click to select/expand.
 */

import './ThreatFeed.css';

export default function ThreatFeed({ events, selectedEvent, onSelectEvent, searchQuery, onSearchQueryChange }) {
  const getSeverityBadgeClass = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return '';
    }
  };

  const getActionBadgeClass = (action) => {
    if (['BLOCK_IP', 'ISOLATE_DEVICE', 'KILL_PROCESS'].includes(action)) {
      return 'action-badge--auto';
    }
    return 'action-badge--manual';
  };

  const formatTime = (isoString) => {
    if (!isoString) return '';
    const date = new Date(isoString);
    return date.toLocaleTimeString('en-US', { hour12: false });
  };

  return (
    <div className="threat-feed glass-panel" id="threat-feed">
      <div className="threat-feed__header">
        <h2 className="threat-feed__title">Activity Feed</h2>
        <span className="threat-feed__count mono">{events.length} events logged</span>
      </div>

      <div className="threat-feed__search">
        <input
          type="text"
          placeholder="Search IP, Host, Severity, MITRE..."
          value={searchQuery}
          onChange={(e) => onSearchQueryChange(e.target.value)}
          className="search-input"
          id="feed-search-input"
        />
      </div>

      <div className="threat-feed__list">
        {events.length === 0 ? (
          <div className="threat-feed__empty">
            <span className="threat-feed__empty-icon">📡</span>
            <p>Awaiting incoming telemetry data...</p>
          </div>
        ) : (
          events.map((event) => {
            const isSelected = selectedEvent?.event_id === event.event_id;
            return (
              <div
                key={event.event_id}
                className={`threat-card threat-card--${event.severity.toLowerCase()} ${
                  isSelected ? 'threat-card--selected' : ''
                }`}
                onClick={() => onSelectEvent(event)}
                id={`threat-card-${event.event_id}`}
              >
                <div className="threat-card__header">
                  <span className={`badge ${getSeverityBadgeClass(event.severity)}`}>
                    {event.severity}
                  </span>
                  <span className="threat-card__time mono">{formatTime(event._raw_event?.timestamp)}</span>
                </div>

                <div className="threat-card__body">
                  <h3 className="threat-card__threat-type">{event.threat_type}</h3>
                  <p className="threat-card__summary">{event.dashboard_summary}</p>
                </div>

                <div className="threat-card__footer">
                  <span className="threat-card__asset mono" title={event.affected_asset}>
                    🖥️ {event.affected_asset}
                  </span>
                  <span className={`action-badge ${getActionBadgeClass(event.recommended_action)}`}>
                    {event.recommended_action.replace(/_/g, ' ')}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
