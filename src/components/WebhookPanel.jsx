/**
 * ThreatShield — WebhookPanel Component
 *
 * Configures outbound webhook endpoint URLs and monitors transmission logs.
 */

import './WebhookPanel.css';

export default function WebhookPanel({ webhookUrl, onUrlChange, logs }) {
  const getStatusClass = (status) => {
    switch (status) {
      case 'DELIVERED': return 'status-delivered';
      case 'FAILED': return 'status-failed';
      default: return 'status-sending';
    }
  };

  return (
    <div className="webhook-panel glass-panel" id="webhook-panel">
      <div className="webhook-panel__header">
        <h3 className="webhook-panel__title">Outbound Integrations</h3>
        <p className="webhook-panel__subtitle">Dispatch auto-responses to external API endpoints</p>
      </div>

      <div className="webhook-panel__config">
        <label htmlFor="webhook-input" className="config-label">Webhook Destination URL</label>
        <div className="config-input-group">
          <input
            id="webhook-input"
            type="text"
            className="config-input mono"
            placeholder="Webhook destination URL (Slack, Discord, custom)"
            value={webhookUrl}
            onChange={(e) => onUrlChange(e.target.value)}
          />
        </div>
      </div>

      <div className="webhook-panel__logs">
        <span className="logs-title">Delivery Audit Trail</span>
        <div className="logs-list">
          {logs.length === 0 ? (
            <div className="logs-empty">
              Awaiting outbound mitigation alerts...
            </div>
          ) : (
            logs.map((log) => (
              <div key={log.id} className="log-row">
                <span className="log-row__time mono">
                  {new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                </span>
                <span className="log-row__action mono" title={log.payload.text}>
                  AUTO_RESPONSE
                </span>
                <span className={`log-row__status mono ${getStatusClass(log.status)}`}>
                  {log.status}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
