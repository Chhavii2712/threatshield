/**
 * ThreatShield — StatsBar Component
 *
 * Row of severity-colored stat cards with animated counters
 */

import './StatsBar.css';

const STAT_CARDS = [
  { key: 'total',   label: 'Total Events', icon: '📊', colorClass: 'stat--primary' },
  { key: 'critical', label: 'Critical',     icon: '🔴', colorClass: 'stat--critical' },
  { key: 'high',     label: 'High',         icon: '🟠', colorClass: 'stat--high' },
  { key: 'medium',   label: 'Medium',       icon: '🟡', colorClass: 'stat--medium' },
  { key: 'low',      label: 'Low',          icon: '🟢', colorClass: 'stat--low' },
  { key: 'autoResponses', label: 'Auto-Responses', icon: '⚡', colorClass: 'stat--auto' },
];

export default function StatsBar({ stats }) {
  return (
    <div className="stats-bar" id="stats-bar">
      {STAT_CARDS.map(({ key, label, icon, colorClass }) => (
        <div className={`stat-card glass-panel ${colorClass}`} key={key} id={`stat-${key}`}>
          <div className="stat-card__icon">{icon}</div>
          <div className="stat-card__data">
            <span className="stat-card__count mono">{(stats[key] || 0).toLocaleString()}</span>
            <span className="stat-card__label">{label}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
