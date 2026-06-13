/**
 * ThreatShield — ThreatTypeChart Component
 *
 * Horizontal bar chart showing counts per threat classification.
 */

import './ThreatTypeChart.css';

const THREAT_TYPES = [
  'Ransomware', 'DataExfiltration', 'DDoS', 'BruteForce',
  'MalwareC2', 'InsiderThreat', 'Phishing', 'LateralMovement',
  'Reconnaissance', 'Smokescreen', 'Unknown'
];

export default function ThreatTypeChart({ counts }) {
  // Find max value to determine percentage width of the bars
  const maxVal = Math.max(...THREAT_TYPES.map(type => counts[type] || 0), 1);

  return (
    <div className="threat-type-chart glass-panel" id="threat-type-chart">
      <div className="threat-type-chart__header">
        <h3 className="threat-type-chart__title">Threat Classification Breakdown</h3>
      </div>

      <div className="threat-type-chart__content">
        {THREAT_TYPES.map((type) => {
          const val = counts[type] || 0;
          const percentage = (val / maxVal) * 100;

          return (
            <div className="bar-row" key={type} id={`threat-type-row-${type.toLowerCase()}`}>
              <span className="bar-row__label" title={type}>{type}</span>
              <div className="bar-row__track">
                <div
                  className="bar-row__fill"
                  style={{ width: `${percentage}%` }}
                />
              </div>
              <span className="bar-row__val mono">{val}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
