/**
 * ThreatShield — SeverityChart Component
 *
 * pure SVG/CSS donut chart representing the distribution of event severity.
 */

import './SeverityChart.css';

export default function SeverityChart({ stats }) {
  const { critical = 0, high = 0, medium = 0, low = 0 } = stats;
  const total = critical + high + medium + low;

  const data = [
    { label: 'Critical', count: critical, color: 'var(--accent-critical)', class: 'severity-critical' },
    { label: 'High',     count: high,     color: 'var(--accent-high)',     class: 'severity-high' },
    { label: 'Medium',   count: medium,   color: 'var(--accent-medium)',   class: 'severity-medium' },
    { label: 'Low',      count: low,      color: 'var(--accent-low)',      class: 'severity-low' },
  ];

  // SVG parameters
  const size = 160;
  const strokeWidth = 16;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  let accumulatedPercentage = 0;

  return (
    <div className="severity-chart glass-panel" id="severity-chart">
      <div className="severity-chart__header">
        <h3 className="severity-chart__title">Severity Distribution</h3>
      </div>

      <div className="severity-chart__content">
        <div className="severity-chart__visualization">
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="donut">
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="transparent"
              stroke="var(--bg-tertiary)"
              strokeWidth={strokeWidth}
            />
            {total > 0 &&
              data.map((item) => {
                const percentage = item.count / total;
                const strokeDasharray = `${percentage * circumference} ${circumference}`;
                const strokeDashoffset = circumference - (accumulatedPercentage * circumference) + (circumference / 4); // rotate start to top
                accumulatedPercentage += percentage;

                if (item.count === 0) return null;

                return (
                  <circle
                    key={item.label}
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    fill="transparent"
                    stroke={item.color}
                    strokeWidth={strokeWidth}
                    strokeDasharray={strokeDasharray}
                    strokeDashoffset={strokeDashoffset}
                    className="donut-segment"
                  />
                );
              })}
          </svg>
          <div className="donut-center">
            <span className="donut-center__count mono">{total}</span>
            <span className="donut-center__label">Total</span>
          </div>
        </div>

        <div className="severity-chart__legend">
          {data.map((item) => {
            const percentage = total > 0 ? Math.round((item.count / total) * 100) : 0;
            return (
              <div className="legend-item" key={item.label}>
                <div className="legend-item__label-group">
                  <span className={`legend-item__dot ${item.class}`} />
                  <span className="legend-item__label">{item.label}</span>
                </div>
                <div className="legend-item__stats">
                  <span className="legend-item__count mono">{item.count}</span>
                  <span className="legend-item__percentage mono">{percentage}%</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
