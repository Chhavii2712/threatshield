/**
 * ThreatShield — GeoMap Component
 *
 * Stylized SVG map representing attack source geographic locations.
 * Draws pulsing indicators where events originate.
 */

import './GeoMap.css';

// Coordinates for countries on a 300x150 SVG projection box
const GEO_COORDS = {
  'United States':   { x: 60,  y: 60  },
  'Brazil':          { x: 100, y: 110 },
  'United Kingdom':  { x: 135, y: 45  },
  'France':          { x: 142, y: 52  },
  'Germany':         { x: 150, y: 48  },
  'Netherlands':     { x: 146, y: 46  },
  'Romania':         { x: 165, y: 54  },
  'Ukraine':         { x: 175, y: 50  },
  'Russia':          { x: 200, y: 42  },
  'China':           { x: 235, y: 65  },
  'North Korea':     { x: 252, y: 62  },
  'Japan':           { x: 262, y: 63  },
  'India':           { x: 215, y: 80  },
  'Singapore':       { x: 240, y: 98  },
  'Iran':            { x: 190, y: 68  },
};

export default function GeoMap({ geoData }) {
  const maxVal = Math.max(...Object.values(geoData), 1);

  return (
    <div className="geo-map glass-panel" id="geo-map">
      <div className="geo-map__header">
        <h3 className="geo-map__title">Global Threat Origins</h3>
      </div>

      <div className="geo-map__content">
        <svg viewBox="0 0 320 160" className="world-svg">
          {/* Abstract land shapes (horizontal grid lines to resemble a high-tech screen matrix) */}
          <g className="world-grid" opacity="0.15">
            {Array.from({ length: 16 }).map((_, i) => (
              <line key={i} x1="0" y1={i * 10} x2="320" y2={i * 10} stroke="var(--accent-primary)" strokeWidth="0.5" />
            ))}
            {Array.from({ length: 32 }).map((_, i) => (
              <line key={i} x1={i * 10} y1="0" x2={i * 10} y2="160" stroke="var(--accent-primary)" strokeWidth="0.5" />
            ))}
          </g>

          {/* Simple representative shapes for major continents */}
          {/* North America */}
          <path d="M25,35 L90,35 L95,65 L70,85 L45,65 Z" fill="rgba(255, 255, 255, 0.03)" stroke="rgba(255, 255, 255, 0.08)" strokeWidth="1" />
          {/* South America */}
          <path d="M75,90 L115,95 L105,145 L90,140 Z" fill="rgba(255, 255, 255, 0.03)" stroke="rgba(255, 255, 255, 0.08)" strokeWidth="1" />
          {/* Eurasia & Africa */}
          <path d="M125,40 L280,30 L290,95 L220,110 L150,115 L125,75 Z" fill="rgba(255, 255, 255, 0.03)" stroke="rgba(255, 255, 255, 0.08)" strokeWidth="1" />
          {/* Australia */}
          <path d="M260,115 L295,115 L295,140 L260,135 Z" fill="rgba(255, 255, 255, 0.03)" stroke="rgba(255, 255, 255, 0.08)" strokeWidth="1" />

          {/* Attack dots */}
          {Object.entries(geoData).map(([country, count]) => {
            const coords = GEO_COORDS[country];
            if (!coords) return null;

            // Dot sizing based on intensity
            const intensity = count / maxVal;
            const rBase = 3 + intensity * 4;
            const rPulse = rBase * 2.2;

            return (
              <g key={country} className="map-node" id={`map-node-${country.toLowerCase().replace(/ /g, '-')}`}>
                {/* Pulse Glow Ring */}
                <circle
                  cx={coords.x}
                  cy={coords.y}
                  r={rPulse}
                  fill="none"
                  stroke="var(--accent-critical)"
                  strokeWidth="0.75"
                  className="map-node__pulse"
                />
                {/* Active Hub */}
                <circle
                  cx={coords.x}
                  cy={coords.y}
                  r={rBase}
                  fill="var(--accent-critical)"
                  className="map-node__dot"
                />
                <title>{`${country}: ${count} event(s)`}</title>
              </g>
            );
          })}
        </svg>
      </div>

      <div className="geo-map__footer">
        <div className="geo-map__top-countries">
          {Object.entries(geoData)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3)
            .map(([country, count]) => (
              <span key={country} className="geo-badge mono">
                📍 {country} ({count})
              </span>
            ))}
        </div>
      </div>
    </div>
  );
}
