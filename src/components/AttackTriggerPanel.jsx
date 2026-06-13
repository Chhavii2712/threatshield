/**
 * ThreatShield — AttackTriggerPanel Component
 *
 * Provides manual scenario execution options for judges and presenters to trigger attacks.
 */

import './AttackTriggerPanel.css';

const SCENARIOS = [
  { type: 'Ransomware',      label: 'Ransomware Chain', icon: '🔴', desc: 'Simulates bulk encryption & known bad IP beaconing.' },
  { type: 'DataExfiltration', label: 'Data Exfil Transfer', icon: '📤', desc: 'Simulates large outbound payloads to outside hosts.' },
  { type: 'DDoS',            label: 'DDoS Storm',       icon: '⚡', desc: 'Simulates volumetric packet surges on ports.' },
  { type: 'BruteForce',      label: 'Brute Force Entry', icon: '🔑', desc: 'Simulates brute force attempts ending in success.' },
  { type: 'Smokescreen',     label: 'Smokescreen Noise', icon: '💨', desc: 'Simulates decoy scans masking concurrent attacks.' },
];

export default function AttackTriggerPanel({ onTrigger }) {
  return (
    <div className="attack-trigger-panel glass-panel" id="attack-trigger-panel">
      <div className="attack-trigger-panel__header">
        <h3 className="attack-trigger-panel__title">Targeted Attack Simulator</h3>
      </div>
      <div className="attack-trigger-panel__content">
        {SCENARIOS.map((scen) => (
          <button
            key={scen.type}
            className="trigger-btn"
            onClick={() => onTrigger(scen.type)}
            id={`btn-trigger-${scen.type.toLowerCase()}`}
            title={`Trigger ${scen.label}`}
          >
            <span className="trigger-btn__icon">{scen.icon}</span>
            <div className="trigger-btn__info">
              <span className="trigger-btn__label">{scen.label}</span>
              <span className="trigger-btn__desc">{scen.desc}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
