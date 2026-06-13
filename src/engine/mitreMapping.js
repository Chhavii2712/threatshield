/**
 * MITRE ATT&CK Mapping
 * Maps each ThreatShield threat type to its primary MITRE ATT&CK tactic and technique.
 */

export const MITRE_MAP = {
  Ransomware: {
    tactic: 'Impact',
    technique: 'T1486',
    techniqueName: 'Data Encrypted for Impact',
  },
  DataExfiltration: {
    tactic: 'Exfiltration',
    technique: 'T1041',
    techniqueName: 'Exfiltration Over C2 Channel',
  },
  DDoS: {
    tactic: 'Impact',
    technique: 'T1498',
    techniqueName: 'Network Denial of Service',
  },
  BruteForce: {
    tactic: 'Credential Access',
    technique: 'T1110',
    techniqueName: 'Brute Force',
  },
  Reconnaissance: {
    tactic: 'Reconnaissance',
    technique: 'T1046',
    techniqueName: 'Network Service Discovery',
  },
  MalwareC2: {
    tactic: 'Command and Control',
    technique: 'T1071',
    techniqueName: 'Application Layer Protocol',
  },
  InsiderThreat: {
    tactic: 'Collection',
    technique: 'T1074',
    techniqueName: 'Data Staged',
  },
  Phishing: {
    tactic: 'Initial Access',
    technique: 'T1566',
    techniqueName: 'Phishing',
  },
  LateralMovement: {
    tactic: 'Lateral Movement',
    technique: 'T1021',
    techniqueName: 'Remote Services',
  },
  Smokescreen: {
    tactic: 'Defense Evasion',
    technique: 'T1036',
    techniqueName: 'Masquerading',
  },
  Unknown: {
    tactic: 'Unknown',
    technique: 'N/A',
    techniqueName: 'Unclassified',
  },
};

/**
 * Returns MITRE ATT&CK mapping for a given threat type.
 */
export function getMitreMapping(threatType) {
  return MITRE_MAP[threatType] || MITRE_MAP.Unknown;
}
