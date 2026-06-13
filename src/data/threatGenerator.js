/**
 * ThreatShield — Simulated Threat Event Generator
 *
 * Produces realistic, randomized threat events for the live dashboard demo.
 * Weighted distribution: ~40% LOW, ~30% MEDIUM, ~20% HIGH, ~10% CRITICAL
 */

let eventCounter = 100;
const recentEventIds = [];

/* ─── Random Helpers ─── */
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const randFloat = (min, max) => +(Math.random() * (max - min) + min).toFixed(2);

/* ─── Data Pools ─── */
const EXTERNAL_IPS = [
  '185.220.101.45', '23.129.64.210', '45.33.32.156', '104.248.20.15',
  '91.219.236.174', '198.51.100.42', '203.0.113.99', '172.217.14.206',
  '54.239.28.85', '13.107.42.14', '185.56.83.112', '77.247.181.165',
  '62.210.105.116', '195.154.179.3', '51.15.43.205', '178.128.200.19',
];

const INTERNAL_IPS = [
  '192.168.1.10', '192.168.1.47', '192.168.1.105', '192.168.2.30',
  '10.0.0.15', '10.0.0.88', '10.0.1.200', '10.0.2.55',
  '172.16.0.10', '172.16.0.22', '172.16.1.100',
];

const GEO_LOCATIONS = [
  'Netherlands', 'Russia', 'China', 'United States', 'Germany',
  'Brazil', 'Iran', 'North Korea', 'Romania', 'Ukraine',
  'India', 'Singapore', 'United Kingdom', 'France', 'Japan',
];

const HOSTNAMES = [
  'radiology-ws-14', 'finance-srv-03', 'hr-desktop-07', 'dev-build-01',
  'dc-primary-01', 'mail-gw-02', 'web-prod-05', 'db-replica-03',
  'vpn-gateway-01', 'nas-backup-02', 'print-srv-01', 'cctv-controller',
  'patient-portal-01', 'trading-ws-08', 'audit-srv-01', 'kiosk-lobby-02',
  'iot-sensor-hub-03', 'lab-analyzer-01', 'scada-plc-07', 'erp-app-02',
];

const DEVICE_IDS = [
  'HOSP-PC-014', 'FIN-SRV-003', 'HR-DT-007', 'DEV-BLD-001',
  'DC-PRI-001', 'MAIL-GW-002', 'WEB-PRD-005', 'DB-REP-003',
  'VPN-GW-001', 'NAS-BKP-002', 'GOV-WS-012', 'ENT-LT-019',
];

const OS_LIST = [
  'Windows Server 2022', 'Windows 11 Pro', 'Ubuntu 22.04 LTS',
  'CentOS 8', 'macOS Ventura', 'Red Hat Enterprise Linux 9',
];

const PROCESS_NAMES = [
  'svchost.exe', 'powershell.exe', 'cmd.exe', 'explorer.exe',
  'chrome.exe', 'python3', 'java', 'node', 'nginx', 'httpd',
  'sqlservr.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe',
  'System', 'wscript.exe', 'mshta.exe', 'certutil.exe',
];

const ENVIRONMENTS = ['hospital', 'financial', 'government', 'enterprise', 'enterprise', 'enterprise'];
const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP'];

/* ─── Scenario Templates ─── */
const SCENARIOS = [
  // CRITICAL scenarios (~10%)
  {
    weight: 3,
    generate: () => ({
      source: 'malware_signal',
      action: 'bulk_file_encrypt',
      riskScore: randInt(90, 99),
      filesAffected: randInt(200, 2000),
      isKnownBad: true,
      protocol: 'HTTPS',
      dstPort: 443,
      bytes: randInt(500000, 5000000),
      pps: randInt(50, 200),
      ruleName: 'RANSOMWARE_ENCRYPT_BULK',
      description: 'Mass file encryption detected on endpoint',
      severityHint: 'critical',
    }),
  },
  {
    weight: 3,
    generate: () => ({
      source: 'network_log',
      action: 'outbound_transfer',
      riskScore: randInt(80, 95),
      filesAffected: randInt(500, 3000),
      isKnownBad: Math.random() > 0.3,
      protocol: 'HTTPS',
      dstPort: 443,
      bytes: randInt(100_000_000, 900_000_000),
      pps: randInt(100, 500),
      ruleName: 'DATA_EXFIL_LARGE_TRANSFER',
      description: 'Unusually large outbound data transfer detected',
      severityHint: 'critical',
    }),
  },
  {
    weight: 2,
    generate: () => ({
      source: 'malware_signal',
      action: 'outbound_call',
      riskScore: randInt(85, 99),
      filesAffected: 0,
      isKnownBad: true,
      protocol: 'HTTPS',
      dstPort: pick([443, 8443, 4443]),
      bytes: randInt(1000, 50000),
      pps: randInt(1, 10),
      ruleName: 'MALWARE_C2_BEACON',
      description: 'Process communicating with known C2 infrastructure',
      severityHint: 'critical',
    }),
  },

  // HIGH scenarios (~20%)
  {
    weight: 5,
    generate: () => ({
      source: 'intrusion_alert',
      action: 'brute_force_success',
      riskScore: randInt(70, 85),
      filesAffected: 0,
      isKnownBad: Math.random() > 0.5,
      protocol: 'TCP',
      dstPort: pick([22, 3389, 445]),
      bytes: randInt(5000, 50000),
      pps: randInt(20, 100),
      ruleName: 'AUTH_BRUTE_FORCE_SUCCESS',
      description: 'Brute force attack succeeded — authentication gained',
      severityHint: 'high',
    }),
  },
  {
    weight: 5,
    generate: () => ({
      source: 'network_log',
      action: 'lateral_remote_exec',
      riskScore: randInt(65, 85),
      filesAffected: randInt(0, 50),
      isKnownBad: false,
      isInternal: true,
      protocol: 'TCP',
      dstPort: pick([445, 135, 5985]),
      bytes: randInt(10000, 500000),
      pps: randInt(5, 50),
      ruleName: 'LATERAL_MOVEMENT_DETECTED',
      description: 'Internal host spreading to adjacent systems via remote execution',
      severityHint: 'high',
    }),
  },
  {
    weight: 4,
    generate: () => ({
      source: 'malware_signal',
      action: 'beacon',
      riskScore: randInt(76, 90),
      filesAffected: 0,
      isKnownBad: Math.random() > 0.4,
      protocol: 'HTTPS',
      dstPort: 443,
      bytes: randInt(500, 10000),
      pps: randInt(1, 5),
      ruleName: 'MALWARE_BEACON_PATTERN',
      description: 'Periodic beacon pattern detected from endpoint process',
      severityHint: 'high',
    }),
  },
  {
    weight: 3,
    generate: () => ({
      source: 'intrusion_alert',
      action: 'privilege_escalation',
      riskScore: randInt(70, 88),
      filesAffected: randInt(0, 20),
      isKnownBad: false,
      isInternal: true,
      protocol: 'TCP',
      dstPort: 445,
      bytes: randInt(1000, 100000),
      pps: randInt(1, 10),
      ruleName: 'INSIDER_PRIV_ESCALATION',
      description: 'User escalated privileges beyond authorized level',
      severityHint: 'high',
    }),
  },

  // MEDIUM scenarios (~30%)
  {
    weight: 8,
    generate: () => ({
      source: 'intrusion_alert',
      action: 'failed_auth',
      riskScore: randInt(30, 55),
      filesAffected: 0,
      isKnownBad: Math.random() > 0.7,
      protocol: 'TCP',
      dstPort: pick([22, 3389, 445, 80]),
      bytes: randInt(500, 5000),
      pps: randInt(10, 80),
      ruleName: 'AUTH_FAILED_REPEATED',
      description: 'Multiple failed authentication attempts from single source',
      severityHint: 'medium',
    }),
  },
  {
    weight: 7,
    generate: () => ({
      source: 'network_log',
      action: 'port_scan',
      riskScore: randInt(20, 45),
      filesAffected: 0,
      isKnownBad: Math.random() > 0.6,
      protocol: 'TCP',
      dstPort: randInt(1, 65535),
      bytes: randInt(100, 5000),
      pps: randInt(50, 500),
      ruleName: 'RECON_PORT_SCAN',
      description: 'Sequential port scanning activity detected from external IP',
      severityHint: 'medium',
    }),
  },
  {
    weight: 5,
    generate: () => ({
      source: 'network_log',
      action: 'suspicious_dns',
      riskScore: randInt(35, 55),
      filesAffected: 0,
      isKnownBad: false,
      protocol: 'DNS',
      dstPort: 53,
      bytes: randInt(100, 2000),
      pps: randInt(5, 30),
      ruleName: 'PHISHING_DNS_SUSPICIOUS',
      description: 'DNS queries to suspicious domains matching phishing patterns',
      severityHint: 'medium',
    }),
  },
  {
    weight: 5,
    generate: () => ({
      source: 'malware_signal',
      action: 'outbound_call',
      riskScore: randInt(40, 65),
      filesAffected: 0,
      isKnownBad: false,
      protocol: pick(['HTTP', 'HTTPS']),
      dstPort: pick([80, 443, 8080]),
      bytes: randInt(1000, 50000),
      pps: randInt(1, 10),
      ruleName: 'SUSPICIOUS_OUTBOUND_PROCESS',
      description: 'Unknown process making suspicious outbound connection',
      severityHint: 'medium',
    }),
  },

  // LOW scenarios (~40%)
  {
    weight: 12,
    generate: () => ({
      source: 'network_log',
      action: 'unusual_port_access',
      riskScore: randInt(5, 25),
      filesAffected: 0,
      isKnownBad: false,
      isInternal: true,
      protocol: pick(['TCP', 'UDP']),
      dstPort: pick([8443, 9090, 6379, 27017, 5432]),
      bytes: randInt(100, 10000),
      pps: randInt(1, 10),
      ruleName: 'ANOMALY_UNUSUAL_PORT',
      description: 'Internal IP accessed unusual port — single occurrence',
      severityHint: 'low',
    }),
  },
  {
    weight: 10,
    generate: () => ({
      source: 'intrusion_alert',
      action: 'minor_rule_trigger',
      riskScore: randInt(5, 20),
      filesAffected: 0,
      isKnownBad: false,
      protocol: pick(['TCP', 'HTTP', 'HTTPS']),
      dstPort: pick([80, 443, 8080]),
      bytes: randInt(100, 5000),
      pps: randInt(1, 5),
      ruleName: 'MINOR_ANOMALY_TRIGGER',
      description: 'Low-confidence rule triggered with no corroborating signals',
      severityHint: 'low',
    }),
  },
  {
    weight: 5,
    generate: () => ({
      source: 'network_log',
      action: 'probe',
      riskScore: randInt(10, 30),
      filesAffected: 0,
      isKnownBad: false,
      protocol: 'ICMP',
      dstPort: 0,
      bytes: randInt(64, 512),
      pps: randInt(1, 20),
      ruleName: 'ICMP_PROBE',
      description: 'ICMP probe detected from external IP',
      severityHint: 'low',
    }),
  },

  // Smokescreen
  {
    weight: 3,
    generate: () => ({
      source: 'network_log',
      action: 'high_volume_noise',
      riskScore: randInt(1, 15),
      filesAffected: 0,
      isKnownBad: false,
      protocol: pick(['UDP', 'ICMP']),
      dstPort: randInt(1, 65535),
      bytes: randInt(50, 500),
      pps: randInt(2000, 8000),
      ruleName: 'NOISE_HIGH_VOLUME',
      description: 'High-volume low-impact traffic — possible smokescreen',
      severityHint: 'low',
    }),
  },
];

/* ─── Weighted Random Selection ─── */
function pickScenario() {
  const totalWeight = SCENARIOS.reduce((sum, s) => sum + s.weight, 0);
  let roll = Math.random() * totalWeight;
  for (const scenario of SCENARIOS) {
    roll -= scenario.weight;
    if (roll <= 0) return scenario;
  }
  return SCENARIOS[SCENARIOS.length - 1];
}

/* ─── Generate a Single Threat Event ─── */
export function generateThreatEvent() {
  const scenario = pickScenario();
  const data = scenario.generate();

  const eventId = `evt_${String(++eventCounter).padStart(4, '0')}`;
  const isInternal = data.isInternal || false;
  const srcIp = isInternal ? pick(INTERNAL_IPS) : pick(EXTERNAL_IPS);
  const dstIp = isInternal ? pick(INTERNAL_IPS) : pick(INTERNAL_IPS);
  const hostname = pick(HOSTNAMES);
  const deviceId = pick(DEVICE_IDS);

  // Build correlated event IDs (30% chance to have 1-3 correlated events)
  let correlatedIds = [];
  if (Math.random() > 0.7 && recentEventIds.length > 0) {
    const count = randInt(1, Math.min(3, recentEventIds.length));
    const shuffled = [...recentEventIds].sort(() => Math.random() - 0.5);
    correlatedIds = shuffled.slice(0, count);
  }

  // Track this event for future correlations
  recentEventIds.push(eventId);
  if (recentEventIds.length > 20) recentEventIds.shift();

  const event = {
    event_id: eventId,
    timestamp: new Date().toISOString(),
    source: data.source,

    network: {
      src_ip: srcIp,
      dst_ip: dstIp,
      src_port: randInt(1024, 65535),
      dst_port: data.dstPort,
      protocol: data.protocol,
      bytes_transferred: data.bytes,
      packets_per_second: data.pps,
      geo_location: pick(GEO_LOCATIONS),
    },

    endpoint: {
      device_id: deviceId,
      hostname,
      os: pick(OS_LIST),
      process_name: pick(PROCESS_NAMES),
      process_id: randInt(1000, 65535),
      file_path: `C:\\Windows\\System32\\${pick(PROCESS_NAMES)}`,
      action: data.action,
      files_affected: data.filesAffected,
      risk_score: data.riskScore,
    },

    alert: {
      alert_id: `alert_${randInt(10000, 99999)}`,
      rule_name: data.ruleName,
      description: data.description,
      severity_hint: data.severityHint,
    },

    context: {
      previous_events_from_same_ip: randInt(0, 8),
      time_since_last_event_ms: randInt(100, 30000),
      is_known_bad_ip: data.isKnownBad,
      is_internal_ip: isInternal,
      correlated_event_ids: correlatedIds,
      environment: pick(ENVIRONMENTS),
    },
  };

  return event;
}

/* ─── Generate a Specific Target Threat Event ─── */
export function generateSpecificThreat(type) {
  let scenarioData;
  
  switch (type) {
    case 'Ransomware':
      scenarioData = {
        source: 'malware_signal',
        action: 'bulk_file_encrypt',
        riskScore: 98,
        filesAffected: 1450,
        isKnownBad: true,
        protocol: 'HTTPS',
        dstPort: 443,
        bytes: 2500000,
        pps: 120,
        ruleName: 'RANSOMWARE_ENCRYPT_BULK',
        description: 'Mass file encryption detected on endpoint - targeted scenario',
        severityHint: 'critical',
      };
      break;
      
    case 'DataExfiltration':
      scenarioData = {
        source: 'network_log',
        action: 'outbound_transfer',
        riskScore: 92,
        filesAffected: 1800,
        isKnownBad: true,
        protocol: 'HTTPS',
        dstPort: 443,
        bytes: 850_000_000,
        pps: 450,
        ruleName: 'DATA_EXFIL_LARGE_TRANSFER',
        description: 'Targeted: massive outbound data transfer to external IP',
        severityHint: 'critical',
      };
      break;

    case 'DDoS':
      scenarioData = {
        source: 'network_log',
        action: 'high_volume_noise',
        riskScore: 15,
        filesAffected: 0,
        isKnownBad: false,
        protocol: 'UDP',
        dstPort: 80,
        bytes: 250,
        pps: 15000,
        ruleName: 'DDoS_ATTACK_VOLUMETRIC',
        description: 'Volumetric DDoS targeting network service availability',
        severityHint: 'high',
      };
      break;

    case 'BruteForce':
      scenarioData = {
        source: 'intrusion_alert',
        action: 'brute_force_success',
        riskScore: 85,
        filesAffected: 0,
        isKnownBad: true,
        protocol: 'TCP',
        dstPort: 22,
        bytes: 15000,
        pps: 85,
        ruleName: 'AUTH_BRUTE_FORCE_SUCCESS',
        description: 'Targeted scenario: Brute force authentication gained',
        severityHint: 'high',
      };
      break;

    case 'Smokescreen':
      scenarioData = {
        source: 'network_log',
        action: 'high_volume_noise',
        riskScore: 5,
        filesAffected: 0,
        isKnownBad: false,
        protocol: 'ICMP',
        dstPort: 0,
        bytes: 64,
        pps: 9000,
        ruleName: 'NOISE_HIGH_VOLUME',
        description: 'High pps network traffic noise - possible distraction smokescreen',
        severityHint: 'low',
      };
      break;

    default:
      return generateThreatEvent();
  }

  const eventId = `evt_${String(++eventCounter).padStart(4, '0')}`;
  const isInternal = scenarioData.isInternal || false;
  const srcIp = isInternal ? pick(INTERNAL_IPS) : pick(EXTERNAL_IPS);
  const dstIp = isInternal ? pick(INTERNAL_IPS) : pick(INTERNAL_IPS);
  const hostname = pick(HOSTNAMES);
  const deviceId = pick(DEVICE_IDS);

  const event = {
    event_id: eventId,
    timestamp: new Date().toISOString(),
    source: scenarioData.source,

    network: {
      src_ip: srcIp,
      dst_ip: dstIp,
      src_port: randInt(1024, 65535),
      dst_port: scenarioData.dstPort,
      protocol: scenarioData.protocol,
      bytes_transferred: scenarioData.bytes,
      packets_per_second: scenarioData.pps,
      geo_location: pick(GEO_LOCATIONS),
    },

    endpoint: {
      device_id: deviceId,
      hostname,
      os: pick(OS_LIST),
      process_name: pick(PROCESS_NAMES),
      process_id: randInt(1000, 65535),
      file_path: `C:\\Windows\\System32\\${pick(PROCESS_NAMES)}`,
      action: scenarioData.action,
      files_affected: scenarioData.filesAffected,
      risk_score: scenarioData.riskScore,
    },

    alert: {
      alert_id: `alert_${randInt(10000, 99999)}`,
      rule_name: scenarioData.ruleName,
      description: scenarioData.description,
      severity_hint: scenarioData.severityHint,
    },

    context: {
      previous_events_from_same_ip: randInt(0, 8),
      time_since_last_event_ms: randInt(100, 30000),
      is_known_bad_ip: scenarioData.isKnownBad,
      is_internal_ip: isInternal,
      correlated_event_ids: [],
      environment: pick(ENVIRONMENTS),
    },
  };

  recentEventIds.push(eventId);
  if (recentEventIds.length > 20) recentEventIds.shift();

  return event;
}

