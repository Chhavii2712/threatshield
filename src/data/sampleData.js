/**
 * ThreatShield — Curated Sample Threat Scenarios
 *
 * Provides a set of static threat scenario definitions for testing, reference, or demo seeding.
 */

export const sampleThreatScenarios = [
  {
    event_id: "evt_sample_01",
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    source: "malware_signal",
    network: {
      src_ip: "91.219.236.174",
      dst_ip: "192.168.1.47",
      src_port: 50401,
      dst_port: 443,
      protocol: "HTTPS",
      bytes_transferred: 41250,
      packets_per_second: 3,
      geo_location: "Netherlands"
    },
    endpoint: {
      device_id: "HOSP-PC-014",
      hostname: "radiology-ws-14",
      os: "Windows 11 Pro",
      process_name: "svchost.exe",
      process_id: 4892,
      file_path: "C:\\Windows\\System32\\svchost.exe",
      action: "bulk_file_encrypt",
      files_affected: 847,
      risk_score: 95
    },
    alert: {
      alert_id: "alert_80321",
      rule_name: "RANSOMWARE_ENCRYPT_BULK",
      description: "Bulk file encryption pattern detected resembling known ransomware behavior.",
      severity_hint: "critical"
    },
    context: {
      previous_events_from_same_ip: 2,
      time_since_last_event_ms: 12000,
      is_known_bad_ip: true,
      is_internal_ip: false,
      correlated_event_ids: ["evt_sample_02", "evt_sample_03"],
      environment: "hospital"
    }
  },
  {
    event_id: "evt_sample_02",
    timestamp: new Date(Date.now() - 3612000).toISOString(),
    source: "network_log",
    network: {
      src_ip: "91.219.236.174",
      dst_ip: "192.168.1.47",
      src_port: 50400,
      dst_port: 443,
      protocol: "HTTPS",
      bytes_transferred: 2800,
      packets_per_second: 1,
      geo_location: "Netherlands"
    },
    endpoint: {
      device_id: "HOSP-PC-014",
      hostname: "radiology-ws-14",
      os: "Windows 11 Pro",
      process_name: "svchost.exe",
      process_id: 4892,
      file_path: "C:\\Windows\\System32\\svchost.exe",
      action: "outbound_call",
      files_affected: 0,
      risk_score: 82
    },
    alert: {
      alert_id: "alert_80319",
      rule_name: "MALWARE_C2_BEACON",
      description: "Periodic outbound communication with known C2 host.",
      severity_hint: "high"
    },
    context: {
      previous_events_from_same_ip: 1,
      time_since_last_event_ms: 60000,
      is_known_bad_ip: true,
      is_internal_ip: false,
      correlated_event_ids: [],
      environment: "hospital"
    }
  }
];
