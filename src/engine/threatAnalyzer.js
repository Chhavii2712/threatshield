/**
 * ThreatShield — Threat Analysis Engine
 *
 * Classifies, scores, and recommends responses for incoming threat events.
 * Implements all rules from the ThreatShield specification.
 */

import { getMitreMapping } from './mitreMapping';

/* ─── Severity Levels (ordered) ─── */
const SEVERITY_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function upgradeSeverity(severity) {
  const idx = SEVERITY_LEVELS.indexOf(severity);
  if (idx < SEVERITY_LEVELS.length - 1) return SEVERITY_LEVELS[idx + 1];
  return severity;
}

/* ─── Threat Classification ─── */
function classifyThreat(event) {
  const action = event.endpoint?.action || '';
  const processName = event.endpoint?.process_name || '';
  const filesAffected = event.endpoint?.files_affected || 0;
  const riskScore = event.endpoint?.risk_score || 0;
  const bytesTransferred = event.network?.bytes_transferred || 0;
  const pps = event.network?.packets_per_second || 0;
  const protocol = event.network?.protocol || '';
  const dstPort = event.network?.dst_port || 0;
  const isKnownBad = event.context?.is_known_bad_ip || false;
  const isInternal = event.context?.is_internal_ip || false;
  const prevEvents = event.context?.previous_events_from_same_ip || 0;
  const source = event.source || '';

  // Ransomware — bulk file encryption, rapid write activity
  if (
    action.includes('encrypt') ||
    action.includes('file_encrypt') ||
    action.includes('bulk_file_encrypt')
  ) {
    return 'Ransomware';
  }
  if (filesAffected > 100 && action.includes('write')) {
    return 'Ransomware';
  }

  // DataExfiltration — large outbound transfer, unusual dst
  if (
    (bytesTransferred > 50_000_000 || filesAffected > 500) &&
    !isInternal &&
    (action.includes('outbound') || action.includes('transfer') || action.includes('upload'))
  ) {
    return 'DataExfiltration';
  }
  if (bytesTransferred > 100_000_000 && !isInternal) {
    return 'DataExfiltration';
  }

  // DDoS — massive packets_per_second
  if (pps > 10000) {
    return 'DDoS';
  }

  // BruteForce — repeated failed auth
  if (
    action.includes('failed_auth') ||
    action.includes('brute_force') ||
    action.includes('login_fail')
  ) {
    if (prevEvents >= 5 || filesAffected > 10) {
      return 'BruteForce';
    }
  }

  // LateralMovement — internal-to-internal spread
  if (isInternal && (action.includes('lateral') || action.includes('credential_reuse') || action.includes('remote_exec'))) {
    return 'LateralMovement';
  }

  // MalwareC2 — process calling known bad IP, beacon pattern
  if (isKnownBad && (action.includes('outbound_call') || action.includes('beacon') || source === 'malware_signal')) {
    return 'MalwareC2';
  }
  if (source === 'malware_signal' && riskScore > 70) {
    return 'MalwareC2';
  }

  // InsiderThreat — internal IP, privilege escalation, data hoarding
  if (
    isInternal &&
    (action.includes('privilege') || action.includes('escalat') || action.includes('data_hoard'))
  ) {
    return 'InsiderThreat';
  }

  // Phishing — suspicious DNS, credential harvesting
  if (
    action.includes('phish') ||
    action.includes('credential_harvest') ||
    (protocol === 'DNS' && action.includes('suspicious'))
  ) {
    return 'Phishing';
  }

  // Reconnaissance — port scanning, sequential port hits
  if (
    action.includes('port_scan') ||
    action.includes('recon') ||
    action.includes('probe')
  ) {
    return 'Reconnaissance';
  }

  // Smokescreen — low risk, high volume, no real payload
  if (riskScore < 20 && pps > 1000 && filesAffected === 0) {
    return 'Smokescreen';
  }

  // Fallback classification by source
  if (source === 'malware_signal') return 'MalwareC2';
  if (source === 'intrusion_alert' && prevEvents > 3) return 'BruteForce';
  if (source === 'intrusion_alert') return 'Reconnaissance';

  return 'Unknown';
}

/* ─── Base Severity Scoring ─── */
function scoreSeverity(threatType, event) {
  const riskScore = event.endpoint?.risk_score || 0;
  const filesAffected = event.endpoint?.files_affected || 0;
  const bytesTransferred = event.network?.bytes_transferred || 0;
  const isKnownBad = event.context?.is_known_bad_ip || false;
  const prevEvents = event.context?.previous_events_from_same_ip || 0;
  const action = event.endpoint?.action || '';
  const severityHint = event.alert?.severity_hint || '';

  // CRITICAL conditions
  if (threatType === 'Ransomware' && filesAffected > 0) return 'CRITICAL';
  if (threatType === 'DataExfiltration' && (bytesTransferred > 100_000_000 || filesAffected > 1000)) return 'CRITICAL';
  if (threatType === 'MalwareC2' && isKnownBad) return 'CRITICAL';
  if (threatType === 'LateralMovement' && prevEvents >= 3) return 'CRITICAL';

  // HIGH conditions
  if (threatType === 'Ransomware') return 'HIGH';
  if (threatType === 'DataExfiltration') return 'HIGH';
  if (threatType === 'BruteForce' && (action.includes('success') || action.includes('auth_gained'))) return 'HIGH';
  if (threatType === 'InsiderThreat' && action.includes('escalat')) return 'HIGH';
  if (threatType === 'LateralMovement') return 'HIGH';
  if (threatType === 'MalwareC2' && riskScore > 75) return 'HIGH';

  // MEDIUM conditions
  if (threatType === 'BruteForce') return 'MEDIUM';
  if (threatType === 'Reconnaissance') return 'MEDIUM';
  if (threatType === 'Phishing') return 'MEDIUM';
  if (threatType === 'MalwareC2') return 'MEDIUM';
  if (threatType === 'InsiderThreat') return 'MEDIUM';
  if (threatType === 'DDoS') return 'HIGH';

  // Smokescreen is always LOW
  if (threatType === 'Smokescreen') return 'LOW';

  // Use severity hint if available
  if (severityHint === 'critical') return 'CRITICAL';
  if (severityHint === 'high') return 'HIGH';
  if (severityHint === 'medium') return 'MEDIUM';

  return 'LOW';
}

/* ─── Confidence Scoring ─── */
function scoreConfidence(threatType, event) {
  let confidence = 50; // base

  const riskScore = event.endpoint?.risk_score || 0;
  const isKnownBad = event.context?.is_known_bad_ip || false;
  const correlated = event.context?.correlated_event_ids || [];
  const prevEvents = event.context?.previous_events_from_same_ip || 0;
  const filesAffected = event.endpoint?.files_affected || 0;

  // Risk score directly boosts confidence
  if (riskScore > 0) confidence = Math.max(confidence, riskScore);

  // Known bad IP = strong signal
  if (isKnownBad) confidence += 20;

  // Correlated events = confirmed pattern
  if (correlated.length > 0) confidence += 10 * Math.min(correlated.length, 3);

  // Previous events from same IP = persistence
  if (prevEvents > 3) confidence += 10;

  // High file count = clear activity
  if (filesAffected > 100) confidence += 10;

  // Unknown type = lower confidence
  if (threatType === 'Unknown') confidence = Math.min(confidence, 40);
  if (threatType === 'Smokescreen') confidence = Math.min(confidence, 30);

  return Math.min(100, Math.max(0, confidence));
}

/* ─── Priority Score (1–10) ─── */
function scorePriority(severity, confidence, threatType) {
  const severityWeight = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
  const base = severityWeight[severity] || 1;
  const confBoost = confidence > 80 ? 1 : confidence > 60 ? 0.5 : 0;
  let priority = Math.round(base + confBoost);

  if (threatType === 'Smokescreen') priority = Math.min(priority, 3);

  return Math.min(10, Math.max(1, priority));
}

/* ─── Recommended Action ─── */
function recommendAction(threatType, severity) {
  if (severity === 'CRITICAL') {
    if (threatType === 'Ransomware' || threatType === 'LateralMovement' || threatType === 'InsiderThreat') {
      return 'ISOLATE_DEVICE';
    }
    if (threatType === 'DDoS' || threatType === 'DataExfiltration') {
      return 'BLOCK_IP';
    }
    if (threatType === 'MalwareC2') {
      return 'KILL_PROCESS';
    }
    return 'ISOLATE_DEVICE';
  }

  if (severity === 'HIGH') {
    if (threatType === 'MalwareC2') return 'KILL_PROCESS';
    if (threatType === 'BruteForce' || threatType === 'DDoS') return 'BLOCK_IP';
    if (threatType === 'Ransomware' || threatType === 'LateralMovement') return 'ISOLATE_DEVICE';
    return 'BLOCK_IP';
  }

  if (severity === 'MEDIUM') return 'ESCALATE_TO_ANALYST';
  if (severity === 'LOW') return 'MONITOR';

  return 'MONITOR';
}

/* ─── Auto-Respond Flag ─── */
function shouldAutoRespond(action) {
  return ['BLOCK_IP', 'ISOLATE_DEVICE', 'KILL_PROCESS'].includes(action);
}

/* ─── Reasoning Generator ─── */
function generateReasoning(threatType, event, severity) {
  const hostname = event.endpoint?.hostname || 'unknown host';
  const processName = event.endpoint?.process_name || 'unknown process';
  const action = event.endpoint?.action || 'unknown action';
  const filesAffected = event.endpoint?.files_affected || 0;
  const srcIp = event.network?.src_ip || 'unknown IP';
  const dstIp = event.network?.dst_ip || 'unknown IP';
  const geo = event.network?.geo_location || 'unknown location';
  const isKnownBad = event.context?.is_known_bad_ip || false;
  const environment = event.context?.environment || 'unknown';
  const correlated = event.context?.correlated_event_ids || [];
  const bytesTransferred = event.network?.bytes_transferred || 0;
  const pps = event.network?.packets_per_second || 0;

  const parts = [];

  switch (threatType) {
    case 'Ransomware':
      parts.push(`${processName} is performing ${action} affecting ${filesAffected} files on ${hostname}.`);
      if (isKnownBad) parts.push(`The destination IP ${dstIp} (${geo}) is a known malicious C2 server.`);
      parts.push('This is a confirmed ransomware encryption attack requiring immediate device isolation.');
      break;

    case 'DataExfiltration':
      parts.push(`Large outbound data transfer detected: ${(bytesTransferred / 1_000_000).toFixed(1)}MB sent to ${dstIp} (${geo}).`);
      if (!event.context?.is_internal_ip) parts.push('The destination is an external IP, suggesting data theft in progress.');
      parts.push('Immediate action needed to prevent further data loss.');
      break;

    case 'DDoS':
      parts.push(`Extremely high traffic volume detected: ${pps.toLocaleString()} packets/sec from ${srcIp} (${geo}).`);
      parts.push('This pattern is consistent with a volumetric DDoS attack targeting network availability.');
      break;

    case 'BruteForce':
      parts.push(`Repeated authentication attempts detected from ${srcIp} targeting ${hostname}.`);
      if (action.includes('success')) parts.push('WARNING: At least one authentication attempt appears successful.');
      parts.push('This pattern indicates a credential brute-force attack.');
      break;

    case 'MalwareC2':
      parts.push(`${processName} on ${hostname} is communicating with ${dstIp} (${geo}).`);
      if (isKnownBad) parts.push('This IP is flagged as a known command-and-control server.');
      parts.push('The beacon pattern suggests active malware awaiting instructions.');
      break;

    case 'InsiderThreat':
      parts.push(`Internal user on ${hostname} (${srcIp}) is performing ${action}.`);
      parts.push(`This activity from an internal IP suggests potential insider threat or compromised account.`);
      break;

    case 'Phishing':
      parts.push(`Suspicious activity detected on ${hostname}: ${action}.`);
      parts.push('DNS patterns and credential harvesting indicators suggest an active phishing campaign.');
      break;

    case 'LateralMovement':
      parts.push(`Internal-to-internal spread detected: ${srcIp} → ${dstIp} via ${action}.`);
      parts.push('Credential reuse or remote execution across devices indicates lateral movement by an attacker.');
      break;

    case 'Reconnaissance':
      parts.push(`Port scanning or probing activity from ${srcIp} (${geo}) targeting ${hostname}.`);
      parts.push('This is likely an attacker mapping the network for exploitable services.');
      break;

    case 'Smokescreen':
      parts.push(`High-volume, low-impact activity detected from ${srcIp} — likely a distraction.`);
      parts.push('WARNING: Another, more dangerous attack may be in progress elsewhere. Analysts should investigate other endpoints.');
      break;

    default:
      parts.push(`Unclassified security event from ${srcIp} on ${hostname}.`);
      parts.push('The pattern does not match known threat signatures but warrants monitoring.');
      break;
  }

  // Add environment context
  if (environment === 'hospital' || environment === 'government') {
    parts.push(`Severity elevated due to ${environment} environment with high data sensitivity.`);
  }

  // Add correlation context
  if (correlated.length > 0) {
    parts.push(`This event correlates with ${correlated.length} related event(s), confirming a coordinated attack.`);
  }

  return parts.join(' ');
}

/* ─── Dashboard Summary (≤12 words) ─── */
function generateDashboardSummary(threatType, event, action) {
  const hostname = event.endpoint?.hostname || 'unknown';
  const actionLabels = {
    BLOCK_IP: 'IP blocked',
    ISOLATE_DEVICE: 'device isolated',
    KILL_PROCESS: 'process killed',
    ESCALATE_TO_ANALYST: 'escalated to analyst',
    MONITOR: 'monitoring',
    IGNORE: 'ignored',
  };
  const actionLabel = actionLabels[action] || 'investigating';

  const summaries = {
    Ransomware: `Ransomware encrypting ${hostname} — ${actionLabel}.`,
    DataExfiltration: `Data exfiltration from ${hostname} — ${actionLabel}.`,
    DDoS: `DDoS attack detected — ${actionLabel}.`,
    BruteForce: `Brute force on ${hostname} — ${actionLabel}.`,
    MalwareC2: `Malware C2 beacon from ${hostname} — ${actionLabel}.`,
    InsiderThreat: `Insider threat on ${hostname} — ${actionLabel}.`,
    Phishing: `Phishing attempt targeting ${hostname} — ${actionLabel}.`,
    LateralMovement: `Lateral movement via ${hostname} — ${actionLabel}.`,
    Reconnaissance: `Recon scan on ${hostname} — ${actionLabel}.`,
    Smokescreen: `Smokescreen activity — possible distraction tactic.`,
    Unknown: `Unclassified event on ${hostname} — ${actionLabel}.`,
  };

  return summaries[threatType] || `Security event on ${hostname} — ${actionLabel}.`;
}

/* ─── Escalation Note ─── */
function generateEscalationNote(threatType, event) {
  const hostname = event.endpoint?.hostname || 'unknown';
  const srcIp = event.network?.src_ip || 'unknown';

  const notes = {
    BruteForce: `Review auth logs on ${hostname} for successful logins from ${srcIp}. Check for credential compromise.`,
    Reconnaissance: `Analyze port scan patterns from ${srcIp}. Determine if any services are exposed and vulnerable.`,
    Phishing: `Inspect DNS queries and email logs for ${hostname}. Check if credentials were entered on suspicious domains.`,
    MalwareC2: `Verify if ${hostname} has been compromised. Check process trees and network connections for beacon patterns.`,
    InsiderThreat: `Review user activity logs on ${hostname}. Check for unusual file access patterns or privilege escalation.`,
    Smokescreen: `This appears to be a distraction. Prioritize investigation of other critical systems for concurrent attacks.`,
    Unknown: `Investigate event on ${hostname} from ${srcIp}. Determine if this is a false positive or emerging threat pattern.`,
  };

  return notes[threatType] || `Investigate suspicious activity on ${hostname} from ${srcIp}.`;
}


/* ════════════════════════════════════════
   MAIN ANALYSIS FUNCTION
   ════════════════════════════════════════ */

export function analyzeThreat(event) {
  // 1. Classify threat
  const threatType = classifyThreat(event);

  // 2. Base severity
  let severity = scoreSeverity(threatType, event);

  // 3. Environment multiplier
  const env = event.context?.environment || 'unknown';
  if (env === 'hospital' || env === 'government') {
    severity = upgradeSeverity(severity);
  }

  // 4. Cross-source correlation boost
  const correlated = event.context?.correlated_event_ids || [];
  if (correlated.length > 0) {
    severity = upgradeSeverity(severity);
  }

  // 5. Confidence
  const confidence = scoreConfidence(threatType, event);

  // 6. Priority
  const priorityScore = scorePriority(severity, confidence, threatType);

  // 7. Recommended action
  const recommendedAction = recommendAction(threatType, severity);

  // 8. Auto-respond flag
  const autoRespond = shouldAutoRespond(recommendedAction);

  // 9. MITRE mapping
  const mitre = getMitreMapping(threatType);

  // 10. Affected asset
  const hostname = event.endpoint?.hostname || event.network?.src_ip || 'unknown';
  const ip = event.network?.src_ip || '';
  const affectedAsset = ip ? `${hostname} (${ip})` : hostname;

  // 11. Reasoning
  const reasoning = generateReasoning(threatType, event, severity);

  // 12. Dashboard summary
  const dashboardSummary = generateDashboardSummary(threatType, event, recommendedAction);

  // 13. Escalation note
  const escalationNote =
    recommendedAction === 'ESCALATE_TO_ANALYST'
      ? generateEscalationNote(threatType, event)
      : null;

  return {
    event_id: event.event_id,
    threat_type: threatType,
    severity,
    confidence,
    priority_score: priorityScore,
    auto_respond: autoRespond,
    recommended_action: recommendedAction,
    affected_asset: affectedAsset,
    mitre_tactic: mitre.tactic,
    mitre_technique: mitre.technique,
    reasoning,
    dashboard_summary: dashboardSummary,
    escalation_note: escalationNote,
    // Extra fields for the dashboard
    _raw_event: event,
    _analyzed_at: new Date().toISOString(),
  };
}
