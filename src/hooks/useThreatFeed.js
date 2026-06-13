/**
 * ThreatShield — useThreatFeed Hook
 *
 * Manages the real-time threat pipeline:
 * generator → analyzer → state → UI
 */

import { useState, useRef, useCallback, useEffect } from 'react';
import { generateThreatEvent, generateSpecificThreat } from '../data/threatGenerator';
import { analyzeThreat } from '../engine/threatAnalyzer';

const MAX_EVENTS = 200;
const SPEED_INTERVALS = { 1: 3000, 2: 1500, 5: 600 };

export function useThreatFeed() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    autoResponses: 0,
  });
  const [isRunning, setIsRunning] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('https://httpbin.org/post');
  const [webhookLogs, setWebhookLogs] = useState([]);
  const intervalRef = useRef(null);

  const dispatchWebhook = useCallback((analyzedEvent) => {
    if (!webhookUrl) return;

    const payload = {
      text: `🚨 *ThreatShield Auto-Response Triggered* 🚨\n*Event ID:* ${analyzedEvent.event_id}\n*Severity:* ${analyzedEvent.severity}\n*Threat Type:* ${analyzedEvent.threat_type}\n*Recommended Action:* ${analyzedEvent.recommended_action}\n*Affected Asset:* ${analyzedEvent.affected_asset}\n*Reasoning:* ${analyzedEvent.reasoning}`
    };

    const logEntry = {
      id: `wh_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      url: webhookUrl,
      payload,
      status: 'SENDING',
    };

    setWebhookLogs(prev => [logEntry, ...prev].slice(0, 50));

    fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then(res => {
        setWebhookLogs(prev =>
          prev.map(log =>
            log.id === logEntry.id ? { ...log, status: res.ok ? 'DELIVERED' : 'FAILED' } : log
          )
        );
      })
      .catch(() => {
        setWebhookLogs(prev =>
          prev.map(log =>
            log.id === logEntry.id ? { ...log, status: 'FAILED' } : log
          )
        );
      });
  }, [webhookUrl]);

  const processEvent = useCallback((customRawEvent = null) => {
    const rawEvent = customRawEvent || generateThreatEvent();
    const analyzed = analyzeThreat(rawEvent);

    setEvents((prev) => {
      const next = [analyzed, ...prev];
      return next.slice(0, MAX_EVENTS);
    });

    setStats((prev) => ({
      total: prev.total + 1,
      critical: prev.critical + (analyzed.severity === 'CRITICAL' ? 1 : 0),
      high: prev.high + (analyzed.severity === 'HIGH' ? 1 : 0),
      medium: prev.medium + (analyzed.severity === 'MEDIUM' ? 1 : 0),
      low: prev.low + (analyzed.severity === 'LOW' ? 1 : 0),
      autoResponses: prev.autoResponses + (analyzed.auto_respond ? 1 : 0),
    }));

    if (analyzed.auto_respond) {
      dispatchWebhook(analyzed);
    }
  }, [dispatchWebhook]);

  // Start/stop the feed
  useEffect(() => {
    if (isRunning) {
      // Generate a few initial events immediately
      for (let i = 0; i < 8; i++) {
        processEvent();
      }

      const interval = SPEED_INTERVALS[speed] || 3000;
      intervalRef.current = setInterval(processEvent, interval);
    }

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isRunning, speed, processEvent]);

  const pause = useCallback(() => setIsRunning(false), []);
  const resume = useCallback(() => setIsRunning(true), []);
  const togglePause = useCallback(() => setIsRunning((r) => !r), []);

  const clearAll = useCallback(() => {
    setEvents([]);
    setStats({ total: 0, critical: 0, high: 0, medium: 0, low: 0, autoResponses: 0 });
    setSelectedEvent(null);
  }, []);

  const changeSpeed = useCallback((newSpeed) => {
    setSpeed(newSpeed);
  }, []);

  const triggerSpecific = useCallback((type) => {
    const rawEvent = generateSpecificThreat(type);
    processEvent(rawEvent);
  }, [processEvent]);

  // Derived data with search filter applied
  const filteredEvents = events.filter((e) => {
    const query = searchQuery.toLowerCase();
    if (!query) return true;

    return (
      e.threat_type.toLowerCase().includes(query) ||
      e.affected_asset.toLowerCase().includes(query) ||
      e.severity.toLowerCase().includes(query) ||
      e.mitre_technique.toLowerCase().includes(query) ||
      (e._raw_event?.network?.src_ip || '').toLowerCase().includes(query) ||
      (e._raw_event?.network?.dst_ip || '').toLowerCase().includes(query)
    );
  });

  const threatTypeCounts = events.reduce((acc, e) => {
    acc[e.threat_type] = (acc[e.threat_type] || 0) + 1;
    return acc;
  }, {});

  const geoData = events.reduce((acc, e) => {
    const geo = e._raw_event?.network?.geo_location;
    if (geo) {
      acc[geo] = (acc[geo] || 0) + 1;
    }
    return acc;
  }, {});

  const autoResponseLog = events.filter((e) => e.auto_respond);

  return {
    events: filteredEvents,
    allEvents: events,
    stats,
    isRunning,
    speed,
    selectedEvent,
    threatTypeCounts,
    geoData,
    autoResponseLog,
    searchQuery,
    webhookUrl,
    webhookLogs,
    setSelectedEvent,
    setSearchQuery,
    setWebhookUrl,
    pause,
    resume,
    togglePause,
    clearAll,
    changeSpeed,
    triggerSpecific,
  };
}

