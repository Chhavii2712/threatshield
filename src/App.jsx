/**
 * ThreatShield — Main App Component
 *
 * Coordinates state and renders the main grid layout containing all SOC dashboard components.
 */

import { useState } from 'react';
import { useThreatFeed } from './hooks/useThreatFeed';
import Header from './components/Header';
import StatsBar from './components/StatsBar';
import ThreatFeed from './components/ThreatFeed';
import ThreatDetail from './components/ThreatDetail';
import SeverityChart from './components/SeverityChart';
import ThreatTypeChart from './components/ThreatTypeChart';
import GeoMap from './components/GeoMap';
import ActivityTimeline from './components/ActivityTimeline';
import ResponseLog from './components/ResponseLog';
import AttackTriggerPanel from './components/AttackTriggerPanel';
import WebhookPanel from './components/WebhookPanel';
import './App.css';

export default function App() {
  const {
    events,
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
    togglePause,
    clearAll,
    changeSpeed,
    triggerSpecific,
  } = useThreatFeed();

  return (
    <div className="app-container grid-bg">
      <Header
        isRunning={isRunning}
        speed={speed}
        onTogglePause={togglePause}
        onSpeedChange={changeSpeed}
        onClear={clearAll}
        stats={stats}
      />

      <StatsBar stats={stats} />

      <main className="dashboard-grid">
        {/* Left Column: Real-time Live Feed */}
        <section className="grid-area--feed" aria-label="Live Threat Feed">
          <ThreatFeed
            events={events}
            selectedEvent={selectedEvent}
            onSelectEvent={setSelectedEvent}
            searchQuery={searchQuery}
            onSearchQueryChange={setSearchQuery}
          />
        </section>

        {/* Center/Right Grid Panel area */}
        <div className="dashboard-subgrid">
          {/* Top Row: Map, Severity Chart & Attack Trigger */}
          <section className="grid-area--map" aria-label="Global Threat Origins">
            <GeoMap geoData={geoData} />
          </section>

          <section className="grid-area--sev-chart" aria-label="Severity Distribution">
            <SeverityChart stats={stats} />
          </section>

          <section className="grid-area--trigger" aria-label="Targeted Attack Simulator">
            <AttackTriggerPanel onTrigger={triggerSpecific} />
          </section>

          {/* Bottom Row: Threat Type Chart & Timeline */}
          <section className="grid-area--type-chart" aria-label="Threat Types Breakdown">
            <ThreatTypeChart counts={threatTypeCounts} />
          </section>

          <section className="grid-area--timeline" aria-label="Mitigation Activity Timeline">
            <ActivityTimeline autoResponseLog={autoResponseLog} />
          </section>
        </div>

        {/* Slide-out or detail side panel */}
        <section className="grid-area--detail" aria-label="Threat Event Details">
          <ThreatDetail
            event={selectedEvent}
            onClose={() => setSelectedEvent(null)}
          />
        </section>
      </main>

      {/* Bottom Area: Response Log & Webhook Integrations */}
      <footer className="dashboard-footer">
        <div className="dashboard-footer-grid">
          <section className="grid-area--response-log" aria-label="Response Log Audit">
            <ResponseLog logs={autoResponseLog} />
          </section>
          
          <section className="grid-area--webhook" aria-label="Outbound Webhook Configurations">
            <WebhookPanel
              webhookUrl={webhookUrl}
              onUrlChange={setWebhookUrl}
              logs={webhookLogs}
            />
          </section>
        </div>
      </footer>
    </div>
  );
}

