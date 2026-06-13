<div align="center">

# 🛡️ ThreatShield
### Autonomous AI-Powered Cyber Threat Response Framework

![ThreatShield Banner](public/icons.svg)

[![GitHub](https://img.shields.io/badge/GitHub-ThreatShield-black?style=for-the-badge&logo=github)](https://github.com/Chhavii2712/threatshield)
[![Built With React](https://img.shields.io/badge/Built%20With-React-61DAFB?style=for-the-badge&logo=react)](https://react.dev)

> **Hackathon Submission** — Problem Statement 1: *"Develop an intelligent threat-response framework that autonomously prioritizes and mitigates cyber threats in real time"*

</div>

---

## 🚨 The Problem

In cybersecurity, when an organization gets attacked, **thousands of threat alerts can fire simultaneously**. Security teams get overwhelmed — they can't manually read, prioritize, and respond to all of them in time. Attackers exploit this delay.

A ransomware attack that isn't contained in the first 60 seconds can encrypt an entire hospital network. A data exfiltration attempt that goes unnoticed for 10 minutes can leak thousands of patient records.

**The bottleneck is human response time. ThreatShield removes it.**

---

## ✅ The Solution

ThreatShield is a real-time SOC (Security Operations Center) dashboard that:

- 🧠 **Intelligently scores** every incoming threat using AI — severity, confidence, threat type, MITRE ATT&CK mapping
- ⚡ **Autonomously responds** to HIGH and CRITICAL threats — no human needed
- 📊 **Visualizes** everything live — threat feed, severity charts, geo origins, mitigation log
- 🔗 **Integrates** with external platforms via webhook — Slack, PagerDuty, SIEM tools

---

## 🎯 Problem Statement vs ThreatShield

| Requirement | How ThreatShield delivers |
|---|---|
| **Intelligent** | AI engine classifies 11 threat types, explains reasoning in plain English |
| **Autonomously prioritizes** | Every threat scored 1–10 with LOW / MEDIUM / HIGH / CRITICAL severity |
| **Autonomously mitigates** | BLOCK IP, ISOLATE DEVICE, KILL PROCESS fire without human input |
| **Real time** | Live event stream, live mitigation timeline, live audit trail |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  THREAT DATA SOURCES                │
│   Network Logs │ Intrusion Alerts │ Malware Signals │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│              threatGenerator.js                     │
│         Simulates realistic threat events           │
│         every 800ms across all 3 sources            │
└──────────────────────┬──────────────────────────────┘
                       │  Raw Event JSON
                       ▼
┌─────────────────────────────────────────────────────┐
│              threatAnalyzer.js                      │
│         AI Scoring & Classification Engine          │
│   • Classifies into 11 threat types                 │
│   • Assigns severity (LOW→CRITICAL)                 │
│   • Maps to MITRE ATT&CK framework                  │
│   • Determines auto-response action                 │
└──────────────────────┬──────────────────────────────┘
                       │  Analysis Result JSON
                       ▼
┌─────────────────────────────────────────────────────┐
│              useThreatFeed.js                       │
│         React State Management Hook                 │
└──┬───────────┬──────────┬──────────┬───────────┬───┘
   │           │          │          │           │
   ▼           ▼          ▼          ▼           ▼
Header      StatsBar  ThreatFeed  SeverityChart  GeoMap
Controls    Counters  Live cards  Donut chart    World map

                    ThreatFeed
                       │ Click
                       ▼
                  ThreatDetail
                  Slide panel
```

---

## ⚙️ Features

### 🔴 Live Threat Feed
Real-time stream of classified threat events — color-coded by severity, searchable by IP, host, severity, or MITRE technique.

### 📊 Severity Distribution
Live donut chart showing the split between CRITICAL, HIGH, MEDIUM, and LOW threats as they come in.

### 🗺️ Global Threat Origins
World map tracking geographic sources of attacks in real time — identifies which countries threats are originating from.

### 🤖 Autonomous Mitigation Engine
HIGH and CRITICAL threats trigger instant responses:
- **BLOCK IP** → Cuts off malicious source at firewall level
- **KILL PROCESS** → Terminates attacking process on endpoint
- **ISOLATE DEVICE** → Removes infected machine from network

### 🎯 Targeted Attack Simulator
Trigger real-world attack scenarios on demand:
- Ransomware Chain
- Data Exfiltration Transfer
- DDoS Storm
- Brute Force Entry
- Smokescreen Noise

### 📋 Mitigation Response Log
Full audit trail — every automated action logged with event ID, action type, target asset, severity, MITRE technique, and execution status.

### 🔗 Outbound Integrations
Every auto-response dispatched via webhook to external platforms (Slack, PagerDuty, SIEM) with a live delivery audit trail.

### 🧩 MITRE ATT&CK Mapping
Every threat mapped to the MITRE ATT&CK framework — tactic and technique ID shown on every event and response log entry.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19 + Vite |
| Styling | CSS Modules |
| AI Engine | Custom threat analyzer (rule-based + ML scoring) |
| Data | Simulated threat generator |
| Real-time | React state + interval hooks |
| Charts | Custom SVG components |
| Deployment | Vercel |

---

## 🚀 Getting Started

```bash
# Clone the repository
git clone https://github.com/Chhavii2712/threatshield.git
cd threatshield

# Install dependencies
npm install

# Start the development server
npm run dev
```

Open `http://localhost:5173` and watch threats roll in.

---

## 📁 Project Structure

```
threatshield/
├── src/
│   ├── components/
│   │   ├── Header.jsx            # Top nav — live indicator, speed controls
│   │   ├── StatsBar.jsx          # Event counters — total, critical, auto-responses
│   │   ├── ThreatFeed.jsx        # Live scrolling threat list
│   │   ├── ThreatDetail.jsx      # Click-to-expand threat detail panel
│   │   ├── SeverityChart.jsx     # Donut chart — severity distribution
│   │   ├── ThreatTypeChart.jsx   # Bar chart — threat classification breakdown
│   │   ├── GeoMap.jsx            # World map — global threat origins
│   │   ├── ActivityTimeline.jsx  # Mitigation timeline
│   │   ├── ResponseLog.jsx       # Full mitigation response log table
│   │   ├── AttackTriggerPanel.jsx # Targeted attack simulator
│   │   └── WebhookPanel.jsx      # Outbound integrations + audit trail
│   ├── data/
│   │   ├── threatGenerator.js    # Simulates realistic threat events
│   │   └── sampleData.js         # Seed data and constants
│   ├── engine/
│   │   ├── threatAnalyzer.js     # Core AI scoring and classification
│   │   └── mitreMapping.js       # MITRE ATT&CK technique database
│   ├── hooks/
│   │   └── useThreatFeed.js      # React hook — manages live threat state
│   ├── App.jsx
│   └── main.jsx
├── public/
├── index.html
└── README.md
```

---
Screenshots:

<img width="1918" height="917" alt="image" src="https://github.com/user-attachments/assets/0308ebdc-efb6-4ed1-ab56-dae9c307a130" />

<img width="1915" height="906" alt="image" src="https://github.com/user-attachments/assets/8ac07bda-49e2-4def-9c94-d08eb78a90df" />

<img width="1917" height="900" alt="image" src="https://github.com/user-attachments/assets/c1651388-18f4-41eb-9458-c2b19b35a24b" />

<img width="1912" height="892" alt="image" src="https://github.com/user-attachments/assets/a30311ef-6c68-460f-97c8-93bdcf817954" />


---


## 👥 Team — High Five AI

Chhavi Dubey · Shreya Kumar · Sakshi Singh · Aditi Choudhary · Divya Krishna

---

## 🏆 Hackathon

Built at **NEURO NEX'26** · June 2026

**Theme:** Neuromorphism in Cyber
**Problem Statement:** *"Develop an intelligent threat-response framework that autonomously prioritizes and mitigates cyber threats in real time"*

---

<div align="center">
Made with ❤️ and a lot of ☕
</div>
