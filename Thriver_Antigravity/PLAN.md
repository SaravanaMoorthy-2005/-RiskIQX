# CYBER INCIDENT PRIORITIZATION & SOC INTELLIGENCE PLATFORM (CIP-SOC)
## Comprehensive Architecture & Implementation Master Plan

---

### 1. Project Overview & Vision

**CIP-SOC** is an enterprise-grade, open-architecture SOC Intelligence and Alert Prioritization Platform designed to eliminate alert fatigue and solve the core SOC challenge:
*"Which security alert or incident should an analyst investigate FIRST, WHY, and WHAT SHOULD THEY DO NEXT?"*

The system ingests raw security telemetry from heterogeneous security controls (SIEM, EDR, IDS/IPS, Firewalls, Auth Systems, Cloud, Email, Vulnerability Scanners, Threat Intel), normalizes them into a **Canonical Event Model**, evaluates them through a **SIEM Detection Engine**, enriches them with multi-dimensional context (Asset Tiers, User Privilege, Threat Intel, CVE Vulnerability Context), deduplicates and correlates multi-signal events into **Incidents**, calculates a **6-Factor Explainable Contextual Risk Score**, deterministically ranks incidents in an **Investigation Priority Queue**, generates dynamic **Pairwise Explanations ("Why #1?" and "Why #1 over #2?")**, maps techniques to **MITRE ATT&CK**, provides **Simulation-Only Playbook Executions** with **Human-in-the-Loop Approval Gates**, and records **Analyst Feedback** for future model learning.

---

### 2. Functional & Non-Functional Requirements

#### Functional Requirements
1. **Unified Event Ingestion**: JSON, CSV upload, REST webhook, bulk ingestion, demo scenario generator.
2. **Canonical Event Model**: Normalizes disparate telemetry into a unified Pydantic schema with standard fields (IPs, users, hashes, asset criticality, security category, raw payload).
3. **SIEM & EDR Detections**: 12+ built-in detection rules (Brute Force, Impossible Travel, Port Scan, Privilege Escalation, Suspicious PowerShell, Credential Attack, Data Exfiltration, Lateral Movement, Malware, Ransomware, Phishing, Cloud Anomaly).
4. **Context Enrichment Services**:
   - Threat Intel Provider (IP/Domain/Hash reputation matching).
   - Asset Intelligence Inventory (Tier 1-4 criticality, business functions, internet-facing status).
   - User Intelligence Directory (Roles, Privileged Status, VIP status).
   - Vulnerability Scanner Context (CVEs, CVSS scores, exploitability status).
5. **Deduplication & Correlation Engines**: Fingerprint-based event deduplication sliding windows; multi-signal clustering across host, user, IP, hash, domain, and attack technique.
6. **6-Factor Risk Scoring Engine**:
   - $\text{Score} = w_{\text{sev}} S_{\text{norm}} + w_{\text{asset}} A_{\text{norm}} + w_{\text{users}} U_{\text{norm}} + w_{\text{data}} D_{\text{norm}} + w_{\text{conf}} C_{\text{norm}} + w_{\text{biz}} B_{\text{norm}}$
   - Default Weights: Severity (0.25), Asset Importance (0.20), Affected Users (0.15), Data Sensitivity (0.15), Attack Confidence (0.15), Business Impact (0.10). Must sum to 1.0.
   - Separate **Attack Confidence** from **Data Confidence** (identifying missing factors / uncertainty).
7. **Ranking & Explainability Engine**: Deterministic multi-tier sort; dynamic text explanation for #1 incident and pairwise comparative matrix against #2 incident.
8. **Case & Playbook Workflow**: Workflow states (NEW -> TRIAGED -> INVESTIGATING -> CONTAINMENT_RECOMMENDED -> AWAITING_APPROVAL -> RESOLVED / FALSE_POSITIVE). Interactive Playbooks with SIMULATION-ONLY response actions and explicit Human Approval required.
9. **Analyst Feedback & Model Versioning**: Record analyst decisions (Confirmed Incident, False Positive, Benign, Needs Investigation); audit logs; versioned scoring configurations (e.g., `weighted-v1`).
10. **Simulator & Live SOC Streaming**: 10 canned attack scenario generators + real-time background event emitter via WebSockets/SSE.

#### Non-Functional Requirements
1. **Performance**: Ingest and process 1,000+ events per batch under 2 seconds without $O(n^2)$ bottlenecks.
2. **Safety Boundary**: Zero destructive commands executed on real systems; 100% simulated response recommendations with approval gates.
3. **Usability & Aesthetic**: Modern, dark SOC-themed UI (React + Tailwind CSS + Lucide icons + Recharts) with high information density, clear visual hierarchy, and readable typography.
4. **Reproducibility & Testability**: 100% deterministic scoring, automated pytest suite covering unit, integration, and edge cases (including the critical Alert A vs Alert B test).

---

### 3. Database Schema (SQLite / SQLAlchemy)

The database model consists of 14 primary entities:

1. `events`: Raw & canonical normalized security events.
2. `detections`: Rules triggered from normalized events.
3. `assets`: Entity inventory with asset tiers (Tier 1-4), criticality, internet-facing flag.
4. `users`: Identity context (roles, privileged flag, VIP flag, department).
5. `threat_intelligence`: Synthetic IOC database (IPs, domains, hashes, malware families).
6. `vulnerabilities`: Vulnerability registry mapped to assets (CVE, CVSS, exploit status).
7. `incidents`: Correlated cluster of detections with calculated risk scores, priority level, confidence metrics, and story narrative.
8. `incident_events`: Junction table connecting incidents to canonical events.
9. `cases`: Lifecycle case management records linked to incidents.
10. `playbook_runs`: Executed simulated playbook steps and approval logs.
11. `feedback`: Analyst decision logs with ground-truth labels and notes.
12. `scoring_models`: Configuration versions for weights, thresholds, and parameters.
13. `score_calculations`: Granular factor-by-factor breakdown per incident calculation.
14. `audit_logs`: Complete audit trail of system activities and state transitions.

---

### 4. REST API Endpoint Specifications

- **Health & System**: `GET /api/v1/health`
- **Events & Ingestion**:
  - `POST /api/v1/events`
  - `POST /api/v1/events/bulk`
  - `GET /api/v1/events`
  - `POST /api/v1/ingest/webhook`
- **Detections**:
  - `GET /api/v1/detections`
  - `GET /api/v1/detections/{id}`
- **Prioritization & Incidents**:
  - `POST /api/v1/prioritize`
  - `GET /api/v1/incidents`
  - `GET /api/v1/incidents/{id}`
  - `GET /api/v1/incidents/{id}/explanation`
  - `GET /api/v1/incidents/{id}/compare-next`
  - `GET /api/v1/incidents/{id}/timeline`
  - `GET /api/v1/incidents/{id}/evidence`
- **Cases, Playbooks & Feedback**:
  - `GET /api/v1/cases`
  - `GET /api/v1/cases/{id}`
  - `PATCH /api/v1/cases/{id}/status`
  - `POST /api/v1/cases/{id}/feedback`
  - `GET /api/v1/cases/{id}/playbook`
  - `POST /api/v1/cases/{id}/playbook/simulate`
- **Config & Analytics**:
  - `GET /api/v1/config/scoring`
  - `PUT /api/v1/config/scoring`
  - `GET /api/v1/analytics/summary`
- **Demo & Live Simulation**:
  - `POST /api/v1/demo/load`
  - `POST /api/v1/demo/reset`
  - `POST /api/v1/simulator/start`
  - `POST /api/v1/simulator/stop`
  - `WS /api/v1/ws/live-soc`

---

### 5. Development Strategy & Definition of Done

#### Implementation Phases
- **Phase 1**: Database models, Alembic migrations, Canonical Event Schema.
- **Phase 2**: Normalization service, Ingestion endpoints, Synthetic Seed Generator (500+ events, 30+ incidents).
- **Phase 3**: Detection Engine (12 rules), Threat Intel, Asset, User & Vulnerability Context Providers.
- **Phase 4**: Deduplication & Multi-Signal Correlation Engine.
- **Phase 5**: 6-Factor Risk Scoring, Data Confidence & Uncertainty Engine, Ranking Engine, Dynamic Pairwise Explainability Engine.
- **Phase 6**: Case Management, Playbook Engine (Simulation + Human Approval Gates), Analyst Feedback API.
- **Phase 7**: Full React + TypeScript Frontend (Investigation Queue, Incident Detail, SOC Dashboard, Analytics, Config Page, Simulator Controls).
- **Phase 8**: Automated Pytest Test Suite, Docker Compose orchestration, End-to-End verification.

#### Definition of Done Checklist
- All backend unit/integration tests pass.
- Frontend builds cleanly without TypeScript or React errors.
- System starts with single `docker-compose up --build` command.
- Real end-to-end workflow verified (Ingest -> Detect -> Enrich -> Deduplicate -> Correlate -> Score -> Explain -> Playbook -> Feedback).
