# CYBER INCIDENT PRIORITIZATION & SOC INTELLIGENCE PLATFORM (CIP-SOC)

**CIP-SOC** is an open-architecture, local defensive cybersecurity prototype that transforms raw security telemetry into a prioritized **Investigation Queue**. It solves alert fatigue by answering the fundamental SOC question:
*"Which alert or incident should the analyst investigate FIRST, WHY, and WHAT SHOULD THEY DO NEXT?"*

---

## 🌟 Core Product Capabilities & Differentiation

1. **Unified Telemetry Ingestion**: Ingests SIEM, EDR, Network, Auth, Firewall, Cloud, Email, and Vulnerability Scanner events into a **Canonical Event Schema**.
2. **SIEM & EDR Detection Engine**: 12 built-in rules mapped to MITRE ATT&CK techniques (Brute Force, Impossible Travel, Port Scan, Privilege Escalation, Suspicious PowerShell, Credential Attack, Data Exfiltration, Lateral Movement, Malware, Ransomware, Phishing, Cloud Anomaly).
3. **Multi-Signal Correlation**: Deduplicates identical events using sliding time window fingerprints and clusters related detections across host, user, IP, domain, and hash.
4. **6-Factor Explainable Risk Scoring Engine**:
   $$\text{Score} = 0.25 S_{\text{norm}} + 0.20 A_{\text{norm}} + 0.15 U_{\text{norm}} + 0.15 D_{\text{norm}} + 0.15 C_{\text{norm}} + 0.10 B_{\text{norm}}$$
   - **Severity** ($S$)
   - **Asset Importance** ($A$)
   - **Affected Users** ($U$)
   - **Data Sensitivity** ($D$)
   - **Attack Confidence** ($C$)
   - **Business Impact** ($B$)
5. **Dynamic Explainability**: Generates dynamic text narratives for **"Why #1?"** and a pairwise comparative delta matrix for **"Why #1 over #2?"**.
6. **Data Confidence vs Attack Confidence**: Identifies missing context and tracks uncertainty explicitly.
7. **Safe Response Simulation**: Interactive playbooks with **SIMULATION ONLY** status and mandatory **Human-in-the-Loop Approval Gates**. Zero real network or endpoint destruction.
8. **Analyst Ground-Truth Feedback**: Collects analyst triage labels (*Confirmed Incident, False Positive, Benign, Needs Investigation*) for model auditability.

---

## 🚀 Quickstart & How to Run

### Option 1: Native Local Execution

#### Backend (FastAPI)
```bash
cd backend
python -m pip install -r requirements.txt
python app/main.py
```
Backend server runs at `http://127.0.0.1:8000`. Swagger API docs available at `http://127.0.0.1:8000/api/v1/openapi.json`.

#### Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:3000` in your browser.

---

### Option 2: Docker Compose

```bash
docker-compose up --build
```
Access the application at `http://localhost:3000`.

---

## 🧪 Running Automated Tests

```bash
cd backend
python -m pytest tests/ -s -v
```
Runs the unit and integration test suite, including the mandatory **Critical Scoring Test (Alert A vs Alert B)** proving that **Severity ≠ Priority**.

---

## 📂 Project Structure

```
├── PLAN.md                   # Complete architectural requirements specification
├── ARCHITECTURE.md           # System architecture & Mermaid pipeline diagrams
├── SCORING.md                # Mathematical scoring formula & normalization logic
├── DETECTION_RULES.md        # Detection rules specification & MITRE mapping
├── API.md                    # REST API endpoint documentation
├── DEMO.md                   # Demo walkthrough & 10 canned attack scenarios
├── LIMITATIONS.md            # Boundary constraints & synthetic data disclosure
├── docker-compose.yml        # Docker orchestration definition
├── backend/
│   ├── app/
│   │   ├── api/v1/           # FastAPI routes (events, incidents, playbooks, analytics)
│   │   ├── db/               # SQLAlchemy models & database session
│   │   ├── models/           # Pydantic canonical & scoring schemas
│   │   └── services/         # Normalization, Detection, Correlation, RiskScoring, Explainability
│   ├── seed_data.py          # Data generator (500+ events, 30+ incidents, asset catalog)
│   └── tests/                # Pytest suite
└── frontend/                 # React 18, Vite, TypeScript, Tailwind CSS SOC Portal
```
