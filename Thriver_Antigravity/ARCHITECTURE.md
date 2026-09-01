# CIP-SOC Architecture Specifications

This document outlines the complete architectural design and data pipelines for the **Cyber Incident Prioritization & SOC Intelligence Platform (CIP-SOC)**.

---

## 1. System Architecture

```mermaid
flowchart TD
    subgraph Security Sources
        S1[SIEM Telemetry]
        S2[EDR Telemetry]
        S3[Network / Firewall / IDS]
        S4[Auth / Cloud / Email]
    end

    subgraph Ingestion Layer
        ING[Ingestion API & Webhooks]
        GEN[Demo Scenario Generator]
    end

    subgraph Core Processing Pipeline
        NORM[Normalization Service]
        DET[Rule-Based Detection Engine]
        ENRICH[Context Enrichment Service]
        DEDUP[Deduplication Engine]
        CORR[Multi-Signal Correlation Engine]
    end

    subgraph Context & Intelligence Providers
        TI[Threat Intel DB]
        ASSET[Asset Inventory]
        USER[User Context Directory]
        VULN[Vulnerability Scanner Context]
    end

    subgraph Prioritization & Analytics Engine
        RISK[6-Factor Risk Scoring Engine]
        UNCERT[Data Confidence & Uncertainty Engine]
        RANK[Deterministic Ranking Engine]
        EXPLAIN[Dynamic Explainability Engine]
    end

    subgraph Workflow & Response Engine
        INC[Incident & Case Management]
        PLAY[Simulated Playbook Engine]
        FEEDBACK[Analyst Feedback Store]
    end

    subgraph User Interface
        UI[React SOC Portal]
        QUEUE[Investigation Priority Queue]
        DASH[SOC Dashboard]
    end

    S1 --> ING
    S2 --> ING
    S3 --> ING
    S4 --> ING
    GEN --> ING
    ING --> NORM
    NORM --> DET
    DET --> ENRICH
    TI --> ENRICH
    ASSET --> ENRICH
    USER --> ENRICH
    VULN --> ENRICH
    ENRICH --> DEDUP
    DEDUP --> CORR
    CORR --> RISK
    RISK --> UNCERT
    UNCERT --> RANK
    RANK --> EXPLAIN
    EXPLAIN --> INC
    INC --> PLAY
    PLAY --> FEEDBACK
    INC --> UI
    QUEUE --> UI
    DASH --> UI
```

---

## 2. Event Pipeline

```mermaid
flowchart LR
    A[Raw Log Payload] --> B[Ingestion Adapter]
    B --> C[Canonical Schema Transformer]
    C --> D{Validation Passed?}
    D -- No --> E[Quarantine / Error Log]
    D -- Yes --> F[Normalized Canonical Event]
    F --> G[Database Event Table]
    F --> H[Detection Engine Queue]
```

---

## 3. Detection Pipeline

```mermaid
flowchart TD
    A[Normalized Event] --> B[Rule Matching Engine]
    B --> C{Rules Matched?}
    C -- No --> D[Pass Through / Log Event]
    C -- Yes --> E[Generate Detection Object]
    E --> F[Attach MITRE ATT&CK Mapping]
    F --> G[Assign Initial Rule Severity & Confidence]
    G --> H[Store Detections]
```

---

## 4. Correlation Pipeline

```mermaid
flowchart TD
    A[Raw Detections] --> B[Deduplication Fingerprinting]
    B --> C{Fingerprint Match in Sliding Window?}
    C -- Yes --> D[Increment Duplicate Counter]
    C -- No --> E[New Unique Detection]
    E --> F[Correlation Clustering Engine]
    F --> G{Match Correlation Keys?}
    G -- Host/User/IP/Hash/Domain --> H[Group into Existing Incident]
    G -- No Match --> I[Create New Incident Cluster]
```

---

## 5. Risk Scoring Pipeline

```mermaid
flowchart TD
    A[Incident Cluster] --> B[Fetch Contextual Factors]
    B --> C[Severity: 0-100]
    B --> D[Asset Importance: Tier 1-4 -> 0-100]
    B --> E[Affected Users: Logarithmic Norm]
    B --> F[Data Sensitivity: 0-100]
    B --> G[Attack Confidence: 0-100]
    B --> H[Business Impact: 0-100]
    
    C --> I[Multiply by Weights]
    D --> I
    E --> I
    F --> I
    G --> I
    H --> I
    
    I --> J[Sum Contributions & Clamp 0-100]
    J --> K[Assign Priority Level: Critical / High / Med / Low]
    J --> L[Calculate Data Confidence & Uncertainty]
```

---

## 6. Incident Lifecycle

```mermaid
stateDiagram-v2
    [*] --> NEW: Event Correlation & Scoring
    NEW --> TRIAGED: Analyst Opens Queue Item
    TRIAGED --> INVESTIGATING: Deep Dive Evidence
    INVESTIGATING --> CONTAINMENT_RECOMMENDED: Playbook Executed
    CONTAINMENT_RECOMMENDED --> AWAITING_APPROVAL: High-Impact Safe Action
    AWAITING_APPROVAL --> RESOLVED: Analyst Approves & Confirms
    INVESTIGATING --> FALSE_POSITIVE: Feedback Submitted
    RESOLVED --> [*]
    FALSE_POSITIVE --> [*]
```

---

## 7. Analyst Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant UI as React UI Queue
    participant API as FastAPI Gateway
    participant Rank as Ranking Service
    participant Explain as Explainability Engine
    participant Play as Playbook Engine

    Analyst->>UI: Opens SOC Portal
    UI->>API: GET /api/v1/incidents
    API->>Rank: Query Sorted Incidents
    Rank-->>UI: Return Prioritized Queue (#1, #2, ...)
    Analyst->>UI: Selects #1 Incident
    UI->>API: GET /api/v1/incidents/{id}/explanation
    API->>Explain: Generate Dynamic "Why #1?" & "Why Over #2"
    Explain-->>UI: Score Decomposition & Pairwise Matrix
    Analyst->>UI: Reviews Evidence & Attack Story
    Analyst->>UI: Triggers Recommended Playbook Action
    UI->>API: POST /api/v1/cases/{id}/playbook/simulate
    API->>Play: Simulate Action (Approval Gate Warning)
    Play-->>UI: Simulation Result (No Real Execution)
    Analyst->>UI: Submits Feedback & Resolves Case
    UI->>API: POST /api/v1/cases/{id}/feedback
    API-->>Analyst: Case Closed & Feedback Logged
```
