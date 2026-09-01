# CIP-SOC REST API Documentation

Base URL: `http://localhost:8000/api/v1`

---

## Endpoints Summary

### Health & System
- `GET /health`: Returns system status and database connectivity.

### Ingestion & Telemetry
- `POST /events`: Ingest single raw telemetry log.
- `POST /events/bulk`: Ingest array of canonical events.
- `POST /events/upload-csv`: Upload raw event CSV file.
- `POST /ingest/webhook`: Webhook ingestion adapter.
- `GET /events`: Paginated list of normalized events.

### Detections & Detections Detail
- `GET /detections`: List triggered detections.
- `GET /detections/{id}`: Get detection detail by ID.

### Prioritization & Incidents
- `POST /prioritize`: Trigger on-demand re-scoring and queue ranking.
- `GET /incidents`: Get prioritized investigation queue.
- `GET /incidents/{id}`: Get incident details and score breakdown.
- `GET /incidents/{id}/explanation`: Get dynamic "Why #1?" explanation.
- `GET /incidents/{id}/compare-next`: Get pairwise comparison matrix against next incident.
- `GET /incidents/{id}/timeline`: Get chronological attack timeline.
- `GET /incidents/{id}/evidence`: Get correlated evidence and raw events.

### Cases, Playbooks & Feedback
- `GET /cases`: List case records.
- `GET /cases/{id}`: Case details and feedback history.
- `PATCH /cases/{id}/status`: Update case workflow status.
- `POST /cases/{id}/feedback`: Submit analyst feedback decision.
- `GET /cases/{id}/playbook`: Get recommended playbook for case.
- `POST /cases/{id}/playbook/simulate`: Execute simulated response action with approval check.

### Config & Analytics
- `GET /config/scoring`: Get active scoring weights and thresholds.
- `PUT /config/scoring`: Update scoring model weights and thresholds.
- `GET /analytics/summary`: Get SOC KPI summary, priority distribution, and noisy rules.

### Simulator & Demo
- `POST /demo/load`: Populate 500+ synthetic events, 30+ incidents, asset catalog.
- `POST /demo/reset`: Reset and re-initialize database.
- `POST /simulator/start`: Execute canned attack scenario (e.g. ransomware).
- `POST /simulator/stop`: Stop background simulation.
