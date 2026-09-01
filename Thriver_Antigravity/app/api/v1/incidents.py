from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from app.db.database import get_db
from app.db.models import IncidentModel, IncidentEventJunction, EventModel, DetectionModel, ThreatIntelModel, VulnerabilityModel
from app.services.ranking import RankingService
from app.services.explainability import ExplainabilityService
from app.services.risk_scoring import RiskScoringService

router = APIRouter(tags=["Incidents & Prioritization"])

@router.post("/prioritize")
def trigger_prioritization(db: Session = Depends(get_db)):
    """
    Triggers on-demand re-scoring and deterministic ranking of all active incidents.
    """
    sorted_incidents = RankingService.get_prioritized_incidents(db)
    return {
        "status": "SUCCESS",
        "processed_incidents": len(sorted_incidents),
        "top_incident_id": sorted_incidents[0].incident_id if sorted_incidents else None
    }

@router.get("/incidents")
def list_incidents(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Returns the Investigation Priority Queue deterministically ordered by risk score.
    """
    incidents = RankingService.get_prioritized_incidents(db)

    # Filtering
    if status:
        incidents = [i for i in incidents if i.status.upper() == status.upper()]
    if priority:
        incidents = [i for i in incidents if i.priority_level.upper() == priority.upper()]
    if search:
        s = search.lower()
        incidents = [
            i for i in incidents
            if s in i.title.lower() or s in i.incident_id.lower() or any(s in str(a).lower() for a in (i.affected_assets_json or []))
        ]

    result = []
    for rank, inc in enumerate(incidents, start=1):
        result.append({
            "rank": rank,
            "incident_id": inc.incident_id,
            "title": inc.title,
            "status": inc.status,
            "priority_score": inc.priority_score,
            "priority_level": inc.priority_level,
            "attack_confidence": inc.attack_confidence,
            "data_confidence": inc.data_confidence,
            "affected_assets": inc.affected_assets_json or [],
            "affected_users": inc.affected_users_json or [],
            "attack_types": inc.attack_types_json or [],
            "top_drivers": inc.top_drivers_json or [],
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "sla_deadline": inc.sla_deadline.isoformat() if inc.sla_deadline else None
        })

    return result

@router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    breakdown = RiskScoringService.calculate_incident_score(db, inc)

    # Get Threat Intel and Vulnerability Context
    threat_intel = []
    vulnerabilities = []

    for asset in (inc.affected_assets_json or []):
        vulns = db.query(VulnerabilityModel).filter(VulnerabilityModel.affected_asset_id == asset).all()
        for v in vulns:
            vulnerabilities.append({
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "known_exploited": v.known_exploited,
                "description": v.description
            })

    return {
        "incident_id": inc.incident_id,
        "title": inc.title,
        "status": inc.status,
        "priority_score": inc.priority_score,
        "priority_level": inc.priority_level,
        "attack_confidence": inc.attack_confidence,
        "data_confidence": inc.data_confidence,
        "affected_assets": inc.affected_assets_json,
        "affected_users": inc.affected_users_json,
        "attack_types": inc.attack_types_json,
        "mitre_techniques": inc.mitre_techniques_json,
        "business_impact": inc.business_impact,
        "data_sensitivity": inc.data_sensitivity,
        "related_alerts_count": len(inc.related_alerts_json or []),
        "top_drivers": inc.top_drivers_json,
        "explanation": inc.explanation,
        "attack_story": inc.attack_story,
        "recommended_playbook": inc.recommended_playbook,
        "assigned_analyst": inc.assigned_analyst,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "sla_deadline": inc.sla_deadline.isoformat() if inc.sla_deadline else None,
        "score_breakdown": breakdown.model_dump(),
        "vulnerabilities": vulnerabilities
    }

@router.get("/incidents/{incident_id}/explanation")
def get_incident_explanation(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return ExplainabilityService.explain_why_number_one(db, inc)

@router.get("/incidents/{incident_id}/compare-next")
def compare_incident_with_next(incident_id: str, db: Session = Depends(get_db)):
    sorted_incidents = RankingService.get_prioritized_incidents(db)
    
    current_idx = None
    for idx, inc in enumerate(sorted_incidents):
        if inc.incident_id == incident_id:
            current_idx = idx
            break

    if current_idx is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found in queue")

    if current_idx >= len(sorted_incidents) - 1:
        # Compare with previous if it's the last element
        if len(sorted_incidents) == 1:
            return {
                "incident_a_id": curr_inc.incident_id,
                "incident_a_title": curr_inc.title,
                "incident_a_score": curr_inc.priority_score,
                "incident_b_id": curr_inc.incident_id,
                "incident_b_title": curr_inc.title,
                "incident_b_score": curr_inc.priority_score,
                "score_gap": 0.0,
                "top_winning_factors": [],
                "factor_deltas": [],
                "summary_narrative": "Only one incident currently active in the queue. Multi-incident pairwise analysis requires at least two incidents."
            }
        next_inc = sorted_incidents[current_idx - 1]
    else:
        next_inc = sorted_incidents[current_idx + 1]

    curr_inc = sorted_incidents[current_idx]
    explanation = ExplainabilityService.compare_pairwise(db, curr_inc, next_inc)
    return explanation.model_dump()

@router.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str, db: Session = Depends(get_db)):
    junctions = db.query(IncidentEventJunction).filter(IncidentEventJunction.incident_id == incident_id).all()
    event_ids = [j.event_id for j in junctions]

    events = db.query(EventModel).filter(EventModel.event_id.in_(event_ids)).order_by(EventModel.timestamp.asc()).all()

    timeline = []
    for e in events:
        timeline.append({
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source": e.source,
            "event_type": e.event_type,
            "category": e.category,
            "severity": e.severity,
            "host": e.host,
            "user": e.user,
            "action_summary": f"[{e.source}] {e.event_type} on {e.host or 'system'} by user {e.user or 'N/A'}"
        })

    return {"incident_id": incident_id, "event_count": len(timeline), "timeline": timeline}

@router.get("/incidents/{incident_id}/evidence")
def get_incident_evidence(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    junctions = db.query(IncidentEventJunction).filter(IncidentEventJunction.incident_id == incident_id).all()
    event_ids = [j.event_id for j in junctions]

    events = db.query(EventModel).filter(EventModel.event_id.in_(event_ids)).all()
    detections = db.query(DetectionModel).filter(DetectionModel.detection_id.in_(inc.related_alerts_json or [])).all()

    return {
        "incident_id": incident_id,
        "title": inc.title,
        "detections": [
            {
                "detection_id": d.detection_id,
                "rule_name": d.rule_name,
                "mitre_technique": d.mitre_technique,
                "evidence": d.evidence_json
            }
            for d in detections
        ],
        "raw_events": [
            {
                "event_id": e.event_id,
                "source": e.source,
                "event_type": e.event_type,
                "process_name": e.process_name,
                "command_line": e.command_line,
                "source_ip": e.source_ip,
                "file_hash": e.file_hash
            }
            for e in events
        ]
    }
