from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid

from app.db.database import get_db
from app.db.models import CaseModel, IncidentModel, FeedbackModel, AuditLogModel
from app.services.playbook import PlaybookService
from app.services.audit import AuditService

router = APIRouter(tags=["Case Management & Playbooks"])

@router.get("/cases")
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(CaseModel).order_by(CaseModel.updated_at.desc()).all()
    result = []
    for c in cases:
        inc = db.query(IncidentModel).filter(IncidentModel.incident_id == c.incident_id).first()
        result.append({
            "case_id": c.case_id,
            "incident_id": c.incident_id,
            "title": inc.title if inc else "Unknown Incident",
            "status": c.status,
            "priority_score": inc.priority_score if inc else 0,
            "priority_level": inc.priority_level if inc else "MEDIUM",
            "assigned_analyst": c.assigned_analyst,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None
        })
    return result

@router.get("/cases/{case_id}")
def get_case_detail(case_id: str, db: Session = Depends(get_db)):
    case = db.query(CaseModel).filter((CaseModel.case_id == case_id) | (CaseModel.incident_id == case_id)).first()
    if not case:
        # Create case on demand if incident exists
        inc = db.query(IncidentModel).filter(IncidentModel.incident_id == case_id).first()
        if inc:
            case = CaseModel(case_id=f"CASE-{uuid.uuid4().hex[:8].upper()}", incident_id=inc.incident_id, status=inc.status)
            db.add(case)
            db.commit()
        else:
            raise HTTPException(status_code=404, detail=f"Case or Incident {case_id} not found")

    inc = db.query(IncidentModel).filter(IncidentModel.incident_id == case.incident_id).first()
    feedbacks = db.query(FeedbackModel).filter(FeedbackModel.incident_id == case.incident_id).all()

    return {
        "case_id": case.case_id,
        "incident_id": case.incident_id,
        "incident_title": inc.title if inc else "",
        "status": case.status,
        "assigned_analyst": case.assigned_analyst,
        "resolution_notes": case.resolution_notes,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "feedback_history": [
            {
                "feedback_id": f.feedback_id,
                "analyst": f.analyst,
                "decision": f.decision,
                "notes": f.notes,
                "timestamp": f.timestamp.isoformat() if f.timestamp else None
            }
            for f in feedbacks
        ]
    }

@router.patch("/cases/{case_id}/status")
def update_case_status(
    case_id: str,
    status: str = Body(..., embed=True),
    analyst: str = Body("analyst@soc.local", embed=True),
    notes: Optional[str] = Body(None, embed=True),
    db: Session = Depends(get_db)
):
    case = db.query(CaseModel).filter((CaseModel.case_id == case_id) | (CaseModel.incident_id == case_id)).first()
    if not case:
        inc = db.query(IncidentModel).filter(IncidentModel.incident_id == case_id).first()
        if inc:
            case = CaseModel(case_id=f"CASE-{uuid.uuid4().hex[:8].upper()}", incident_id=inc.incident_id, status=inc.status)
            db.add(case)
            db.commit()
        else:
            raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    case.status = status.upper()
    case.assigned_analyst = analyst
    case.updated_at = datetime.now(timezone.utc)
    if notes:
        case.resolution_notes = notes

    inc = db.query(IncidentModel).filter(IncidentModel.incident_id == case.incident_id).first()
    if inc:
        inc.status = status.upper()
        inc.updated_at = datetime.now(timezone.utc)

    db.commit()
    AuditService.log(db, action="CASE_STATUS_UPDATED", actor=analyst, entity="case", entity_id=case.case_id, details={"status": status})

    return {"status": "SUCCESS", "case_id": case.case_id, "new_status": case.status}

@router.post("/cases/{case_id}/feedback")
def submit_analyst_feedback(
    case_id: str,
    decision: str = Body(..., embed=True), # CONFIRMED_INCIDENT, FALSE_POSITIVE, BENIGN, NEEDS_INVESTIGATION
    analyst: str = Body("analyst@soc.local", embed=True),
    notes: Optional[str] = Body(None, embed=True),
    db: Session = Depends(get_db)
):
    case = db.query(CaseModel).filter((CaseModel.case_id == case_id) | (CaseModel.incident_id == case_id)).first()
    incident_id = case.incident_id if case else case_id

    fb = FeedbackModel(
        incident_id=incident_id,
        analyst=analyst,
        decision=decision.upper(),
        notes=notes,
        timestamp=datetime.now(timezone.utc)
    )
    db.add(fb)

    # Update case status based on feedback decision
    if decision.upper() == "FALSE_POSITIVE":
        if case: case.status = "FALSE_POSITIVE"
        inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
        if inc: inc.status = "FALSE_POSITIVE"
    elif decision.upper() == "CONFIRMED_INCIDENT":
        if case: case.status = "RESOLVED"
        inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
        if inc: inc.status = "RESOLVED"

    db.commit()
    AuditService.log(db, action="ANALYST_FEEDBACK_SUBMITTED", actor=analyst, entity="incident", entity_id=incident_id, details={"decision": decision})

    return {"status": "SUCCESS", "feedback_id": fb.feedback_id, "decision": fb.decision}

@router.get("/cases/{case_id}/playbook")
def get_recommended_playbook(case_id: str, db: Session = Depends(get_db)):
    case = db.query(CaseModel).filter((CaseModel.case_id == case_id) | (CaseModel.incident_id == case_id)).first()
    inc_id = case.incident_id if case else case_id
    inc = db.query(IncidentModel).filter(IncidentModel.incident_id == inc_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {inc_id} not found")

    return PlaybookService.get_playbook_for_incident(inc)

@router.post("/cases/{case_id}/playbook/simulate")
def simulate_playbook_action(
    case_id: str,
    action_name: str = Body(..., embed=True),
    playbook_id: str = Body(..., embed=True),
    approved: bool = Body(False, embed=True),
    analyst: str = Body("analyst@soc.local", embed=True),
    db: Session = Depends(get_db)
):
    case = db.query(CaseModel).filter((CaseModel.case_id == case_id) | (CaseModel.incident_id == case_id)).first()
    inc_id = case.incident_id if case else case_id

    result = PlaybookService.execute_playbook_step(
        db=db,
        incident_id=inc_id,
        playbook_id=playbook_id,
        action_name=action_name,
        analyst_name=analyst,
        approved=approved
    )
    return result
