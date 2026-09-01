from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from app.db.database import get_db
from app.db.models import DetectionModel

router = APIRouter(tags=["Detections"])

@router.get("/detections", response_model=List[Dict[str, Any]])
def list_detections(
    limit: int = Query(100, le=1000),
    offset: int = 0,
    category: str = None,
    db: Session = Depends(get_db)
):
    query = db.query(DetectionModel)
    if category:
        query = query.filter(DetectionModel.category == category)

    detections = query.order_by(DetectionModel.created_at.desc()).offset(offset).limit(limit).all()

    return [
        {
            "detection_id": d.detection_id,
            "rule_id": d.rule_id,
            "rule_name": d.rule_name,
            "category": d.category,
            "severity": d.severity,
            "confidence": d.confidence,
            "mitre_technique": d.mitre_technique,
            "mitre_name": d.mitre_name,
            "evidence": d.evidence_json,
            "event_ids": d.event_ids_json,
            "created_at": d.created_at.isoformat() if d.created_at else None
        }
        for d in detections
    ]

@router.get("/detections/{detection_id}")
def get_detection(detection_id: str, db: Session = Depends(get_db)):
    det = db.query(DetectionModel).filter(DetectionModel.detection_id == detection_id).first()
    if not det:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found")
    return {
        "detection_id": det.detection_id,
        "rule_id": det.rule_id,
        "rule_name": det.rule_name,
        "category": det.category,
        "severity": det.severity,
        "confidence": det.confidence,
        "description": det.description,
        "evidence": det.evidence_json,
        "mitre_technique": det.mitre_technique,
        "mitre_name": det.mitre_name,
        "event_ids": det.event_ids_json,
        "created_at": det.created_at.isoformat() if det.created_at else None
    }
