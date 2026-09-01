from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import csv
import io
import json

from app.db.database import get_db
from app.models.canonical import CanonicalEvent, BulkIngestRequest, IngestResponse
from app.services.normalization import EventNormalizationService
from app.services.enrichment import EnrichmentService
from app.services.detection import DetectionEngine
from app.services.deduplication import DeduplicationService
from app.services.correlation import CorrelationEngine
from app.services.ranking import RankingService
from app.services.audit import AuditService
from app.db.models import EventModel

router = APIRouter(tags=["Events & Ingestion"])

@router.post("/events", response_model=Dict[str, Any])
def ingest_single_event(raw_event: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Ingests, normalizes, enriches, deduplicates, runs detections, and correlates a single raw telemetry event.
    """
    normalized = EventNormalizationService.normalize(raw_event)
    EnrichmentService.enrich_event(db, normalized)

    db_event = EventModel(**normalized.model_dump(exclude_none=True))
    db.add(db_event)
    db.flush()

    DeduplicationService.check_and_deduplicate(db, db_event)
    db.commit()

    detections = DetectionEngine.evaluate_event(db, db_event)
    incidents = CorrelationEngine.correlate_detections(db, detections) if detections else []

    if incidents:
        RankingService.get_prioritized_incidents(db)

    AuditService.log(db, action="EVENT_INGESTED", entity="event", entity_id=db_event.event_id)

    return {
        "status": "SUCCESS",
        "event_id": db_event.event_id,
        "is_duplicate": db_event.is_duplicate,
        "detections_count": len(detections),
        "incidents_affected": len(incidents)
    }

@router.post("/events/bulk", response_model=IngestResponse)
def ingest_bulk_events(payload: BulkIngestRequest, db: Session = Depends(get_db)):
    """
    Bulk event ingestion endpoint handling batch JSON events.
    """
    total_received = len(payload.events)
    normalized_count = 0
    duplicate_count = 0
    total_detections = []
    affected_incidents = []

    for event_data in payload.events:
        EnrichmentService.enrich_event(db, event_data)
        db_event = EventModel(**event_data.model_dump(exclude_none=True))
        db.add(db_event)
        db.flush()

        DeduplicationService.check_and_deduplicate(db, db_event)
        if db_event.is_duplicate:
            duplicate_count += 1
        normalized_count += 1

        db.commit()

        dets = DetectionEngine.evaluate_event(db, db_event)
        if dets:
            total_detections.extend(dets)
            incs = CorrelationEngine.correlate_detections(db, dets)
            affected_incidents.extend(incs)

    if affected_incidents:
        RankingService.get_prioritized_incidents(db)

    AuditService.log(db, action="BULK_EVENTS_INGESTED", details={"received": total_received, "normalized": normalized_count})

    return IngestResponse(
        status="SUCCESS",
        received=total_received,
        normalized=normalized_count,
        duplicates=duplicate_count,
        detections_generated=len(total_detections),
        incidents_created=len(set(i.incident_id for i in affected_incidents))
    )

@router.post("/events/upload-csv")

def upload_csv_events(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Ingests raw security events from CSV upload file.
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")

    content = file.file.read().decode('utf-8')
    reader = csv.DictReader(io.StringIO(content))

    count = 0
    for row in reader:
        raw_dict = dict(row)
        ingest_single_event(raw_dict, db)
        count += 1

    return {"status": "SUCCESS", "filename": file.filename, "rows_processed": count}

@router.post("/ingest/webhook")
def ingest_webhook(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Generic webhook ingestion adapter endpoint for SIEM / EDR integrations.
    """
    return ingest_single_event(payload, db)

@router.get("/events", response_model=List[Dict[str, Any]])
def list_events(
    limit: int = Query(100, le=1000),
    offset: int = 0,
    source: str = None,
    category: str = None,
    db: Session = Depends(get_db)
):
    """
    Retrieves normalized canonical events with pagination and filters.
    """
    query = db.query(EventModel)
    if source:
        query = query.filter(EventModel.source == source)
    if category:
        query = query.filter(EventModel.category == category)

    events = query.order_by(EventModel.timestamp.desc()).offset(offset).limit(limit).all()

    return [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source": e.source,
            "event_type": e.event_type,
            "category": e.category,
            "severity": e.severity,
            "host": e.host,
            "user": e.user,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "is_duplicate": e.is_duplicate,
            "duplicate_count": e.duplicate_count
        }
        for e in events
    ]
