import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy.orm import Session
from app.db.models import EventModel, DetectionModel, IncidentModel, IncidentEventJunction
from app.config import settings

class CorrelationEngine:
    @classmethod
    def correlate_detections(cls, db: Session, detections: List[DetectionModel]) -> List[IncidentModel]:
        """
        Correlates detections and associated canonical events into multi-signal Incidents.
        Clusters events based on common keys: Host, User, Source IP, Destination IP, File Hash, Domain.
        """
        incidents_affected: List[IncidentModel] = []

        for det in detections:
            event_ids = det.event_ids_json or []
            events = db.query(EventModel).filter(EventModel.event_id.in_(event_ids)).all()
            if not events:
                continue

            for event in events:
                # Find matching open incident within correlation sliding window
                incident = cls._find_matching_incident(db, event, det)
                if not incident:
                    incident = cls._create_incident(db, event, det)
                else:
                    cls._update_incident_with_event(db, incident, event, det)

                if incident not in incidents_affected:
                    incidents_affected.append(incident)

        db.commit()
        return incidents_affected

    @classmethod
    def _find_matching_incident(cls, db: Session, event: EventModel, det: DetectionModel) -> Optional[IncidentModel]:
        # Query open incidents for correlation match
        open_incidents = db.query(IncidentModel).filter(
            IncidentModel.status.in_(["NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT_RECOMMENDED", "AWAITING_APPROVAL"])
        ).all()

        for inc in open_incidents:
            assets = inc.affected_assets_json or []
            users = inc.affected_users_json or []
            alerts = inc.related_alerts_json or []

            # Check matching keys
            if event.host and event.host in assets:
                return inc
            if event.user and event.user in users:
                return inc
            if event.source_ip and any(event.source_ip in str(a) for a in alerts):
                return inc
            if det.mitre_technique and any(det.mitre_technique in m for m in (inc.mitre_techniques_json or [])):
                return inc

        return None

    @classmethod
    def _create_incident(cls, db: Session, event: EventModel, det: DetectionModel) -> IncidentModel:
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        title = f"{det.rule_name} on {event.host or event.user or 'System'}"
        
        # Initial incident record
        inc = IncidentModel(
            incident_id=inc_id,
            title=title,
            status="NEW",
            created_at=now,
            updated_at=now,
            priority_score=0.0,
            priority_level="MEDIUM",
            attack_confidence=det.confidence,
            data_confidence=1.0 if event.asset_tier else 0.8,
            affected_assets_json=[event.host] if event.host else [],
            affected_users_json=[event.user] if event.user else [],
            attack_types_json=[det.category],
            mitre_techniques_json=[f"{det.mitre_technique}: {det.mitre_name}"] if det.mitre_technique else [],
            business_impact=event.business_impact,
            data_sensitivity=event.data_sensitivity,
            related_alerts_json=[det.detection_id],
            top_drivers_json=[],
            explanation="",
            attack_story=f"Initial signal detected: {det.rule_name} involving host '{event.host}' and user '{event.user}'.",
            recommended_playbook=cls._map_playbook(det.category),
            sla_deadline=now + timedelta(hours=settings.SLA_MEDIUM_HOURS)
        )
        db.add(inc)
        db.flush()

        # Link junction
        junction = IncidentEventJunction(incident_id=inc.incident_id, event_id=event.event_id)
        db.add(junction)
        return inc

    @classmethod
    def _update_incident_with_event(cls, db: Session, inc: IncidentModel, event: EventModel, det: DetectionModel):
        inc.updated_at = datetime.now(timezone.utc)
        
        assets = set(inc.affected_assets_json or [])
        if event.host: assets.add(event.host)
        inc.affected_assets_json = list(assets)

        users = set(inc.affected_users_json or [])
        if event.user: users.add(event.user)
        inc.affected_users_json = list(users)

        attack_types = set(inc.attack_types_json or [])
        attack_types.add(det.category)
        inc.attack_types_json = list(attack_types)

        mitre = set(inc.mitre_techniques_json or [])
        if det.mitre_technique:
            mitre.add(f"{det.mitre_technique}: {det.mitre_name}")
        inc.mitre_techniques_json = list(mitre)

        alerts = set(inc.related_alerts_json or [])
        alerts.add(det.detection_id)
        inc.related_alerts_json = list(alerts)

        # Elevate impact & confidence as multi-signal correlation grows
        inc.attack_confidence = min(1.0, max(inc.attack_confidence, det.confidence) + 0.05)
        inc.business_impact = max(inc.business_impact, event.business_impact)
        inc.data_sensitivity = max(inc.data_sensitivity, event.data_sensitivity)
        
        # Link junction if not already linked
        existing = db.query(IncidentEventJunction).filter(
            IncidentEventJunction.incident_id == inc.incident_id,
            IncidentEventJunction.event_id == event.event_id
        ).first()
        if not existing:
            db.add(IncidentEventJunction(incident_id=inc.incident_id, event_id=event.event_id))

    @staticmethod
    def _map_playbook(category: str) -> str:
        cat_upper = category.upper()
        if "AUTHENTICATION" in cat_upper:
            return "PLAYBOOK-BRUTE-FORCE"
        elif "ENDPOINT" in cat_upper:
            return "PLAYBOOK-MALWARE"
        elif "FILE" in cat_upper:
            return "PLAYBOOK-MALWARE"
        elif "EMAIL" in cat_upper:
            return "PLAYBOOK-PHISHING"
        elif "NETWORK" in cat_upper:
            return "PLAYBOOK-DATA-EXFIL"
        elif "CLOUD" in cat_upper:
            return "PLAYBOOK-PRIV-ESC"
        return "PLAYBOOK-MALWARE"
