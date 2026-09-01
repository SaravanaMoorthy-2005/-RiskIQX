import hashlib
from typing import Optional
from sqlalchemy.orm import Session
from app.db.models import EventModel
from app.config import settings

class DeduplicationService:
    @staticmethod
    def generate_fingerprint(event: EventModel) -> str:
        """
        Generates a deterministic SHA256 fingerprint for deduplicating identical events within sliding time windows.
        Fields: source, event_type, host, user, source_ip, destination_ip
        """
        raw_str = f"{event.source}|{event.event_type}|{event.host or ''}|{event.user or ''}|{event.source_ip or ''}|{event.destination_ip or ''}"
        return hashlib.sha256(raw_str.encode('utf-8')).hexdigest()

    @classmethod
    def check_and_deduplicate(cls, db: Session, event: EventModel) -> EventModel:
        """
        Checks if an event is a duplicate of a recent event within the deduplication window.
        """
        fingerprint = cls.generate_fingerprint(event)
        event.deduplication_hash = fingerprint

        # Check existing events with matching fingerprint within time window
        recent_duplicate = db.query(EventModel).filter(
            EventModel.deduplication_hash == fingerprint,
            EventModel.id != event.id
        ).order_by(EventModel.timestamp.desc()).first()

        if recent_duplicate:
            # Mark event as duplicate and increment duplicate count on master
            event.is_duplicate = True
            recent_duplicate.duplicate_count += 1
            db.add(recent_duplicate)
        else:
            event.is_duplicate = False
            event.duplicate_count = 1

        return event
