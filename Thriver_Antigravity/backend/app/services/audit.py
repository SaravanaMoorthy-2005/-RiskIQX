from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.db.models import AuditLogModel

class AuditService:
    @staticmethod
    def log(
        db: Session,
        action: str,
        actor: str = "system",
        entity: str = "general",
        entity_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLogModel:
        log_entry = AuditLogModel(
            timestamp=datetime.now(timezone.utc),
            actor=actor,
            action=action,
            entity=entity,
            entity_id=entity_id,
            details_json=details or {}
        )
        db.add(log_entry)
        db.commit()
        return log_entry
