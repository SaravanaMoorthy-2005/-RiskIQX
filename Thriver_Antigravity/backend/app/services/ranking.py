from typing import List
from sqlalchemy.orm import Session
from app.db.models import IncidentModel, IncidentEventJunction, EventModel
from app.services.risk_scoring import RiskScoringService

class RankingService:
    @classmethod
    def get_prioritized_incidents(cls, db: Session) -> List[IncidentModel]:
        """
        Retrieves all open incidents and applies deterministic tie-breaking sorting.
        Hierarchy:
        1. Priority score (desc)
        2. Attack confidence (desc)
        3. Business Impact (desc)
        4. Data Sensitivity (desc)
        5. Age (created_at asc)
        """
        incidents = db.query(IncidentModel).filter(
            IncidentModel.status.in_(["NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT_RECOMMENDED", "AWAITING_APPROVAL"])
        ).all()

        # Recalculate scores for consistent batch max user log normalization
        max_users = 1
        for inc in incidents:
            users_count = len(inc.affected_users_json or [])
            if users_count > max_users:
                max_users = users_count

        for inc in incidents:
            RiskScoringService.calculate_incident_score(db, inc, batch_max_users=max_users)

        # Deterministic sorting
        sorted_incidents = sorted(
            incidents,
            key=lambda x: (
                x.priority_score,
                x.attack_confidence,
                x.business_impact,
                x.data_sensitivity,
                -x.created_at.timestamp() if x.created_at else 0
            ),
            reverse=True
        )

        return sorted_incidents
