import math
from typing import Dict, Any, Tuple, List, Optional
from sqlalchemy.orm import Session
from app.db.models import IncidentModel, IncidentEventJunction, EventModel, ScoringModelConfig, ScoreCalculationModel
from app.models.scoring import ScoringWeights, PriorityThresholds, FactorContribution, ScoreBreakdown
from app.config import settings

class RiskScoringService:
    @classmethod
    def calculate_incident_score(
        cls,
        db: Session,
        incident: IncidentModel,
        weights: Optional[ScoringWeights] = None,
        thresholds: Optional[PriorityThresholds] = None,
        batch_max_users: int = 10
    ) -> ScoreBreakdown:
        """
        Calculates 6-Factor Contextual Risk Score, score contributions, Priority Level, SLA deadline, and Data Confidence.
        """
        active_cfg = None
        if weights is None or thresholds is None:
            active_cfg = db.query(ScoringModelConfig).filter(ScoringModelConfig.is_active == True).first()

        if weights is None:
            if active_cfg and active_cfg.weights_json:
                weights = ScoringWeights(**active_cfg.weights_json)
            else:
                weights = ScoringWeights(
                    severity=settings.DEFAULT_WEIGHT_SEVERITY,
                    asset_importance=settings.DEFAULT_WEIGHT_ASSET,
                    affected_users=settings.DEFAULT_WEIGHT_USERS,
                    data_sensitivity=settings.DEFAULT_WEIGHT_DATA,
                    attack_confidence=settings.DEFAULT_WEIGHT_CONFIDENCE,
                    business_impact=settings.DEFAULT_WEIGHT_IMPACT
                )
        
        if thresholds is None:
            if active_cfg and active_cfg.thresholds_json:
                thresholds = PriorityThresholds(**active_cfg.thresholds_json)
            else:
                thresholds = PriorityThresholds(
                    critical=settings.THRESHOLD_CRITICAL,
                    high=settings.THRESHOLD_HIGH,
                    medium=settings.THRESHOLD_MEDIUM,
                    low=settings.THRESHOLD_LOW
                )

        # Retrieve related canonical events for accurate feature aggregation
        junctions = db.query(IncidentEventJunction).filter(
            IncidentEventJunction.incident_id == incident.incident_id
        ).all()
        event_ids = [j.event_id for j in junctions]
        events = db.query(EventModel).filter(EventModel.event_id.in_(event_ids)).all() if event_ids else []

        # Feature extraction
        max_severity = max([e.severity for e in events], default=3)
        
        asset_tiers = [e.asset_tier for e in events if e.asset_tier]
        max_asset_crit = max([e.asset_criticality for e in events if e.asset_criticality], default=3)
        if "TIER 1" in asset_tiers: max_asset_crit = 5
        elif "TIER 2" in asset_tiers: max_asset_crit = 4

        users = set(incident.affected_users_json or [])
        user_count = len(users) if users else 1

        max_data_sens = max([e.data_sensitivity for e in events], default=incident.data_sensitivity or 3)
        max_biz_impact = max([e.business_impact for e in events], default=incident.business_impact or 3)
        attack_conf = incident.attack_confidence or 0.7

        # Missing factors tracking & Data Confidence computation
        missing_factors: List[str] = []
        data_confidence = 1.0
        if not asset_tiers:
            missing_factors.append("Asset Tier Unavailable")
            data_confidence -= 0.20
        if not incident.affected_users_json:
            missing_factors.append("User Directory Context Missing")
            data_confidence -= 0.15
        if not events:
            missing_factors.append("Raw Telemetry Events Missing")
            data_confidence -= 0.25
        data_confidence = max(0.1, min(1.0, data_confidence))

        # 1. Normalization (0 - 100)
        norm_sev = cls._normalize_1_to_5(max_severity)
        norm_asset = cls._normalize_1_to_5(max_asset_crit)
        norm_users = cls._normalize_users(user_count, batch_max_users)
        norm_data = cls._normalize_1_to_5(max_data_sens)
        norm_conf = min(100.0, max(0.0, attack_conf * 100.0))
        norm_impact = cls._normalize_1_to_5(max_biz_impact)

        # 2. Factor Contributions calculation
        c_sev = norm_sev * weights.severity
        c_asset = norm_asset * weights.asset_importance
        c_users = norm_users * weights.affected_users
        c_data = norm_data * weights.data_sensitivity
        c_conf = norm_conf * weights.attack_confidence
        c_impact = norm_impact * weights.business_impact

        final_score = min(100.0, max(0.0, c_sev + c_asset + c_users + c_data + c_conf + c_impact))
        final_score = round(final_score, 2)

        # 3. Priority Level Determination
        if final_score >= thresholds.critical:
            priority_level = "CRITICAL"
            sla_hours = settings.SLA_CRITICAL_HOURS
        elif final_score >= thresholds.high:
            priority_level = "HIGH"
            sla_hours = settings.SLA_HIGH_HOURS
        elif final_score >= thresholds.medium:
            priority_level = "MEDIUM"
            sla_hours = settings.SLA_MEDIUM_HOURS
        elif final_score >= thresholds.low:
            priority_level = "LOW"
            sla_hours = settings.SLA_LOW_HOURS
        else:
            priority_level = "INFORMATIONAL"
            sla_hours = settings.SLA_LOW_HOURS

        # Update Incident database fields
        incident.priority_score = final_score
        incident.priority_level = priority_level
        incident.data_confidence = round(data_confidence, 2)
        incident.business_impact = max_biz_impact
        incident.data_sensitivity = max_data_sens

        # Top drivers for UI breakdown
        contributions_dict = {
            "Severity": FactorContribution(factor_name="Severity", raw_value=f"{max_severity}/5", normalized_value=norm_sev, weight=weights.severity, contribution=round(c_sev, 2)),
            "Asset Importance": FactorContribution(factor_name="Asset Importance", raw_value=f"{max_asset_crit}/5 ({asset_tiers[0] if asset_tiers else 'Tier 3'})", normalized_value=norm_asset, weight=weights.asset_importance, contribution=round(c_asset, 2)),
            "Affected Users": FactorContribution(factor_name="Affected Users", raw_value=f"{user_count} User(s)", normalized_value=norm_users, weight=weights.affected_users, contribution=round(c_users, 2)),
            "Data Sensitivity": FactorContribution(factor_name="Data Sensitivity", raw_value=f"{max_data_sens}/5", normalized_value=norm_data, weight=weights.data_sensitivity, contribution=round(c_data, 2)),
            "Attack Confidence": FactorContribution(factor_name="Attack Confidence", raw_value=f"{int(attack_conf * 100)}%", normalized_value=norm_conf, weight=weights.attack_confidence, contribution=round(c_conf, 2)),
            "Business Impact": FactorContribution(factor_name="Business Impact", raw_value=f"{max_biz_impact}/5", normalized_value=norm_impact, weight=weights.business_impact, contribution=round(c_impact, 2))
        }

        top_drivers = sorted(contributions_dict.values(), key=lambda x: x.contribution, reverse=True)[:3]
        incident.top_drivers_json = [f"{d.factor_name} (+{d.contribution} pts)" for d in top_drivers]

        # Record ScoreCalculation log
        calc_record = ScoreCalculationModel(
            incident_id=incident.incident_id,
            model_version="weighted-v1",
            raw_factors_json={
                "severity": max_severity, "asset_criticality": max_asset_crit,
                "user_count": user_count, "data_sensitivity": max_data_sens,
                "attack_confidence": attack_conf, "business_impact": max_biz_impact
            },
            normalized_factors_json={
                "severity": norm_sev, "asset_importance": norm_asset,
                "affected_users": norm_users, "data_sensitivity": norm_data,
                "attack_confidence": norm_conf, "business_impact": norm_impact
            },
            contributions_json={k: v.contribution for k, v in contributions_dict.items()},
            final_score=final_score
        )
        db.add(calc_record)
        db.commit()

        return ScoreBreakdown(
            final_score=final_score,
            priority_level=priority_level,
            attack_confidence=round(attack_conf, 2),
            data_confidence=round(data_confidence, 2),
            missing_factors=missing_factors,
            contributions=contributions_dict
        )

    @staticmethod
    def _normalize_1_to_5(val: int) -> float:
        val = max(1, min(5, val))
        return round(((val - 1) / 4.0) * 100.0, 2)

    @staticmethod
    def _normalize_users(users: int, max_users: int) -> float:
        if users <= 0:
            return 0.0
        if max_users <= 1:
            return min(100.0, users * 25.0)
        norm = 100.0 * (math.log(1 + users) / math.log(1 + max(max_users, 10)))
        return round(min(100.0, max(0.0, norm)), 2)
