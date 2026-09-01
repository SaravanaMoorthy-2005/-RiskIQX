from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.db.models import IncidentModel, IncidentEventJunction, EventModel
from app.services.risk_scoring import RiskScoringService
from app.models.scoring import PairwiseExplanation, PairwiseComparisonDelta, ScoreBreakdown

class ExplainabilityService:
    @classmethod
    def explain_why_number_one(cls, db: Session, incident: IncidentModel) -> Dict[str, Any]:
        """
        Generates structured, crisp, executive-level explanations for why this incident is ranked #1.
        """
        breakdown: ScoreBreakdown = RiskScoringService.calculate_incident_score(db, incident)
        
        # Sort contributions descending
        sorted_contribs = sorted(
            breakdown.contributions.values(),
            key=lambda c: c.contribution,
            reverse=True
        )

        top1 = sorted_contribs[0]
        top2 = sorted_contribs[1]
        top3 = sorted_contribs[2]

        assets = ", ".join(incident.affected_assets_json or ["Unspecified Asset"])
        users = ", ".join(incident.affected_users_json or ["Unspecified User"])
        attack_types = ", ".join(incident.attack_types_json or ["General Anomaly"])
        mitre_techs = ", ".join(incident.mitre_techniques_json or ["Unmapped"])

        # Fetch extra event details for richer context
        junctions = db.query(IncidentEventJunction).filter(
            IncidentEventJunction.incident_id == incident.incident_id
        ).all()
        event_ids = [j.event_id for j in junctions]
        events = db.query(EventModel).filter(EventModel.event_id.in_(event_ids)).all() if event_ids else []

        asset_tier = events[0].asset_tier if events and events[0].asset_tier else "Tier 2/3"
        privileged = "PRIVILEGED ADMIN" if any(e.privileged_user for e in events) else "Standard Account"
        internet_facing = "YES (Internet-Facing Target)" if any(e.internet_facing for e in events) else "NO (Internal Network)"

        # 1. Executive Summary
        executive_summary = (
            f"Incident '{incident.title}' ({incident.incident_id}) holds RANK #1 in the queue with a Contextual Risk Score of "
            f"{breakdown.final_score}/100 [{breakdown.priority_level} PRIORITY]. "
            f"This incident demands immediate SOC triage because it combines {top1.factor_name} ({top1.raw_value}) with "
            f"{top2.factor_name} ({top2.raw_value}), targeting high-value infrastructure [{assets}] under {privileged} context."
        )

        # 2. Structured Driver Highlights
        driver_highlights = [
            {
                "rank": 1,
                "factor": top1.factor_name,
                "raw_value": top1.raw_value,
                "contribution": f"+{top1.contribution} pts",
                "weight": f"{(top1.weight * 100):.0f}%",
                "impact_statement": cls._get_factor_impact_statement(top1.factor_name, top1.raw_value)
            },
            {
                "rank": 2,
                "factor": top2.factor_name,
                "raw_value": top2.raw_value,
                "contribution": f"+{top2.contribution} pts",
                "weight": f"{(top2.weight * 100):.0f}%",
                "impact_statement": cls._get_factor_impact_statement(top2.factor_name, top2.raw_value)
            },
            {
                "rank": 3,
                "factor": top3.factor_name,
                "raw_value": top3.raw_value,
                "contribution": f"+{top3.contribution} pts",
                "weight": f"{(top3.weight * 100):.0f}%",
                "impact_statement": cls._get_factor_impact_statement(top3.factor_name, top3.raw_value)
            }
        ]

        # 3. Contextual Risk Assessment
        context_assessment = {
            "affected_assets": assets,
            "asset_tier": asset_tier,
            "affected_users": users,
            "user_privilege": privileged,
            "internet_facing": internet_facing,
            "attack_confidence": f"{int(breakdown.attack_confidence * 100)}%",
            "data_confidence": f"{int(breakdown.data_confidence * 100)}%",
            "attack_types": attack_types,
            "mitre_techniques": mitre_techs
        }

        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "priority_score": breakdown.final_score,
            "priority_level": breakdown.priority_level,
            "narrative": executive_summary,
            "driver_highlights": driver_highlights,
            "context_assessment": context_assessment,
            "top_drivers": [f"{c.factor_name}: +{c.contribution} pts" for c in sorted_contribs[:3]],
            "score_breakdown": breakdown.model_dump()
        }

    @classmethod
    def compare_pairwise(cls, db: Session, inc_a: IncidentModel, inc_b: IncidentModel) -> PairwiseExplanation:
        """
        Compares Incident A against Incident B factor-by-factor to explain crisply why A outranks B.
        """
        bd_a: ScoreBreakdown = RiskScoringService.calculate_incident_score(db, inc_a)
        bd_b: ScoreBreakdown = RiskScoringService.calculate_incident_score(db, inc_b)

        score_gap = round(bd_a.final_score - bd_b.final_score, 2)

        deltas: List[PairwiseComparisonDelta] = []
        winning_factors: List[str] = []

        for factor_key in bd_a.contributions.keys():
            c_a = bd_a.contributions[factor_key]
            c_b = bd_b.contributions[factor_key]

            diff = round(c_a.contribution - c_b.contribution, 2)
            
            if diff > 0:
                expl = f"Incident A (+{c_a.contribution} pts) outranks Incident B (+{c_b.contribution} pts) by +{diff} pts due to higher {factor_key.lower()} ({c_a.raw_value} vs {c_b.raw_value})."
                winning_factors.append(factor_key)
            elif diff < 0:
                expl = f"Incident B (+{c_b.contribution} pts) had higher {factor_key.lower()} than Incident A (+{c_a.contribution} pts), but A exceeded B overall."
            else:
                expl = f"Equal contribution (+{c_a.contribution} pts) for both incidents."

            deltas.append(PairwiseComparisonDelta(
                factor_name=factor_key,
                inc_a_value=str(c_a.raw_value),
                inc_b_value=str(c_b.raw_value),
                inc_a_contribution=c_a.contribution,
                inc_b_contribution=c_b.contribution,
                contribution_diff=diff,
                explanation=expl
            ))

        # Sort winning factors by highest diff
        deltas.sort(key=lambda d: d.contribution_diff, reverse=True)

        winning_deltas = [d for d in deltas if d.contribution_diff > 0]
        if winning_deltas:
            top_win = winning_deltas[0]
            summary_narrative = (
                f"Incident '{inc_a.title}' (Score {bd_a.final_score}) ranks above Incident '{inc_b.title}' (Score {bd_b.final_score}) "
                f"by a decisive gap of +{score_gap} points. "
                f"The largest single ranking delta is driven by {top_win.factor_name} (+{top_win.contribution_diff} pts advantage: {top_win.inc_a_value} vs {top_win.inc_b_value})."
            )
        else:
            summary_narrative = (
                f"Incident '{inc_a.title}' (Score {bd_a.final_score}) outranks Incident '{inc_b.title}' (Score {bd_b.final_score}) "
                f"by +{score_gap} points based on cumulative tie-breaking rules and attack confidence."
            )

        return PairwiseExplanation(
            incident_a_id=inc_a.incident_id,
            incident_a_title=inc_a.title,
            incident_a_score=bd_a.final_score,
            incident_b_id=inc_b.incident_id,
            incident_b_title=inc_b.title,
            incident_b_score=bd_b.final_score,
            score_gap=score_gap,
            top_winning_factors=[d.factor_name for d in deltas if d.contribution_diff > 0][:3],
            factor_deltas=deltas,
            summary_narrative=summary_narrative
        )

    @staticmethod
    def _get_factor_impact_statement(factor: str, raw_value: Any) -> str:
        f = factor.lower()
        if "asset" in f:
            return f"Assets classified under high business criticality (Value: {raw_value}) increase systemic risk."
        elif "severity" in f:
            return f"High technical detection severity rating (Value: {raw_value}) indicates potent attack signals."
        elif "user" in f:
            return f"Involvement of {raw_value} expands potential administrative credential compromise exposure."
        elif "data" in f:
            return f"Elevated data classification level (Value: {raw_value}) risks breach of sensitive organizational records."
        elif "confidence" in f:
            return f"Verified threat intel and correlated evidence establish high certainty ({raw_value}) of malicious intent."
        elif "impact" in f:
            return f"Operational business impact rating (Value: {raw_value}) reflects potential service disruption."
        return f"Factor value ({raw_value}) directly contributes to overall contextual risk."
