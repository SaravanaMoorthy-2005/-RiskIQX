import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.database import Base
from app.db.models import IncidentModel, EventModel, IncidentEventJunction
from app.services.risk_scoring import RiskScoringService
from app.services.explainability import ExplainabilityService

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_critical_scoring_alert_a_vs_alert_b(db_session):
    """
    CRITICAL MANDATORY SCORING TEST (Section 55 & 56):
    Proves that Severity alone does NOT equal Priority.
    
    ALERT A: High Severity (5/5), Low Asset (2/5), Low Confidence (0.35), Low Sensitivity (2/5), Low Impact (2/5)
    ALERT B: Moderate Severity (4/5), Critical Asset Tier-1 (5/5), High Confidence (0.95), High Sensitivity (5/5), High Impact (5/5)
    """
    
    # 1. Create Alert A Incident
    inc_a = IncidentModel(
        incident_id="INC-TEST-ALERT-A",
        title="High Severity on Low Criticality Endpoint",
        status="NEW",
        attack_confidence=0.35,
        affected_assets_json=["LOW-PRIO-HOST-01"],
        affected_users_json=["user_a"],
        data_sensitivity=2,
        business_impact=2
    )
    db_session.add(inc_a)
    db_session.flush()

    evt_a = EventModel(
        event_id="EVT-A",
        source="EDR",
        source_type="generic_edr",
        event_type="suspicious_activity",
        category="ENDPOINT",
        severity=5,
        asset_tier="TIER 4",
        asset_criticality=2,
        data_sensitivity=2,
        business_impact=2,
        attack_confidence=0.35
    )
    db_session.add(evt_a)
    db_session.flush()
    db_session.add(IncidentEventJunction(incident_id=inc_a.incident_id, event_id=evt_a.event_id))

    # 2. Create Alert B Incident
    inc_b = IncidentModel(
        incident_id="INC-TEST-ALERT-B",
        title="Moderate Severity on Tier-1 Critical Database",
        status="NEW",
        attack_confidence=0.95,
        affected_assets_json=["DB-SERVER-01"],
        affected_users_json=["user_b"],
        data_sensitivity=5,
        business_impact=5
    )
    db_session.add(inc_b)
    db_session.flush()

    evt_b = EventModel(
        event_id="EVT-B",
        source="SIEM",
        source_type="generic_siem",
        event_type="exfiltration_attempt",
        category="NETWORK_ACTIVITY",
        severity=4,
        asset_tier="TIER 1",
        asset_criticality=5,
        data_sensitivity=5,
        business_impact=5,
        attack_confidence=0.95
    )
    db_session.add(evt_b)
    db_session.flush()
    db_session.add(IncidentEventJunction(incident_id=inc_b.incident_id, event_id=evt_b.event_id))

    db_session.commit()

    # 3. Calculate Scores
    breakdown_a = RiskScoringService.calculate_incident_score(db_session, inc_a)
    breakdown_b = RiskScoringService.calculate_incident_score(db_session, inc_b)

    score_a = breakdown_a.final_score
    score_b = breakdown_b.final_score

    print(f"\n[CRITICAL TEST RESULTS]")
    print(f"Alert A (High Sev / Low Context) Final Score: {score_a} ({breakdown_a.priority_level})")
    print(f"Alert B (Mod Sev / High Context) Final Score: {score_b} ({breakdown_b.priority_level})")

    # 4. Assertions
    # Alert B MUST outrank Alert A despite lower severity
    assert score_b > score_a, f"Expected Alert B score ({score_b}) to be higher than Alert A ({score_a})"
    assert breakdown_b.priority_level in ["HIGH", "CRITICAL"]
    assert breakdown_a.priority_level in ["LOW", "MEDIUM"]

    # 5. Verify Pairwise Comparative Explanation
    pairwise = ExplainabilityService.compare_pairwise(db_session, inc_b, inc_a)
    assert pairwise.score_gap > 0
    assert len(pairwise.factor_deltas) > 0
    assert "Asset Importance" in pairwise.top_winning_factors or "Data Sensitivity" in pairwise.top_winning_factors
