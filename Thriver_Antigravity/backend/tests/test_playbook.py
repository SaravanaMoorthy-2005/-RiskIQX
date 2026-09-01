import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.database import Base
from app.db.models import IncidentModel
from app.services.playbook import PlaybookService

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_playbook_approval_gate(db_session):
    inc = IncidentModel(
        incident_id="INC-PB-TEST",
        title="Malware Infection",
        status="NEW",
        recommended_playbook="PLAYBOOK-MALWARE"
    )
    db_session.add(inc)
    db_session.commit()

    # 1. Unapproved high-risk step -> MUST return APPROVAL_REQUIRED
    res_unapproved = PlaybookService.execute_playbook_step(
        db_session,
        incident_id=inc.incident_id,
        playbook_id="PLAYBOOK-MALWARE",
        action_name="ISOLATE_HOST_ENDPOINT",
        approved=False
    )
    assert res_unapproved["status"] == "APPROVAL_REQUIRED"
    assert inc.status == "AWAITING_APPROVAL"

    # 2. Approved step -> Executed in SIMULATION ONLY mode
    res_approved = PlaybookService.execute_playbook_step(
        db_session,
        incident_id=inc.incident_id,
        playbook_id="PLAYBOOK-MALWARE",
        action_name="ISOLATE_HOST_ENDPOINT",
        approved=True
    )
    assert res_approved["status"] == "SUCCESS"
    assert res_approved["simulation_status"] == "SIMULATION ONLY"
    assert inc.status == "CONTAINMENT_RECOMMENDED"
