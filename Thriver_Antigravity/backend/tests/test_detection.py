import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.database import Base
from app.db.models import EventModel
from app.services.detection import DetectionEngine

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_powershell_detection_rule(db_session):
    event = EventModel(
        event_id="EVT-PS-01",
        source="EDR",
        source_type="generic_edr",
        event_type="process_creation",
        category="ENDPOINT_EXECUTION",
        severity=4,
        host="FINANCE-PC",
        user="john",
        process_name="powershell.exe",
        command_line="powershell.exe -Nop -Enc SQBFA..."
    )
    db_session.add(event)
    db_session.commit()

    detections = DetectionEngine.evaluate_event(db_session, event)
    assert len(detections) >= 1
    det = detections[0]
    assert det.rule_id == "RULE-SUSP-POWERSHELL"
    assert det.mitre_technique == "T1059.001"
