from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import uuid
from app.db.database import Base

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class EventModel(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True)
    source = Column(String(64), index=True)
    source_type = Column(String(64), index=True)
    event_type = Column(String(64), index=True)
    category = Column(String(64), index=True)
    severity = Column(Integer, default=1)  # 1-5

    host = Column(String(128), index=True, nullable=True)
    hostname = Column(String(128), nullable=True)
    os = Column(String(64), nullable=True)
    asset_id = Column(String(64), index=True, nullable=True)
    asset_type = Column(String(64), nullable=True)
    asset_tier = Column(String(32), nullable=True) # Tier 1, Tier 2, etc.
    asset_criticality = Column(Integer, nullable=True) # 1-5
    internet_facing = Column(Boolean, default=False)

    user = Column(String(128), index=True, nullable=True)
    user_id = Column(String(64), index=True, nullable=True)
    user_role = Column(String(64), nullable=True)
    privileged_user = Column(Boolean, default=False)

    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), index=True, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)

    domain = Column(String(256), index=True, nullable=True)
    url = Column(Text, nullable=True)
    file_hash = Column(String(128), index=True, nullable=True)
    process_name = Column(String(256), nullable=True)
    command_line = Column(Text, nullable=True)

    authentication_result = Column(String(32), nullable=True)
    authentication_method = Column(String(64), nullable=True)

    affected_users_count = Column(Integer, default=1)
    data_sensitivity = Column(Integer, default=1) # 1-5
    business_impact = Column(Integer, default=1)   # 1-5
    attack_confidence = Column(Float, default=0.5) # 0.0 - 1.0

    deduplication_hash = Column(String(64), index=True, nullable=True)
    is_duplicate = Column(Boolean, default=False)
    duplicate_count = Column(Integer, default=1)

    raw_event = Column(JSON, nullable=True)
    extra_metadata = Column(JSON, nullable=True)


class DetectionModel(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(String(64), unique=True, index=True, default=generate_uuid)
    rule_id = Column(String(64), index=True)
    rule_name = Column(String(128))
    category = Column(String(64))
    severity = Column(Integer, default=3) # 1-5
    confidence = Column(Float, default=0.7) # 0-1
    description = Column(Text)
    evidence_json = Column(JSON, nullable=True)
    mitre_technique = Column(String(64), nullable=True)
    mitre_name = Column(String(128), nullable=True)
    event_ids_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class AssetModel(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(String(64), unique=True, index=True)
    hostname = Column(String(128), index=True)
    owner = Column(String(128), nullable=True)
    department = Column(String(128), nullable=True)
    asset_type = Column(String(64))
    criticality = Column(Integer, default=3) # 1-5
    asset_tier = Column(String(32), default="TIER 3") # TIER 1, TIER 2, TIER 3, TIER 4
    business_function = Column(String(128), nullable=True)
    internet_facing = Column(Boolean, default=False)
    data_classification = Column(String(64), default="RESTRICTED")


class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(64), unique=True, index=True)
    username = Column(String(128), index=True)
    department = Column(String(128), nullable=True)
    role = Column(String(128), nullable=True)
    privileged = Column(Boolean, default=False)
    vip = Column(Boolean, default=False)
    risk_level = Column(String(32), default="MEDIUM")


class ThreatIntelModel(Base):
    __tablename__ = "threat_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(32), index=True) # ip, domain, url, hash
    ioc_value = Column(String(256), index=True)
    threat_score = Column(Integer, default=80) # 0-100
    malware_family = Column(String(128), nullable=True)
    campaign = Column(String(128), nullable=True)
    ioc_confidence = Column(Float, default=0.9)
    is_malicious = Column(Boolean, default=True)


class VulnerabilityModel(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(64), index=True)
    cvss_score = Column(Float, default=7.5)
    exploitability = Column(Integer, default=3) # 1-5
    affected_asset_id = Column(String(64), index=True)
    known_exploited = Column(Boolean, default=False)
    description = Column(Text, nullable=True)


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, index=True, default=generate_uuid)
    title = Column(String(256))
    status = Column(String(32), default="NEW", index=True) # NEW, TRIAGED, INVESTIGATING, CONTAINMENT_RECOMMENDED, AWAITING_APPROVAL, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now)

    priority_score = Column(Float, default=0.0, index=True)
    priority_level = Column(String(32), default="MEDIUM", index=True) # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL

    attack_confidence = Column(Float, default=0.5)
    data_confidence = Column(Float, default=1.0) # 0-1

    affected_assets_json = Column(JSON, default=list)
    affected_users_json = Column(JSON, default=list)
    attack_types_json = Column(JSON, default=list)
    mitre_techniques_json = Column(JSON, default=list)

    business_impact = Column(Integer, default=3) # 1-5
    data_sensitivity = Column(Integer, default=3) # 1-5

    related_alerts_json = Column(JSON, default=list)
    top_drivers_json = Column(JSON, default=list)
    explanation = Column(Text, nullable=True)
    attack_story = Column(Text, nullable=True)

    recommended_playbook = Column(String(64), nullable=True)
    assigned_analyst = Column(String(128), nullable=True)
    sla_deadline = Column(DateTime(timezone=True), nullable=True)


class IncidentEventJunction(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), index=True)
    event_id = Column(String(64), index=True)


class CaseModel(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(64), unique=True, index=True, default=generate_uuid)
    incident_id = Column(String(64), index=True)
    status = Column(String(32), default="NEW", index=True)
    assigned_analyst = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now)
    resolution_notes = Column(Text, nullable=True)


class PlaybookRunModel(Base):
    __tablename__ = "playbook_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), unique=True, index=True, default=generate_uuid)
    playbook_id = Column(String(64), index=True)
    incident_id = Column(String(64), index=True)
    action_name = Column(String(128))
    action_description = Column(Text)
    risk_level = Column(String(32)) # HIGH, CRITICAL, MEDIUM, LOW
    simulation_status = Column(String(32), default="SIMULATION ONLY")
    approval_required = Column(Boolean, default=True)
    approval_status = Column(String(32), default="PENDING") # PENDING, APPROVED, REJECTED, EXECUTED_SIMULATED
    executed_by = Column(String(128), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now)
    logs_json = Column(JSON, nullable=True)


class FeedbackModel(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    feedback_id = Column(String(64), unique=True, index=True, default=generate_uuid)
    incident_id = Column(String(64), index=True)
    analyst = Column(String(128))
    timestamp = Column(DateTime(timezone=True), default=utc_now)
    decision = Column(String(64)) # CONFIRMED_INCIDENT, FALSE_POSITIVE, BENIGN, NEEDS_INVESTIGATION
    notes = Column(Text, nullable=True)


class ScoringModelConfig(Base):
    __tablename__ = "scoring_models"

    id = Column(Integer, primary_key=True, index=True)
    version_name = Column(String(64), unique=True, index=True)
    weights_json = Column(JSON)
    thresholds_json = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    created_by = Column(String(128), default="system")
    is_active = Column(Boolean, default=True)


class ScoreCalculationModel(Base):
    __tablename__ = "score_calculations"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), index=True)
    model_version = Column(String(64))
    raw_factors_json = Column(JSON)
    normalized_factors_json = Column(JSON)
    contributions_json = Column(JSON)
    final_score = Column(Float)
    calculated_at = Column(DateTime(timezone=True), default=utc_now)


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True)
    actor = Column(String(128), default="system")
    action = Column(String(128), index=True)
    entity = Column(String(64), index=True)
    entity_id = Column(String(64), index=True, nullable=True)
    details_json = Column(JSON, nullable=True)


class DetectionRuleModel(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), unique=True, index=True)
    name = Column(String(128))
    description = Column(Text)
    category = Column(String(64))
    severity = Column(Integer, default=3)
    conditions_json = Column(JSON)
    mitre_technique = Column(String(64), nullable=True)
    confidence = Column(Float, default=0.8)
    enabled = Column(Boolean, default=True)
