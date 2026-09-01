from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime

class CanonicalEvent(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    source: str = Field(..., description="Telemetry source e.g. SIEM, EDR, Firewall")
    source_type: str = Field(..., description="Adapter source type e.g. generic_siem, generic_edr")
    event_type: str = Field(..., description="Event activity e.g. login, process_creation, network_connect")
    category: str = Field("AUTHENTICATION", description="Security domain category")
    severity: int = Field(1, ge=1, le=5, description="1-5 rating")

    host: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    asset_id: Optional[str] = None
    asset_type: Optional[str] = None
    asset_tier: Optional[str] = None # TIER 1, TIER 2, TIER 3, TIER 4
    asset_criticality: Optional[int] = Field(None, ge=1, le=5)
    internet_facing: bool = False

    user: Optional[str] = None
    user_id: Optional[str] = None
    user_role: Optional[str] = None
    privileged_user: bool = False

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    domain: Optional[str] = None
    url: Optional[str] = None
    file_hash: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None

    authentication_result: Optional[str] = None # SUCCESS, FAILURE
    authentication_method: Optional[str] = None

    affected_users_count: int = 1
    data_sensitivity: int = Field(1, ge=1, le=5)
    business_impact: int = Field(1, ge=1, le=5)
    attack_confidence: float = Field(0.5, ge=0.0, le=1.0)

    raw_event: Optional[Dict[str, Any]] = None
    extra_metadata: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="ignore", from_attributes=True)


class BulkIngestRequest(BaseModel):
    events: List[CanonicalEvent]


class IngestResponse(BaseModel):
    status: str
    received: int
    normalized: int
    duplicates: int
    detections_generated: int
    incidents_created: int
