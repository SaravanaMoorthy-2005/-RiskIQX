from pydantic import BaseModel, Field, field_validator
from typing import Dict, List, Optional, Any
from datetime import datetime

class ScoringWeights(BaseModel):
    severity: float = Field(0.25, ge=0.0, le=1.0)
    asset_importance: float = Field(0.20, ge=0.0, le=1.0)
    affected_users: float = Field(0.15, ge=0.0, le=1.0)
    data_sensitivity: float = Field(0.15, ge=0.0, le=1.0)
    attack_confidence: float = Field(0.15, ge=0.0, le=1.0)
    business_impact: float = Field(0.10, ge=0.0, le=1.0)

    @field_validator('*', mode='after')
    def check_sum(cls, v, info):
        # Validation is checked dynamically in service to allow full weight payload validation
        return v

class PriorityThresholds(BaseModel):
    critical: float = Field(90.0, ge=0.0, le=100.0)
    high: float = Field(75.0, ge=0.0, le=100.0)
    medium: float = Field(50.0, ge=0.0, le=100.0)
    low: float = Field(25.0, ge=0.0, le=100.0)

class FactorContribution(BaseModel):
    factor_name: str
    raw_value: Any
    normalized_value: float # 0 - 100
    weight: float           # 0.0 - 1.0
    contribution: float     # normalized_value * weight

class ScoreBreakdown(BaseModel):
    final_score: float
    priority_level: str
    attack_confidence: float
    data_confidence: float
    missing_factors: List[str] = []
    contributions: Dict[str, FactorContribution]

class PairwiseComparisonDelta(BaseModel):
    factor_name: str
    inc_a_value: str
    inc_b_value: str
    inc_a_contribution: float
    inc_b_contribution: float
    contribution_diff: float
    explanation: str

class PairwiseExplanation(BaseModel):
    incident_a_id: str
    incident_a_title: str
    incident_a_score: float
    incident_b_id: str
    incident_b_title: str
    incident_b_score: float
    score_gap: float
    top_winning_factors: List[str]
    factor_deltas: List[PairwiseComparisonDelta]
    summary_narrative: str
