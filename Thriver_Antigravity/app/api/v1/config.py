from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

from app.db.database import get_db
from app.db.models import ScoringModelConfig
from app.models.scoring import ScoringWeights, PriorityThresholds
from app.config import settings
from app.config.sector_profiles import get_all_sector_profiles, get_sector_profile, load_sector_into_db
from app.services.audit import AuditService
from app.services.ranking import RankingService

router = APIRouter(tags=["Scoring Configuration & Sector Presets"])

class ActivateSectorRequest(BaseModel):
    sector_id: str
    weights: Optional[ScoringWeights] = None
    version_name: Optional[str] = None

class UpdateConfigRequest(BaseModel):
    version_name: str
    weights: ScoringWeights
    thresholds: PriorityThresholds
    sector_id: Optional[str] = None

@router.get("/sectors")
def list_sectors():
    """
    Returns all 7 industry sector presets with target weights, descriptions, and threat counts.
    """
    return get_all_sector_profiles()

@router.get("/sectors/{sector_id}")
def get_sector(sector_id: str):
    profile = get_sector_profile(sector_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Sector preset '{sector_id}' not found.")
    return profile

@router.post("/sectors/activate")
def activate_sector(
    req: ActivateSectorRequest,
    db: Session = Depends(get_db)
):
    """
    Activates an industry sector preset:
    1. Loads sector-specific threat scenarios and telemetry.
    2. Updates active weights to sector profile.
    3. Re-runs the 6-Factor Risk Scoring Engine to deterministically rank and score all threats.
    """
    try:
        w_dict = req.weights.model_dump() if req.weights else None
        res = load_sector_into_db(
            db,
            sector_id=req.sector_id,
            custom_weights=w_dict,
            version_name=req.version_name
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to activate sector: {str(e)}")

@router.get("/config/scoring")
def get_scoring_config(db: Session = Depends(get_db)):
    active_cfg = db.query(ScoringModelConfig).filter(ScoringModelConfig.is_active == True).first()
    if active_cfg:
        # Determine current sector if encoded in created_by or version_name
        sector = "healthcare"
        if active_cfg.created_by and active_cfg.created_by.startswith("sector_preset_"):
            sector = active_cfg.created_by.replace("sector_preset_", "")
        elif "banking" in active_cfg.version_name:
            sector = "banking"
        elif "ecommerce" in active_cfg.version_name:
            sector = "ecommerce"
        elif "saas" in active_cfg.version_name:
            sector = "saas"
        elif "government" in active_cfg.version_name:
            sector = "government"
        elif "education" in active_cfg.version_name:
            sector = "education"
        elif "manufacturing" in active_cfg.version_name:
            sector = "manufacturing"

        return {
            "version_name": active_cfg.version_name,
            "weights": active_cfg.weights_json,
            "thresholds": active_cfg.thresholds_json,
            "active_sector": sector,
            "is_active": True,
            "created_at": active_cfg.created_at.isoformat() if active_cfg.created_at else None
        }

    return {
        "version_name": "weighted-v1-healthcare",
        "weights": {
            "severity": 0.25,
            "asset_importance": 0.15,
            "affected_users": 0.15,
            "data_sensitivity": 0.25,
            "attack_confidence": 0.10,
            "business_impact": 0.10
        },
        "thresholds": {
            "critical": settings.THRESHOLD_CRITICAL,
            "high": settings.THRESHOLD_HIGH,
            "medium": settings.THRESHOLD_MEDIUM,
            "low": settings.THRESHOLD_LOW
        },
        "active_sector": "healthcare",
        "is_active": True
    }

@router.put("/config/scoring")
def update_scoring_config(
    payload: UpdateConfigRequest,
    db: Session = Depends(get_db)
):
    # Validate weights sum to 1.0 (with 0.001 floating point tolerance)
    w_dict = payload.weights.model_dump()
    w_sum = sum(w_dict.values())
    if abs(w_sum - 1.0) > 0.001:
        raise HTTPException(status_code=400, detail=f"Scoring weights MUST sum to exactly 1.0 (Current sum: {w_sum:.3f})")

    # Deactivate existing active models
    db.query(ScoringModelConfig).update({"is_active": False})

    creator_tag = f"sector_preset_{payload.sector_id}" if payload.sector_id else "custom_analyst"
    new_config = ScoringModelConfig(
        version_name=payload.version_name,
        weights_json=w_dict,
        thresholds_json=payload.thresholds.model_dump(),
        is_active=True,
        created_by=creator_tag
    )
    db.add(new_config)
    db.commit()

    # Immediately recalculate all active incidents with the newly saved weights
    sorted_incidents = RankingService.get_prioritized_incidents(db)
    db.commit()

    AuditService.log(
        db,
        action="SCORING_CONFIG_UPDATED",
        entity="scoring_model",
        entity_id=payload.version_name,
        details={"weights": w_dict, "threats_recalculated": len(sorted_incidents)}
    )

    return {
        "status": "SUCCESS",
        "version_name": payload.version_name,
        "weights": w_dict,
        "threats_recalculated": len(sorted_incidents),
        "top_threat": sorted_incidents[0].title if sorted_incidents else None,
        "top_score": sorted_incidents[0].priority_score if sorted_incidents else None
    }

@router.post("/config/reset")
def reset_scoring_config(db: Session = Depends(get_db)):
    """
    Resets to default Healthcare sector preset and recalibrates all risk scores.
    """
    res = load_sector_into_db(db, sector_id="healthcare")
    return {
        "status": "SUCCESS",
        "message": "Scoring model and telemetry reset to default Healthcare preset.",
        "details": res
    }
