from fastapi import APIRouter, Depends, Body
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
from app.db.database import get_db
from app.services.simulator import ScenarioSimulator
from seed_data import seed_database, clear_database

router = APIRouter(tags=["Simulator & Demo Control"])

@router.post("/demo/load")
def load_demo_data(db: Session = Depends(get_db)):
    """
    Seeds comprehensive synthetic demo dataset (500+ events, 100+ detections, 30+ correlated incidents, asset catalog, user directory, threat intel, vulnerabilities).
    """
    counts = seed_database(db)
    return {
        "status": "SUCCESS",
        "message": "Synthetic demo dataset successfully loaded into database.",
        "counts": counts
    }

@router.post("/demo/reset")
def reset_demo_database(db: Session = Depends(get_db)):
    """
    Resets and re-initializes database tables.
    """
    clear_database(db)
    counts = seed_database(db)
    return {"status": "SUCCESS", "message": "Database cleared and re-initialized.", "counts": counts}

@router.post("/simulator/start")
def start_simulator_scenario(
    payload: Optional[Dict[str, Any]] = Body(default=None),
    db: Session = Depends(get_db)
):
    """
    Executes a canned attack scenario (ransomware, phishing, brute_force, data_exfil, priv_esc, lateral_move, port_scan, insider_threat, cloud_compromise, credential_attack).
    """
    key = "ransomware"
    if payload and isinstance(payload, dict):
        key = payload.get("scenario_key") or payload.get("scenarioKey") or payload.get("key") or "ransomware"
    elif isinstance(payload, str):
        key = payload

    res = ScenarioSimulator.trigger_scenario(db, key)
    return res

@router.post("/simulator/stop")
def stop_simulator():
    ScenarioSimulator.SIMULATOR_RUNNING = False
    return {"status": "SUCCESS", "message": "Simulator background task stopped."}
