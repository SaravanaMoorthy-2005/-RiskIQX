from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.db.models import IncidentModel, PlaybookRunModel, AuditLogModel

class PlaybookService:
    PLAYBOOKS_CATALOG = {
        "PLAYBOOK-BRUTE-FORCE": {
            "id": "PLAYBOOK-BRUTE-FORCE",
            "name": "Brute Force & Credential Protection Playbook",
            "category": "AUTHENTICATION",
            "steps": [
                {
                    "action": "CHECK_IP_REPUTATION",
                    "description": "Query Threat Intelligence for source IP reputation",
                    "risk": "LOW",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": False
                },
                {
                    "action": "AUDIT_AUTH_LOGS",
                    "description": "Aggregate failed and successful authentication events for affected account",
                    "risk": "LOW",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": False
                },
                {
                    "action": "LOCK_USER_ACCOUNT",
                    "description": "Revoke active SSO sessions and temporarily lock user credential",
                    "risk": "HIGH",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": True
                }
            ]
        },
        "PLAYBOOK-MALWARE": {
            "id": "PLAYBOOK-MALWARE",
            "name": "Malware & Endpoint Containment Playbook",
            "category": "ENDPOINT_EXECUTION",
            "steps": [
                {
                    "action": "VERIFY_FILE_HASH",
                    "description": "Cross-reference binary hash against threat intel databases",
                    "risk": "LOW",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": False
                },
                {
                    "action": "INSPECT_PROCESS_TREE",
                    "description": "Analyze parent process hierarchy and spawned command lines",
                    "risk": "LOW",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": False
                },
                {
                    "action": "ISOLATE_HOST_ENDPOINT",
                    "description": "Disconnect host from internal network (Simulated endpoint isolation)",
                    "risk": "CRITICAL",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": True
                }
            ]
        },
        "PLAYBOOK-PHISHING": {
            "id": "PLAYBOOK-PHISHING",
            "name": "Phishing & Email Security Response Playbook",
            "category": "EMAIL_SECURITY",
            "steps": [
                {
                    "action": "ANALYZE_URL_ATTACHMENT",
                    "description": "Submit email attachment and URL payload to sandbox analyzer",
                    "risk": "LOW",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": False
                },
                {
                    "action": "PURGE_MALICIOUS_EMAILS",
                    "description": "Delete phishing email across all internal user mailboxes",
                    "risk": "HIGH",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": True
                }
            ]
        },
        "PLAYBOOK-DATA-EXFIL": {
            "id": "PLAYBOOK-DATA-EXFIL",
            "name": "Data Exfiltration & Network Containment Playbook",
            "category": "NETWORK_ACTIVITY",
            "steps": [
                {
                    "action": "INSPECT_TRAFFIC_VOLUME",
                    "description": "Measure outbound byte count to external IP/Domain",
                    "risk": "LOW",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": False
                },
                {
                    "action": "BLOCK_DESTINATION_IP",
                    "description": "Deploy egress rule to perimeter firewall (Simulated Firewall Block)",
                    "risk": "HIGH",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": True
                }
            ]
        },
        "PLAYBOOK-PRIV-ESC": {
            "id": "PLAYBOOK-PRIV-ESC",
            "name": "Privilege Escalation Containment Playbook",
            "category": "ENDPOINT_EXECUTION",
            "steps": [
                {
                    "action": "AUDIT_PRIVILEGE_TOKENS",
                    "description": "Trace process privilege token elevation history",
                    "risk": "LOW",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": False
                },
                {
                    "action": "TERMINATE_PRIVILEGED_PROCESS",
                    "description": "Kill suspicious elevated process tree (Simulated Process Termination)",
                    "risk": "HIGH",
                    "simulation_status": "SIMULATION ONLY",
                    "approval_required": True
                }
            ]
        }
    }

    @classmethod
    def get_playbook_for_incident(cls, incident: IncidentModel) -> Dict[str, Any]:
        playbook_id = incident.recommended_playbook or "PLAYBOOK-MALWARE"
        return cls.PLAYBOOKS_CATALOG.get(playbook_id, cls.PLAYBOOKS_CATALOG["PLAYBOOK-MALWARE"])

    @classmethod
    def execute_playbook_step(
        cls,
        db: Session,
        incident_id: str,
        playbook_id: str,
        action_name: str,
        analyst_name: str = "analyst@soc.local",
        approved: bool = False
    ) -> Dict[str, Any]:
        """
        Executes a playbook response action in SIMULATION ONLY mode.
        If approval_required is True and approved is False, flags as AWAITING APPROVAL.
        """
        playbook = cls.PLAYBOOKS_CATALOG.get(playbook_id, cls.PLAYBOOKS_CATALOG["PLAYBOOK-MALWARE"])
        target_step = None
        for step in playbook["steps"]:
            if step["action"] == action_name:
                target_step = step
                break

        if not target_step:
            return {"status": "ERROR", "message": f"Action {action_name} not found in playbook {playbook_id}"}

        # Check approval gate
        if target_step["approval_required"] and not approved:
            # Update incident status to AWAITING_APPROVAL
            inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
            if inc:
                inc.status = "AWAITING_APPROVAL"
                db.commit()

            return {
                "status": "APPROVAL_REQUIRED",
                "action": action_name,
                "risk_level": target_step["risk"],
                "message": f"Action '{action_name}' is a high-risk operational response ({target_step['risk']}). Human approval is required before simulation.",
                "simulation_status": "SIMULATION ONLY"
            }

        # Execute Simulation
        run_record = PlaybookRunModel(
            playbook_id=playbook_id,
            incident_id=incident_id,
            action_name=action_name,
            action_description=target_step["description"],
            risk_level=target_step["risk"],
            simulation_status="SIMULATION ONLY",
            approval_required=target_step["approval_required"],
            approval_status="APPROVED_AND_EXECUTED_SIMULATED" if target_step["approval_required"] else "EXECUTED_SIMULATED",
            executed_by=analyst_name,
            timestamp=datetime.now(timezone.utc),
            logs_json={
                "message": f"[SAFE SIMULATION] {target_step['description']} executed successfully.",
                "target_incident": incident_id,
                "safety_guard": "No destructive network or endpoint changes were applied to real infrastructure."
            }
        )
        db.add(run_record)

        # Audit log
        db.add(AuditLogModel(
            actor=analyst_name,
            action="PLAYBOOK_SIMULATION_EXECUTED",
            entity="incident",
            entity_id=incident_id,
            details_json={"action_name": action_name, "playbook_id": playbook_id, "simulation": True}
        ))

        # Advance incident status
        inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
        if inc:
            inc.status = "CONTAINMENT_RECOMMENDED"
            db.commit()

        return {
            "status": "SUCCESS",
            "run_id": run_record.run_id,
            "action": action_name,
            "simulation_status": "SIMULATION ONLY",
            "execution_log": run_record.logs_json["message"]
        }
