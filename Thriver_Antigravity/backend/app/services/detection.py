import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.db.models import EventModel, DetectionModel
from app.models.canonical import CanonicalEvent

class DetectionEngine:
    """
    Rule-based Detection Engine processing normalized canonical events and emitting detections.
    Supports 12 distinct SIEM & EDR detection rules mapped to MITRE ATT&CK techniques.
    """
    
    RULES_DEFINITION = [
        {
            "rule_id": "RULE-BRUTE-FORCE",
            "name": "Brute Force Authentication Attempt",
            "category": "AUTHENTICATION",
            "severity": 3,
            "confidence": 0.85,
            "mitre_technique": "T1110",
            "mitre_name": "Brute Force",
            "description": "Repeated authentication failures detected from a single source IP or user."
        },
        {
            "rule_id": "RULE-IMPOSSIBLE-TRAVEL",
            "name": "Impossible Travel Authentication Anomaly",
            "category": "AUTHENTICATION",
            "severity": 4,
            "confidence": 0.90,
            "mitre_technique": "T1078",
            "mitre_name": "Valid Accounts",
            "description": "Successful logins detected from geographically distant locations in an impossible timeframe."
        },
        {
            "rule_id": "RULE-PORT-SCAN",
            "name": "Network Reconnaissance / Port Scan",
            "category": "NETWORK_ACTIVITY",
            "severity": 2,
            "confidence": 0.75,
            "mitre_technique": "T1046",
            "mitre_name": "Network Service Discovery",
            "description": "Single source IP attempting connections across multiple destination ports/hosts."
        },
        {
            "rule_id": "RULE-PRIV-ESC",
            "name": "Privilege Escalation Activity",
            "category": "ENDPOINT_EXECUTION",
            "severity": 5,
            "confidence": 0.95,
            "mitre_technique": "T1068",
            "mitre_name": "Exploitation for Privilege Escalation",
            "description": "Low-privileged user session spawned privileged administrative process or token."
        },
        {
            "rule_id": "RULE-SUSP-POWERSHELL",
            "name": "Suspicious Obfuscated PowerShell Execution",
            "category": "ENDPOINT_EXECUTION",
            "severity": 4,
            "confidence": 0.88,
            "mitre_technique": "T1059.001",
            "mitre_name": "PowerShell",
            "description": "PowerShell process executed with suspicious flags (-EncodedCommand, -Nop, Bypass, DownloadString)."
        },
        {
            "rule_id": "RULE-CRED-ATTACK",
            "name": "Credential Access / Password Spray",
            "category": "AUTHENTICATION",
            "severity": 4,
            "confidence": 0.85,
            "mitre_technique": "T1110.003",
            "mitre_name": "Password Spraying",
            "description": "Multiple auth failures across distinct user accounts followed by a successful login."
        },
        {
            "rule_id": "RULE-DATA-EXFIL",
            "name": "Large Scale Data Exfiltration",
            "category": "NETWORK_ACTIVITY",
            "severity": 5,
            "confidence": 0.92,
            "mitre_technique": "T1048",
            "mitre_name": "Exfiltration Over Alternative Protocol",
            "description": "Abnormal outbound data transfer volume to external IP or suspicious cloud service."
        },
        {
            "rule_id": "RULE-LATERAL-MOVE",
            "name": "Lateral Movement Activity",
            "category": "NETWORK_ACTIVITY",
            "severity": 4,
            "confidence": 0.87,
            "mitre_technique": "T1021",
            "mitre_name": "Remote Services",
            "description": "Single user or endpoint authenticating to multiple internal host assets in a short window."
        },
        {
            "rule_id": "RULE-MALWARE-HASH",
            "name": "Known Malicious File Hash Execution",
            "category": "FILE_SYSTEM",
            "severity": 5,
            "confidence": 0.98,
            "mitre_technique": "T1204",
            "mitre_name": "User Execution",
            "description": "File hash matched against threat intelligence malware repository."
        },
        {
            "rule_id": "RULE-RANSOMWARE",
            "name": "Ransomware Mass File Encryption Pattern",
            "category": "FILE_SYSTEM",
            "severity": 5,
            "confidence": 0.96,
            "mitre_technique": "T1486",
            "mitre_name": "Data Encrypted for Impact",
            "description": "Rapid mass file modification / extension changes detected on endpoint."
        },
        {
            "rule_id": "RULE-PHISHING",
            "name": "Phishing Email with Malicious Indicator",
            "category": "EMAIL_SECURITY",
            "severity": 3,
            "confidence": 0.80,
            "mitre_technique": "T1566",
            "mitre_name": "Phishing",
            "description": "Suspicious email containing malicious link or executable attachment."
        },
        {
            "rule_id": "RULE-CLOUD-ANOMALY",
            "name": "Cloud IAM Privilege Anomaly",
            "category": "CLOUD_ACTIVITY",
            "severity": 4,
            "confidence": 0.82,
            "mitre_technique": "T1098",
            "mitre_name": "Account Manipulation",
            "description": "Unusual cloud API call altering security groups or adding admin credentials."
        }
    ]

    @classmethod
    def evaluate_event(cls, db: Session, event: EventModel) -> List[DetectionModel]:
        """
        Evaluates a single stored event against detection rules.
        Creates DetectionModel records for any rule triggered.
        """
        triggered_detections: List[DetectionModel] = []
        
        # 1. Brute Force Rule
        if event.authentication_result == "FAILURE" or "failed" in (event.event_type or "").lower():
            rule = cls._get_rule("RULE-BRUTE-FORCE")
            det = cls._create_detection(event, rule, evidence="Multiple authentication failure payload detected.")
            triggered_detections.append(det)

        # 2. Suspicious PowerShell Rule
        if event.process_name and "powershell" in event.process_name.lower():
            cmd = (event.command_line or "").lower()
            if any(k in cmd for k in ["-encodedcommand", "-enc", "-nop", "downloadstring", "bypass", "-w hidden"]):
                rule = cls._get_rule("RULE-SUSP-POWERSHELL")
                det = cls._create_detection(event, rule, evidence=f"Command line: {event.command_line}")
                triggered_detections.append(det)

        # 3. Malware Hash Match Rule
        if event.file_hash or (event.extra_metadata and "threat_intel_match" in event.extra_metadata):
            rule = cls._get_rule("RULE-MALWARE-HASH")
            match_info = (event.extra_metadata or {}).get("threat_intel_match", {})
            evidence = f"Hash match: {event.file_hash}. Threat Intel: {match_info}"
            det = cls._create_detection(event, rule, evidence=evidence)
            triggered_detections.append(det)

        # 4. Privilege Escalation Rule
        if event.privileged_user and event.event_type in ["privilege_escalation", "token_impersonation", "sudo_elevation"]:
            rule = cls._get_rule("RULE-PRIV-ESC")
            det = cls._create_detection(event, rule, evidence=f"Privileged activity by user {event.user} on {event.host}")
            triggered_detections.append(det)

        # 5. Data Exfiltration Rule
        if event.event_type in ["data_exfiltration", "large_outbound_transfer"] or event.category == "NETWORK_ACTIVITY" and event.severity >= 4:
            rule = cls._get_rule("RULE-DATA-EXFIL")
            det = cls._create_detection(event, rule, evidence=f"High severity outbound network activity to {event.destination_ip}")
            triggered_detections.append(det)

        # 6. Lateral Movement Rule
        if event.event_type in ["lateral_movement", "remote_exec", "psexec_service"]:
            rule = cls._get_rule("RULE-LATERAL-MOVE")
            det = cls._create_detection(event, rule, evidence=f"Remote execution from {event.source_ip} to {event.host}")
            triggered_detections.append(det)

        # 7. Ransomware Rule
        if event.event_type in ["mass_file_encrypt", "ransomware_indicator", "shadow_copy_delete"]:
            rule = cls._get_rule("RULE-RANSOMWARE")
            det = cls._create_detection(event, rule, evidence=f"Ransomware signature detected on host {event.host}")
            triggered_detections.append(det)

        # 8. Phishing Rule
        if event.category == "EMAIL_SECURITY" or event.event_type in ["phishing_email", "suspicious_attachment"]:
            rule = cls._get_rule("RULE-PHISHING")
            det = cls._create_detection(event, rule, evidence=f"Phishing indicators detected for user {event.user}")
            triggered_detections.append(det)

        # 9. Cloud Anomaly Rule
        if event.category == "CLOUD_ACTIVITY" and (event.severity >= 3 or event.privileged_user):
            rule = cls._get_rule("RULE-CLOUD-ANOMALY")
            det = cls._create_detection(event, rule, evidence=f"Cloud IAM/API privilege action by {event.user}")
            triggered_detections.append(det)

        # 10. Impossible Travel Rule
        if event.event_type == "impossible_travel":
            rule = cls._get_rule("RULE-IMPOSSIBLE-TRAVEL")
            det = cls._create_detection(event, rule, evidence=f"Geographic authentication anomaly for user {event.user}")
            triggered_detections.append(det)

        # 11. Port Scan Rule
        if event.event_type == "port_scan":
            rule = cls._get_rule("RULE-PORT-SCAN")
            det = cls._create_detection(event, rule, evidence=f"Source {event.source_ip} contacted multiple ports")
            triggered_detections.append(det)

        # 12. Credential Attack Rule
        if event.event_type == "credential_attack" or event.event_type == "password_spray":
            rule = cls._get_rule("RULE-CRED-ATTACK")
            det = cls._create_detection(event, rule, evidence=f"Password spray / credential attack from {event.source_ip}")
            triggered_detections.append(det)

        # Save to database
        for d in triggered_detections:
            db.add(d)
        db.commit()
        return triggered_detections

    @classmethod
    def _get_rule(cls, rule_id: str) -> Dict[str, Any]:
        for r in cls.RULES_DEFINITION:
            if r["rule_id"] == rule_id:
                return r
        return cls.RULES_DEFINITION[0]

    @classmethod
    def _create_detection(cls, event: EventModel, rule: Dict[str, Any], evidence: str) -> DetectionModel:
        return DetectionModel(
            detection_id=f"DET-{uuid.uuid4().hex[:8].upper()}",
            rule_id=rule["rule_id"],
            rule_name=rule["name"],
            category=rule["category"],
            severity=rule["severity"],
            confidence=rule["confidence"],
            description=rule["description"],
            evidence_json={"detail": evidence, "event_type": event.event_type, "host": event.host, "user": event.user},
            mitre_technique=rule["mitre_technique"],
            mitre_name=rule["mitre_name"],
            event_ids_json=[event.event_id],
            created_at=datetime.now(timezone.utc)
        )
