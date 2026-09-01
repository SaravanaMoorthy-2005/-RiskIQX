import random
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.db.database import Base, engine
from app.db.models import (
    EventModel, DetectionModel, AssetModel, UserModel,
    ThreatIntelModel, VulnerabilityModel, IncidentModel, IncidentEventJunction,
    CaseModel, ScoringModelConfig, DetectionRuleModel
)
from app.services.normalization import EventNormalizationService
from app.services.enrichment import EnrichmentService
from app.services.detection import DetectionEngine
from app.services.deduplication import DeduplicationService
from app.services.correlation import CorrelationEngine
from app.services.ranking import RankingService
from app.services.risk_scoring import RiskScoringService

def clear_database(db: Session):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def seed_database(db: Session):
    random.seed(42)

    if db.query(EventModel).count() > 50:
        return {"message": "Database already populated."}

    print("Seeding Asset Inventory...")
    assets_data = [
        # Tier 1 - Critical infrastructure
        AssetModel(asset_id="AST-DC-01", hostname="DC-SERVER-01", owner="IT Sec Ops", department="Infrastructure", asset_type="Domain Controller", criticality=5, asset_tier="TIER 1", business_function="Identity & Active Directory", internet_facing=False, data_classification="TOP_SECRET"),
        AssetModel(asset_id="AST-DB-01", hostname="DB-SERVER-01", owner="Data Engineering", department="Finance", asset_type="Database Server", criticality=5, asset_tier="TIER 1", business_function="Core Financial Ledger", internet_facing=False, data_classification="TOP_SECRET"),
        AssetModel(asset_id="AST-K8S-PROD", hostname="PROD-K8S-MASTER", owner="DevOps", department="Engineering", asset_type="Kubernetes Cluster", criticality=5, asset_tier="TIER 1", business_function="Production API Gateway", internet_facing=True, data_classification="RESTRICTED"),
        
        # Tier 2 - Production systems
        AssetModel(asset_id="AST-WEB-01", hostname="WEB-SRV-01", owner="Web Team", department="Marketing", asset_type="Web Server", criticality=4, asset_tier="TIER 2", business_function="Customer Portal", internet_facing=True, data_classification="CONFIDENTIAL"),
        AssetModel(asset_id="AST-AUTH-01", hostname="AUTH-GATEWAY-01", owner="IAM Team", department="Security", asset_type="Auth Proxy", criticality=4, asset_tier="TIER 2", business_function="SSO Gateway", internet_facing=True, data_classification="RESTRICTED"),
        AssetModel(asset_id="AST-HQ-FILES", hostname="HQ-FILES-01", owner="Storage Admins", department="Operations", asset_type="NAS Storage", criticality=4, asset_tier="TIER 2", business_function="Corporate File Share", internet_facing=False, data_classification="RESTRICTED"),

        # Tier 3 - Internal business endpoints
        AssetModel(asset_id="AST-FINANCE-PC", hostname="FINANCE-PC-01", owner="Sarah Connor", department="Finance", asset_type="Workstation", criticality=3, asset_tier="TIER 3", business_function="Finance Laptop", internet_facing=False, data_classification="CONFIDENTIAL"),
        AssetModel(asset_id="AST-DEV-LAPTOP", hostname="DEV-LAPTOP-42", owner="Alex Mercer", department="Engineering", asset_type="Workstation", criticality=3, asset_tier="TIER 3", business_function="Developer Workstation", internet_facing=False, data_classification="INTERNAL"),
        
        # Tier 4 - Low criticality endpoints
        AssetModel(asset_id="AST-GUEST-WIFI", hostname="GUEST-IOT-102", owner="Facility Mgmt", department="Facilities", asset_type="IoT Appliance", criticality=1, asset_tier="TIER 4", business_function="Lobby Display", internet_facing=True, data_classification="PUBLIC")
    ]
    for a in assets_data: db.add(a)

    print("Seeding User Directory...")
    users_data = [
        UserModel(user_id="USR-001", username="admin", department="IT Security", role="Domain Admin", privileged=True, vip=False, risk_level="HIGH"),
        UserModel(user_id="USR-002", username="exec_ceo", department="Executive", role="Chief Executive Officer", privileged=True, vip=True, risk_level="HIGH"),
        UserModel(user_id="USR-003", username="db_admin", department="Data Ops", role="Database Administrator", privileged=True, vip=False, risk_level="HIGH"),
        UserModel(user_id="USR-004", username="svc_account", department="DevOps", role="Service Principal", privileged=True, vip=False, risk_level="HIGH"),
        UserModel(user_id="USR-005", username="finance_user", department="Finance", role="Financial Analyst", privileged=False, vip=False, risk_level="MEDIUM"),
        UserModel(user_id="USR-006", username="jsmith@corp.local", department="Sales", role="Account Executive", privileged=False, vip=False, risk_level="LOW"),
        UserModel(user_id="USR-007", username="contractor_john", department="Vendors", role="External Contractor", privileged=False, vip=False, risk_level="MEDIUM")
    ]
    for u in users_data: db.add(u)

    print("Seeding Threat Intelligence IOCs...")
    ti_data = [
        ThreatIntelModel(ioc_type="ip", ioc_value="185.220.101.5", threat_score=95, malware_family="CobaltStrike C2", campaign="Operation DarkSky", ioc_confidence=0.98, is_malicious=True),
        ThreatIntelModel(ioc_type="ip", ioc_value="198.51.100.44", threat_score=85, malware_family="BruteForce Botnet", campaign="SprayCampaign-2026", ioc_confidence=0.90, is_malicious=True),
        ThreatIntelModel(ioc_type="ip", ioc_value="93.184.216.34", threat_score=90, malware_family="Exfil DropZone", campaign="APT-29 Exfil", ioc_confidence=0.95, is_malicious=True),
        ThreatIntelModel(ioc_type="hash", ioc_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", threat_score=99, malware_family="LockBit 3.0", campaign="GlobalRansom", ioc_confidence=0.99, is_malicious=True),
        ThreatIntelModel(ioc_type="domain", ioc_value="evil-phish-domain.com", threat_score=92, malware_family="Credential Harvester", campaign="PhishDrive", ioc_confidence=0.92, is_malicious=True)
    ]
    for t in ti_data: db.add(t)

    print("Seeding Vulnerabilities...")
    vuln_data = [
        VulnerabilityModel(cve_id="CVE-2024-38077", cvss_score=9.8, exploitability=5, affected_asset_id="AST-DC-01", known_exploited=True, description="Windows Remote Desktop Licensing Service RCE"),
        VulnerabilityModel(cve_id="CVE-2023-34362", cvss_score=9.8, exploitability=5, affected_asset_id="AST-DB-01", known_exploited=True, description="MOVEit Transfer Critical SQL Injection"),
        VulnerabilityModel(cve_id="CVE-2024-21626", cvss_score=8.6, exploitability=4, affected_asset_id="AST-K8S-PROD", known_exploited=False, description="runc Process Container Breakout")
    ]
    for v in vuln_data: db.add(v)

    db.add(ScoringModelConfig(
        version_name="weighted-v1",
        weights_json={"severity": 0.25, "asset_importance": 0.20, "affected_users": 0.15, "data_sensitivity": 0.15, "attack_confidence": 0.15, "business_impact": 0.10},
        thresholds_json={"critical": 90.0, "high": 75.0, "medium": 50.0, "low": 25.0},
        is_active=True
    ))

    db.commit()

    print("Generating High-Fidelity Threat Scenarios across Priority Tiers...")
    now = datetime.now(timezone.utc)

    # Specific High-Fidelity Threat Scenario Templates
    threat_scenarios = [
        # CRITICAL PRIORITY (90-100)
        {
            "title_hint": "Ransomware Attack on Core Financial Database",
            "events": [
                {"source": "EDR", "source_type": "generic_edr", "event_type": "mass_file_encrypt", "category": "FILE_SYSTEM", "severity": 5, "host": "DB-SERVER-01", "user": "db_admin", "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "data_sensitivity": 5, "business_impact": 5, "attack_confidence": 0.98},
                {"source": "EDR", "source_type": "generic_edr", "event_type": "process_creation", "category": "ENDPOINT_EXECUTION", "severity": 5, "host": "DB-SERVER-01", "user": "db_admin", "process_name": "vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet", "data_sensitivity": 5, "business_impact": 5, "attack_confidence": 0.95}
            ]
        },
        {
            "title_hint": "Active Data Exfiltration from Production Customer Database",
            "events": [
                {"source": "FIREWALL", "source_type": "firewall", "event_type": "data_exfiltration", "category": "NETWORK_ACTIVITY", "severity": 5, "host": "DB-SERVER-01", "user": "db_admin", "source_ip": "10.0.1.50", "destination_ip": "93.184.216.34", "data_sensitivity": 5, "business_impact": 5, "attack_confidence": 0.95}
            ]
        },
        {
            "title_hint": "Domain Controller Privilege Escalation & Active Directory Takeover",
            "events": [
                {"source": "SIEM", "source_type": "generic_siem", "event_type": "privilege_escalation", "category": "ENDPOINT_EXECUTION", "severity": 5, "host": "DC-SERVER-01", "user": "admin", "process_name": "mimikatz.exe", "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords", "privileged_user": True, "data_sensitivity": 5, "business_impact": 5, "attack_confidence": 0.96}
            ]
        },

        # HIGH PRIORITY (75-89)
        {
            "title_hint": "Impossible Travel & SSO Login Anomaly from Malicious C2 IP",
            "events": [
                {"source": "AUTH", "source_type": "authentication", "event_type": "impossible_travel", "category": "AUTHENTICATION", "severity": 4, "host": "AUTH-GATEWAY-01", "user": "exec_ceo", "source_ip": "185.220.101.5", "privileged_user": True, "data_sensitivity": 5, "business_impact": 4, "attack_confidence": 0.90}
            ]
        },
        {
            "title_hint": "Suspicious Obfuscated PowerShell Execution on Web Gateway",
            "events": [
                {"source": "EDR", "source_type": "generic_edr", "event_type": "process_creation", "category": "ENDPOINT_EXECUTION", "severity": 4, "host": "WEB-SRV-01", "user": "svc_account", "process_name": "powershell.exe", "command_line": "powershell.exe -Nop -Enc SQBFA...", "data_sensitivity": 4, "business_impact": 4, "attack_confidence": 0.88}
            ]
        },
        {
            "title_hint": "Cloud IAM Admin Key Addition Anomaly on Production K8s",
            "events": [
                {"source": "CLOUD", "source_type": "cloud_security", "event_type": "iam_key_create", "category": "CLOUD_ACTIVITY", "severity": 4, "host": "PROD-K8S-MASTER", "user": "svc_account", "privileged_user": True, "data_sensitivity": 4, "business_impact": 4, "attack_confidence": 0.85}
            ]
        },

        # MEDIUM PRIORITY (50-74)
        {
            "title_hint": "Password Spray & Credential Stuffing Attack",
            "events": [
                {"source": "AUTH", "source_type": "authentication", "event_type": "credential_attack", "category": "AUTHENTICATION", "severity": 3, "host": "AUTH-GATEWAY-01", "user": "jsmith@corp.local", "source_ip": "198.51.100.44", "data_sensitivity": 3, "business_impact": 3, "attack_confidence": 0.80}
            ]
        },
        {
            "title_hint": "Phishing Email with Malicious Credential Harvester Link",
            "events": [
                {"source": "EMAIL", "source_type": "email_security", "event_type": "phishing_email", "category": "EMAIL_SECURITY", "severity": 3, "user": "jsmith@corp.local", "url": "http://evil-phish-domain.com/login", "data_sensitivity": 3, "business_impact": 3, "attack_confidence": 0.80}
            ]
        },
        {
            "title_hint": "Lateral Movement Attempt from Dev Workstation",
            "events": [
                {"source": "SIEM", "source_type": "generic_siem", "event_type": "lateral_movement", "category": "NETWORK_ACTIVITY", "severity": 4, "host": "HQ-FILES-01", "user": "contractor_john", "source_ip": "10.0.4.88", "data_sensitivity": 4, "business_impact": 3, "attack_confidence": 0.85}
            ]
        },
        {
            "title_hint": "Internal Network Subnet Reconnaissance / Port Scan",
            "events": [
                {"source": "IDS", "source_type": "ids_ips", "event_type": "port_scan", "category": "NETWORK_ACTIVITY", "severity": 2, "host": "GUEST-IOT-102", "source_ip": "10.0.4.88", "data_sensitivity": 2, "business_impact": 2, "attack_confidence": 0.75}
            ]
        },

        # LOW PRIORITY (25-49)
        {
            "title_hint": "Repeated Failed Login Attempts on Workstation",
            "events": [
                {"source": "AUTH", "source_type": "authentication", "event_type": "login", "category": "AUTHENTICATION", "severity": 2, "host": "DEV-LAPTOP-42", "user": "contractor_john", "authentication_result": "FAILURE", "data_sensitivity": 2, "business_impact": 2, "attack_confidence": 0.50}
            ]
        },
        {
            "title_hint": "Unusual Outbound HTTP Traffic from IoT Display Appliance",
            "events": [
                {"source": "FIREWALL", "source_type": "firewall", "event_type": "network_connection", "category": "NETWORK_ACTIVITY", "severity": 1, "host": "GUEST-IOT-102", "destination_ip": "192.168.1.100", "data_sensitivity": 1, "business_impact": 1, "attack_confidence": 0.40}
            ]
        }
    ]

    all_db_events = []

    for scen in threat_scenarios:
        for raw_e in scen["events"]:
            raw_e["timestamp"] = (now - timedelta(minutes=random.randint(5, 720))).isoformat()
            norm = EventNormalizationService.normalize(raw_e, source_type=raw_e.get("source_type", "generic_siem"))
            EnrichmentService.enrich_event(db, norm)
            
            db_e = EventModel(**norm.model_dump(exclude_none=True))
            db.add(db_e)
            db.flush()
            
            DeduplicationService.check_and_deduplicate(db, db_e)
            all_db_events.append(db_e)

    # Generate additional 450 general events for volume & analytics distribution
    hosts = ["DC-SERVER-01", "DB-SERVER-01", "PROD-K8S-MASTER", "WEB-SRV-01", "HQ-FILES-01", "FINANCE-PC-01", "DEV-LAPTOP-42", "GUEST-IOT-102"]
    users = ["admin", "exec_ceo", "db_admin", "svc_account", "finance_user", "jsmith@corp.local", "contractor_john"]
    source_ips = ["185.220.101.5", "198.51.100.44", "93.184.216.34", "10.0.1.50", "10.0.2.10", "10.0.4.88", "192.168.1.100"]

    for _ in range(450):
        h = random.choice(hosts)
        u = random.choice(users)
        sip = random.choice(source_ips)
        ts = now - timedelta(minutes=random.randint(1, 1440))

        raw = {
            "timestamp": ts.isoformat(),
            "source": random.choice(["SIEM", "EDR", "FIREWALL", "IDS", "AUTH", "CLOUD", "EMAIL"]),
            "event_type": random.choice(["login", "network_connection", "process_creation", "file_write"]),
            "category": random.choice(["AUTHENTICATION", "NETWORK_ACTIVITY", "ENDPOINT_EXECUTION", "FILE_SYSTEM"]),
            "severity": random.choice([1, 2, 3]),
            "host": h,
            "user": u,
            "source_ip": sip,
            "authentication_result": random.choice(["SUCCESS", "FAILURE"])
        }

        norm = EventNormalizationService.normalize(raw)
        EnrichmentService.enrich_event(db, norm)
        
        db_e = EventModel(**norm.model_dump(exclude_none=True))
        db.add(db_e)
        db.flush()
        
        DeduplicationService.check_and_deduplicate(db, db_e)
        all_db_events.append(db_e)

    db.commit()

    print("Evaluating Detection Rules across normalized events...")
    all_detections = []
    for e in all_db_events:
        dets = DetectionEngine.evaluate_event(db, e)
        all_detections.extend(dets)

    print(f"Generated {len(all_detections)} Detections. Running Correlation Engine...")
    incidents = CorrelationEngine.correlate_detections(db, all_detections)

    print(f"Formed {len(incidents)} Incidents. Calculating 6-Factor Risk Scores & Ranking Queue...")
    sorted_incidents = RankingService.get_prioritized_incidents(db)

    print("Creating Cases & Playbook Runs...")
    for idx, inc in enumerate(sorted_incidents):
        case = CaseModel(
            case_id=f"CASE-{uuid.uuid4().hex[:8].upper()}",
            incident_id=inc.incident_id,
            status=inc.status,
            assigned_analyst="soc_tier2_analyst@corp.local" if idx < 5 else None
        )
        db.add(case)

    db.commit()
    print("Database seeding completed cleanly!")
    return {
        "events": db.query(EventModel).count(),
        "detections": db.query(DetectionModel).count(),
        "incidents": db.query(IncidentModel).count(),
        "cases": db.query(CaseModel).count()
    }
