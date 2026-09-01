import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.db.models import (
    AssetModel, UserModel, IncidentModel, EventModel, IncidentEventJunction,
    ScoringModelConfig, ThreatIntelModel, VulnerabilityModel, CaseModel, DetectionModel
)
from app.models.scoring import ScoringWeights, PriorityThresholds

SECTOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "healthcare": {
        "id": "healthcare",
        "name": "Healthcare",
        "description": "Patient safety, PHI and clinical systems focused",
        "weights": {
            "severity": 0.25,
            "asset_importance": 0.15,
            "affected_users": 0.15,
            "data_sensitivity": 0.25,
            "attack_confidence": 0.10,
            "business_impact": 0.10,
        },
        "default_version": "weighted-v1-healthcare",
        "assets": [
            {"id": "AST-HC-EHR", "hostname": "EHR-CORE-DB01", "department": "Clinical Informatics", "type": "Database Server", "criticality": 5, "tier": "TIER 1", "func": "Electronic Health Records (EHR)", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-HC-ICU", "hostname": "ICU-TELEMETRY-HUB", "department": "Critical Care", "type": "Medical Gateway", "criticality": 5, "tier": "TIER 1", "func": "ICU Life-Support Telemetry", "internet": False, "data": "RESTRICTED"},
            {"id": "AST-HC-PACS", "hostname": "PACS-IMAGING-SRV", "department": "Radiology", "type": "Imaging Storage", "criticality": 4, "tier": "TIER 2", "func": "Radiology & MRI Image Archive", "internet": False, "data": "CONFIDENTIAL"},
            {"id": "AST-HC-TELE", "hostname": "TELEMED-PORTAL-01", "department": "Outpatient Services", "type": "Web Portal", "criticality": 4, "tier": "TIER 2", "func": "Virtual Doctor Consultations", "internet": True, "data": "CONFIDENTIAL"},
            {"id": "AST-HC-PHARM", "hostname": "PHARM-DISPENSE-01", "department": "Pharmacy", "type": "IoT Dispenser", "criticality": 4, "tier": "TIER 2", "func": "Automated Medication Dispensing", "internet": False, "data": "RESTRICTED"},
            {"id": "AST-HC-CLINIC", "hostname": "NURSE-STATION-4B", "department": "Inpatient Ward", "type": "Workstation", "criticality": 3, "tier": "TIER 3", "func": "Bedside Charting Terminal", "internet": False, "data": "CONFIDENTIAL"},
        ],
        "users": [
            {"id": "USR-HC-01", "name": "ehr_sysadmin", "dept": "Health IT", "role": "EHR System Architect", "priv": True},
            {"id": "USR-HC-02", "name": "dr_chen_chief", "dept": "Cardiology", "role": "Chief Medical Officer", "priv": True},
            {"id": "USR-HC-03", "name": "nurse_sarah_icu", "dept": "Critical Care", "role": "ICU Charge Nurse", "priv": False},
            {"id": "USR-HC-04", "name": "telemed_patient_ops", "dept": "Outpatient", "role": "Patient Navigator", "priv": False},
            {"id": "USR-HC-05", "name": "radiology_tech_bob", "dept": "Diagnostic Imaging", "role": "MRI Specialist", "priv": False},
        ],
        "threats": [
            {
                "id": "INC-HC-001",
                "title": "Ransomware Against EHR",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 4,
                "data_sensitivity": 5,
                "attack_confidence": 0.95,
                "business_impact": 5,
                "assets": ["EHR-CORE-DB01", "ICU-TELEMETRY-HUB"],
                "users": ["ehr_sysadmin", "dr_chen_chief", "nurse_sarah_icu", "telemed_patient_ops"],
                "attack_types": ["Ransomware Execution", "Shadow Copy Deletion", "EHR Interruption"],
                "mitre": ["T1486: Data Encrypted for Impact", "T1490: Inhibit System Recovery"],
                "story": "Sophisticated ransomware deployed against primary electronic health records database, with attempted shadow copy purging threatening hospital-wide clinical admissions.",
                "playbook": "Clinical EHR Isolation & Cold Backup Restoration"
            },
            {
                "id": "INC-HC-002",
                "title": "Medical Device Compromise",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 2,
                "data_sensitivity": 3,
                "attack_confidence": 0.90,
                "business_impact": 5,
                "assets": ["ICU-TELEMETRY-HUB", "PHARM-DISPENSE-01"],
                "users": ["nurse_sarah_icu", "dr_chen_chief"],
                "attack_types": ["Firmware Tampering", "Man-in-the-Middle Telemetry"],
                "mitre": ["T1565: Data Manipulation", "T1199: Trusted Relationship Abuse"],
                "story": "Unauthorized firmware downgrade and anomaly detected in ICU infusion telemetry stream, risking real-time dosing inaccuracies.",
                "playbook": "Medical Device VLAN Quarantine & Manual Failover"
            },
            {
                "id": "INC-HC-003",
                "title": "Patient Data Exfiltration",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 5,
                "data_sensitivity": 5,
                "attack_confidence": 0.85,
                "business_impact": 4,
                "assets": ["PACS-IMAGING-SRV", "EHR-CORE-DB01"],
                "users": ["radiology_tech_bob", "ehr_sysadmin", "nurse_sarah_icu", "dr_chen_chief", "telemed_patient_ops"],
                "attack_types": ["HIPAA Data Exfiltration", "Mass DICOM Export"],
                "mitre": ["T1048: Exfiltration Over Alternative Protocol", "T1005: Data from Local System"],
                "story": "Over 45,000 patient diagnostic scans and medical histories staged to an unauthorized external IP via encrypted DICOM tunnel.",
                "playbook": "HIPAA Breach Containment & Forensic IP Block"
            },
            {
                "id": "INC-HC-004",
                "title": "Healthcare Phishing Campaign",
                "severity": 3,
                "asset_importance": 3,
                "affected_users": 5,
                "data_sensitivity": 4,
                "attack_confidence": 0.90,
                "business_impact": 3,
                "assets": ["NURSE-STATION-4B"],
                "users": ["nurse_sarah_icu", "telemed_patient_ops", "radiology_tech_bob", "dr_chen_chief", "ehr_sysadmin"],
                "attack_types": ["Spear Phishing", "Credential Harvesting"],
                "mitre": ["T1566: Phishing", "T1056: Input Capture"],
                "story": "Targeted clinical staff email campaign spoofing Hospital Accreditation Board credential portal, capturing 5 clinical sessions.",
                "playbook": "Emergency Password Reset & Inbound Domain Block"
            },
            {
                "id": "INC-HC-005",
                "title": "Clinical System Availability Attack",
                "severity": 4,
                "asset_importance": 5,
                "affected_users": 4,
                "data_sensitivity": 3,
                "attack_confidence": 0.80,
                "business_impact": 4,
                "assets": ["PHARM-DISPENSE-01", "NURSE-STATION-4B"],
                "users": ["nurse_sarah_icu", "ehr_sysadmin", "dr_chen_chief", "telemed_patient_ops"],
                "attack_types": ["Denial of Service", "SYN Flood on Clinical Dispatch"],
                "mitre": ["T1498: Network Denial of Service", "T1499: Endpoint DoS"],
                "story": "Distributed SYN flood exhausting automated medication dispenser network interfaces, delaying scheduled ICU pharmaceutical rounds.",
                "playbook": "Anti-DDoS Scrubbing & Emergency Manual Dispatch"
            },
            {
                "id": "INC-HC-006",
                "title": "Telemedicine Account Takeover",
                "severity": 3,
                "asset_importance": 3,
                "affected_users": 3,
                "data_sensitivity": 4,
                "attack_confidence": 0.85,
                "business_impact": 2,
                "assets": ["TELEMED-PORTAL-01"],
                "users": ["telemed_patient_ops", "dr_chen_chief", "nurse_sarah_icu"],
                "attack_types": ["Session Hijacking", "Unauthorized Telehealth Access"],
                "mitre": ["T1539: Steal Web Session Cookie", "T1078: Valid Accounts"],
                "story": "Attacker hijacked doctor virtual consultation tokens from an unmanaged residence laptop, attempting prescription modification.",
                "playbook": "Session Revocation & Ephemeral Token Purge"
            }
        ]
    },
    "banking": {
        "id": "banking",
        "name": "Banking",
        "description": "Financial systems, transaction integrity and fraud focused",
        "weights": {
            "severity": 0.25,
            "asset_importance": 0.20,
            "affected_users": 0.10,
            "data_sensitivity": 0.20,
            "attack_confidence": 0.15,
            "business_impact": 0.10,
        },
        "default_version": "weighted-v1-banking",
        "assets": [
            {"id": "AST-BK-SWIFT", "hostname": "SWIFT-ALLIANCE-GATE", "department": "Treasury", "type": "Transaction Gateway", "criticality": 5, "tier": "TIER 1", "func": "Interbank Settlement & Wire Clearing", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-BK-CORE", "hostname": "CORE-BANKING-LEDGER", "department": "Core Banking", "type": "Mainframe DB", "criticality": 5, "tier": "TIER 1", "func": "Primary Customer Accounts Ledger", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-BK-PAY", "hostname": "PAYMENT-API-GW01", "department": "Retail Payments", "type": "API Cluster", "criticality": 5, "tier": "TIER 1", "func": "Card Payment Processing Engine", "internet": True, "data": "RESTRICTED"},
            {"id": "AST-BK-ATM", "hostname": "ATM-SWITCH-DIRECTOR", "department": "ATM Network", "type": "Switch Controller", "criticality": 4, "tier": "TIER 2", "func": "ATM Fleet Telemetry & Cash Dispense", "internet": False, "data": "CONFIDENTIAL"},
            {"id": "AST-BK-WEB", "hostname": "ONLINE-BANKING-WEB", "department": "Digital Banking", "type": "Web Cluster", "criticality": 4, "tier": "TIER 2", "func": "Retail Customer Portal", "internet": True, "data": "CONFIDENTIAL"},
            {"id": "AST-BK-FRAUD", "hostname": "AML-FRAUD-ANALYTICS", "department": "Compliance", "type": "Analytics Node", "criticality": 4, "tier": "TIER 2", "func": "Anti-Money Laundering Engine", "internet": False, "data": "RESTRICTED"},
        ],
        "users": [
            {"id": "USR-BK-01", "name": "swift_operator_lead", "dept": "Treasury", "role": "Senior Wire Controller", "priv": True},
            {"id": "USR-BK-02", "name": "core_dba_admin", "dept": "Database Engineering", "role": "Mainframe DBA", "priv": True},
            {"id": "USR-BK-03", "name": "payment_api_engineer", "dept": "Merchant Services", "role": "Payments Architect", "priv": True},
            {"id": "USR-BK-04", "name": "retail_fraud_analyst", "dept": "Risk Operations", "role": "Senior Fraud Specialist", "priv": False},
        ],
        "threats": [
            {
                "id": "INC-BK-001",
                "title": "Payment API Attack",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 3,
                "data_sensitivity": 5,
                "attack_confidence": 0.95,
                "business_impact": 5,
                "assets": ["PAYMENT-API-GW01", "CORE-BANKING-LEDGER"],
                "users": ["payment_api_engineer", "core_dba_admin", "swift_operator_lead"],
                "attack_types": ["API Parameter Injection", "Transaction Tampering"],
                "mitre": ["T1190: Exploit Public-Facing Application", "T1059: Command and Scripting Interpreter"],
                "story": "High-velocity token replay and parameter manipulation targeting ISO-20022 payment API, forging card authorization responses.",
                "playbook": "Payment Gateway Hard Isolation & HSM Re-Keying"
            },
            {
                "id": "INC-BK-002",
                "title": "Wire Transfer Fraud",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 2,
                "data_sensitivity": 4,
                "attack_confidence": 0.88,
                "business_impact": 5,
                "assets": ["SWIFT-ALLIANCE-GATE", "CORE-BANKING-LEDGER"],
                "users": ["swift_operator_lead", "core_dba_admin"],
                "attack_types": ["Unauthorized Wire Injection", "Operator Bypass"],
                "mitre": ["T1078: Valid Accounts", "T1565: Data Manipulation"],
                "story": "Unauthorized $12.4M outgoing international settlement messages queued during non-operating hours using compromised dual-authorization certificates.",
                "playbook": "SWIFT Alliance Kill-Switch & Central Clearing Revocation"
            },
            {
                "id": "INC-BK-003",
                "title": "Account Takeover",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 5,
                "data_sensitivity": 5,
                "attack_confidence": 0.90,
                "business_impact": 4,
                "assets": ["ONLINE-BANKING-WEB", "CORE-BANKING-LEDGER"],
                "users": ["retail_fraud_analyst", "payment_api_engineer", "core_dba_admin", "swift_operator_lead"],
                "attack_types": ["MFA Fatigue", "Session Hijacking", "Beneficiary Addition"],
                "mitre": ["T1539: Steal Web Session Cookie", "T1110: Brute Force"],
                "story": "Synchronized takeover of 30+ high-net-worth commercial banking accounts following residential MFA push fatigue attacks.",
                "playbook": "Commercial Account Freeze & Immediate Out-of-Band Callout"
            },
            {
                "id": "INC-BK-004",
                "title": "Credential Stuffing Against Online Banking",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 5,
                "data_sensitivity": 4,
                "attack_confidence": 0.92,
                "business_impact": 3,
                "assets": ["ONLINE-BANKING-WEB"],
                "users": ["retail_fraud_analyst", "payment_api_engineer", "core_dba_admin"],
                "attack_types": ["Credential Stuffing", "Distributed Botnet Proxying"],
                "mitre": ["T1110.004: Credential Stuffing", "T1090: Proxy"],
                "story": "Over 2.8 million automated credential stuffing attempts through residential proxies hitting customer login endpoints with a 1.2% success hit rate.",
                "playbook": "Cloudflare WAF Bot Fight Mode & Forced Password Rotations"
            },
            {
                "id": "INC-BK-005",
                "title": "Banking Data Exfiltration",
                "severity": 4,
                "asset_importance": 5,
                "affected_users": 4,
                "data_sensitivity": 5,
                "attack_confidence": 0.85,
                "business_impact": 4,
                "assets": ["CORE-BANKING-LEDGER", "AML-FRAUD-ANALYTICS"],
                "users": ["core_dba_admin", "retail_fraud_analyst", "payment_api_engineer", "swift_operator_lead"],
                "attack_types": ["SQL Query Exfiltration", "Encrypted Tunneling"],
                "mitre": ["T1005: Data from Local System", "T1048: Exfiltration Over Alternative Protocol"],
                "story": "Suspicious large-scale SQL query dumps of cardholder PANs and IBANs transferred via encrypted SSH tunnel from replica database node.",
                "playbook": "PCI-DSS Data Leakage Containment & Database Firewall Lock"
            },
            {
                "id": "INC-BK-006",
                "title": "Payment Infrastructure Attack",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 4,
                "data_sensitivity": 4,
                "attack_confidence": 0.90,
                "business_impact": 5,
                "assets": ["PAYMENT-API-GW01", "ATM-SWITCH-DIRECTOR"],
                "users": ["payment_api_engineer", "core_dba_admin", "swift_operator_lead", "retail_fraud_analyst"],
                "attack_types": ["Hardware Security Module Disruption", "Infrastructure DoS"],
                "mitre": ["T1499: Endpoint Denial of Service", "T1489: Service Stop"],
                "story": "Repeated cryptographic fault injection attempts targeting the primary HSM cluster, threatening core payment settlement failovers.",
                "playbook": "Failover to Disaster Recovery Settlement Cluster"
            },
            {
                "id": "INC-BK-007",
                "title": "ATM Malware",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 2,
                "data_sensitivity": 2,
                "attack_confidence": 0.80,
                "business_impact": 3,
                "assets": ["ATM-SWITCH-DIRECTOR"],
                "users": ["retail_fraud_analyst", "core_dba_admin"],
                "attack_types": ["ATM Jackpotting Malware", "XFS Subsystem Hooking"],
                "mitre": ["T1055: Process Injection", "T1562: Impair Defenses"],
                "story": "C&C beaconing and XFS API manipulation detected across 14 metropolitan branch ATM controllers attempting cash jackpotting command triggers.",
                "playbook": "ATM Dispenser Bus Disconnect & Fleet Firmware Verification"
            }
        ]
    },
    "ecommerce": {
        "id": "ecommerce",
        "name": "E-Commerce",
        "description": "Customer accounts, checkout availability and transaction protection",
        "weights": {
            "severity": 0.20,
            "asset_importance": 0.15,
            "affected_users": 0.20,
            "data_sensitivity": 0.15,
            "attack_confidence": 0.15,
            "business_impact": 0.15,
        },
        "default_version": "weighted-v1-ecommerce",
        "assets": [
            {"id": "AST-EC-CHECK", "hostname": "CHECKOUT-SERVICE-PROD", "department": "E-Commerce Eng", "type": "Microservice Pod", "criticality": 5, "tier": "TIER 1", "func": "Shopping Cart & Checkout API", "internet": True, "data": "RESTRICTED"},
            {"id": "AST-EC-PAY", "hostname": "PAYMENT-STRIPE-PROXY", "department": "Payments", "type": "API Gateway", "criticality": 5, "tier": "TIER 1", "func": "Stripe/PayPal Card Tokenization", "internet": True, "data": "RESTRICTED"},
            {"id": "AST-EC-INV", "hostname": "INVENTORY-DB-CLUSTER", "department": "Fulfillment", "type": "Database Cluster", "criticality": 4, "tier": "TIER 2", "func": "Real-time Stock & Order Fulfillment", "internet": False, "data": "CONFIDENTIAL"},
            {"id": "AST-EC-USER", "hostname": "CUSTOMER-AUTH-IAM", "department": "Identity", "type": "Auth Service", "criticality": 4, "tier": "TIER 2", "func": "Consumer SSO & Profile Store", "internet": True, "data": "CONFIDENTIAL"},
            {"id": "AST-EC-SEARCH", "hostname": "ELASTIC-CATALOG-SEARCH", "department": "Catalog", "type": "Search Cluster", "criticality": 3, "tier": "TIER 3", "func": "Product Catalog Search Index", "internet": True, "data": "INTERNAL"},
        ],
        "users": [
            {"id": "USR-EC-01", "name": "lead_checkout_dev", "dept": "Storefront", "role": "Staff Engineer", "priv": True},
            {"id": "USR-EC-02", "name": "fulfillment_ops_manager", "dept": "Logistics", "role": "Supply Chain Director", "priv": False},
            {"id": "USR-EC-03", "name": "customer_support_lead", "dept": "Support", "role": "Escalations Specialist", "priv": False},
            {"id": "USR-EC-04", "name": "secops_analyst_ec", "dept": "Security", "role": "SOC Engineer", "priv": True},
        ],
        "threats": [
            {
                "id": "INC-EC-001",
                "title": "Payment Gateway Attack",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 4,
                "data_sensitivity": 5,
                "attack_confidence": 0.95,
                "business_impact": 5,
                "assets": ["PAYMENT-STRIPE-PROXY", "CHECKOUT-SERVICE-PROD"],
                "users": ["lead_checkout_dev", "secops_analyst_ec", "fulfillment_ops_manager", "customer_support_lead"],
                "attack_types": ["Magecart Web Skimmer", "Formjacking"],
                "mitre": ["T1059.007: JavaScript Insertion", "T1056: Input Capture"],
                "story": "Obfuscated JavaScript skimmer injected into production checkout bundle via compromised third-party analytics script tag.",
                "playbook": "CDN Bundle Rollback & Subresource Integrity Enforcement"
            },
            {
                "id": "INC-EC-002",
                "title": "Checkout API Abuse",
                "severity": 4,
                "asset_importance": 5,
                "affected_users": 5,
                "data_sensitivity": 4,
                "attack_confidence": 0.92,
                "business_impact": 5,
                "assets": ["CHECKOUT-SERVICE-PROD", "INVENTORY-DB-CLUSTER"],
                "users": ["lead_checkout_dev", "fulfillment_ops_manager", "secops_analyst_ec", "customer_support_lead"],
                "attack_types": ["Race Condition Exploit", "Negative Price Order Injection"],
                "mitre": ["T1190: Exploit Public-Facing Application", "T1068: Exploitation for Privilege Escalation"],
                "story": "Adversary exploiting concurrency lock race condition in coupon application logic, draining $340k in promotional credit.",
                "playbook": "Rate Limiting Ingress Rules & Idempotency Key Lock"
            },
            {
                "id": "INC-EC-003",
                "title": "Customer Account Takeover",
                "severity": 4,
                "asset_importance": 3,
                "affected_users": 5,
                "data_sensitivity": 4,
                "attack_confidence": 0.90,
                "business_impact": 4,
                "assets": ["CUSTOMER-AUTH-IAM"],
                "users": ["customer_support_lead", "lead_checkout_dev", "secops_analyst_ec", "fulfillment_ops_manager"],
                "attack_types": ["Credential Stuffing", "Loyalty Point Draining"],
                "mitre": ["T1110.004: Credential Stuffing", "T1539: Steal Web Session Cookie"],
                "story": "Coordinated bot network brute-forcing customer profiles, re-routing saved shipping addresses, and depleting reward points on luxury items.",
                "playbook": "Revoke Customer Tokens & Enable Mandatory CAPTCHA"
            },
            {
                "id": "INC-EC-004",
                "title": "Customer PII Exposure",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 5,
                "data_sensitivity": 5,
                "attack_confidence": 0.85,
                "business_impact": 4,
                "assets": ["CUSTOMER-AUTH-IAM", "INVENTORY-DB-CLUSTER"],
                "users": ["lead_checkout_dev", "secops_analyst_ec", "customer_support_lead", "fulfillment_ops_manager"],
                "attack_types": ["IDOR Vulnerability", "Bulk PII Scraping"],
                "mitre": ["T1005: Data from Local System", "T1552: Unsecured Credentials"],
                "story": "Broken object-level authorization on order tracking endpoint allowing unauthenticated scraping of customer phone numbers and home addresses.",
                "playbook": "API Route Hotfix & Perimeter Web Application Firewall Rule"
            },
            {
                "id": "INC-EC-005",
                "title": "E-Commerce Ransomware",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 4,
                "data_sensitivity": 4,
                "attack_confidence": 0.90,
                "business_impact": 5,
                "assets": ["INVENTORY-DB-CLUSTER", "CHECKOUT-SERVICE-PROD"],
                "users": ["fulfillment_ops_manager", "lead_checkout_dev", "secops_analyst_ec"],
                "attack_types": ["Database Encryption", "Fulfillment Lockout"],
                "mitre": ["T1486: Data Encrypted for Impact", "T1489: Service Stop"],
                "story": "Ransomware encryption targeting warehouse relational database volumes, halting package labeling and same-day delivery dispatch.",
                "playbook": "Failover to Multi-Region Read Replica & Read-Only Store Mode"
            },
            {
                "id": "INC-EC-006",
                "title": "Bot-Based Inventory Abuse",
                "severity": 3,
                "asset_importance": 4,
                "affected_users": 3,
                "data_sensitivity": 2,
                "attack_confidence": 0.85,
                "business_impact": 4,
                "assets": ["CHECKOUT-SERVICE-PROD", "ELASTIC-CATALOG-SEARCH"],
                "users": ["lead_checkout_dev", "fulfillment_ops_manager", "customer_support_lead"],
                "attack_types": ["Scalping Bot Automation", "Cart Hoarding Denial of Inventory"],
                "mitre": ["T1499: Endpoint DoS", "T1071: Application Layer Protocol"],
                "story": "Automated scalping bots holding 18,000 limited-edition units in temporary checkout reservations, blocking genuine consumers.",
                "playbook": "Cart Reservation Expiration Clamp & Device Fingerprint Throttling"
            },
            {
                "id": "INC-EC-007",
                "title": "Credential Stuffing",
                "severity": 3,
                "asset_importance": 3,
                "affected_users": 5,
                "data_sensitivity": 3,
                "attack_confidence": 0.88,
                "business_impact": 3,
                "assets": ["CUSTOMER-AUTH-IAM"],
                "users": ["customer_support_lead", "lead_checkout_dev", "secops_analyst_ec"],
                "attack_types": ["High-Volume Login Testing", "Proxy Rotation"],
                "mitre": ["T1110.004: Credential Stuffing"],
                "story": "Distributed credential stuffing barrage testing breached combo lists against checkout customer login gateways.",
                "playbook": "Geographic IP Anomaly Blocking & Rate Limiting"
            }
        ]
    },
    "saas": {
        "id": "saas",
        "name": "SaaS / Technology",
        "description": "Cloud infrastructure, tenant isolation, APIs and supply chain security",
        "weights": {
            "severity": 0.20,
            "asset_importance": 0.20,
            "affected_users": 0.15,
            "data_sensitivity": 0.15,
            "attack_confidence": 0.15,
            "business_impact": 0.15,
        },
        "default_version": "weighted-v1-saas",
        "assets": [
            {"id": "AST-SAAS-K8S", "hostname": "K8S-PROD-EKS-CLUSTER", "department": "Platform Eng", "type": "Kubernetes Cluster", "criticality": 5, "tier": "TIER 1", "func": "Multi-Tenant Container Orchestration", "internet": True, "data": "TOP_SECRET"},
            {"id": "AST-SAAS-VAULT", "hostname": "HASHICORP-VAULT-PROD", "department": "SecOps", "type": "Key Management", "criticality": 5, "tier": "TIER 1", "func": "Customer Secrets & Encryption Keys", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-SAAS-API", "hostname": "CORE-GATEWAY-ENVOY", "department": "API Infrastructure", "type": "API Mesh", "criticality": 5, "tier": "TIER 1", "func": "Public API Routing & Authentication", "internet": True, "data": "RESTRICTED"},
            {"id": "AST-SAAS-DB", "hostname": "AURORA-MULTITENANT-DB", "department": "Data Platform", "type": "Managed DB", "criticality": 4, "tier": "TIER 2", "func": "Multi-Tenant Workload Storage", "internet": False, "data": "RESTRICTED"},
            {"id": "AST-SAAS-CI", "hostname": "GITHUB-ACTIONS-RUNNER", "department": "DevOps", "type": "Build Runner", "criticality": 4, "tier": "TIER 2", "func": "Continuous Integration Build Agent", "internet": True, "data": "CONFIDENTIAL"},
        ],
        "users": [
            {"id": "USR-SAAS-01", "name": "platform_lead_sre", "dept": "SRE", "role": "Principal SRE", "priv": True},
            {"id": "USR-SAAS-02", "name": "iam_security_architect", "dept": "Cloud Security", "role": "Staff SecOps", "priv": True},
            {"id": "USR-SAAS-03", "name": "backend_api_dev", "dept": "Core Services", "role": "Senior Engineer", "priv": False},
            {"id": "USR-SAAS-04", "name": "devops_build_bot", "dept": "Platform", "role": "CI Service Account", "priv": True},
        ],
        "threats": [
            {
                "id": "INC-SAAS-001",
                "title": "Tenant Isolation Failure",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 5,
                "data_sensitivity": 5,
                "attack_confidence": 0.95,
                "business_impact": 5,
                "assets": ["AURORA-MULTITENANT-DB", "K8S-PROD-EKS-CLUSTER"],
                "users": ["platform_lead_sre", "backend_api_dev", "iam_security_architect", "devops_build_bot"],
                "attack_types": ["Tenant Boundary Escape", "Cross-Org Query Leak"],
                "mitre": ["T1190: Exploit Public-Facing Application", "T1005: Data from Local System"],
                "story": "Flaw in row-level security policy engine allowed organization tenant ID parameter substitution, exposing enterprise customer data across tenants.",
                "playbook": "Emergency RLS Policy Enforcement & Customer Notification"
            },
            {
                "id": "INC-SAAS-002",
                "title": "Cloud Account Compromise",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 4,
                "data_sensitivity": 4,
                "attack_confidence": 0.92,
                "business_impact": 5,
                "assets": ["K8S-PROD-EKS-CLUSTER", "CORE-GATEWAY-ENVOY"],
                "users": ["platform_lead_sre", "iam_security_architect", "devops_build_bot"],
                "attack_types": ["AWS Root Role Abuse", "CloudTrail Disablement"],
                "mitre": ["T1078.004: Cloud Accounts", "T1562.001: Disable or Modify Tools"],
                "story": "Compromised AWS admin access key used from unexpected foreign ASN to spin up rogue GPU instances and modify VPC peering tables.",
                "playbook": "IAM Credential Revocation & Cloud Incident Containment"
            },
            {
                "id": "INC-SAAS-003",
                "title": "Software Supply Chain Attack",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 5,
                "data_sensitivity": 4,
                "attack_confidence": 0.90,
                "business_impact": 5,
                "assets": ["GITHUB-ACTIONS-RUNNER", "CORE-GATEWAY-ENVOY"],
                "users": ["devops_build_bot", "platform_lead_sre", "backend_api_dev", "iam_security_architect"],
                "attack_types": ["Dependency Typosquatting", "Build Pipeline Poisoning"],
                "mitre": ["T1195.002: Vulnerabilities in Third-Party Software", "T1059: Command Execution"],
                "story": "Malicious npm dependency injected into main deployment pipeline via typosquatted package, beaconing environment secrets to external dropzone.",
                "playbook": "Kill CI Runners & Purge Artifact Repository Cache"
            },
            {
                "id": "INC-SAAS-004",
                "title": "Secrets Exposure",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 3,
                "data_sensitivity": 5,
                "attack_confidence": 0.88,
                "business_impact": 4,
                "assets": ["HASHICORP-VAULT-PROD"],
                "users": ["iam_security_architect", "platform_lead_sre", "backend_api_dev"],
                "attack_types": ["Hardcoded API Key Leak", "Vault Token Hijack"],
                "mitre": ["T1552.001: Credentials in Files", "T1555: Credentials from Password Stores"],
                "story": "Production Vault root-level signing key accidentally committed to public Git repository during developer debugging session.",
                "playbook": "Immediate Key Revocation & Vault Auto-Roll Rotation"
            },
            {
                "id": "INC-SAAS-005",
                "title": "API Authorization Bypass",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 4,
                "data_sensitivity": 4,
                "attack_confidence": 0.90,
                "business_impact": 4,
                "assets": ["CORE-GATEWAY-ENVOY"],
                "users": ["backend_api_dev", "platform_lead_sre", "iam_security_architect"],
                "attack_types": ["BOLA/IDOR", "JWT Signature Stripping"],
                "mitre": ["T1190: Exploit Public-Facing Application", "T1078: Valid Accounts"],
                "story": "Alg 'none' JWT signature stripping bypass on enterprise administrative billing and license upgrade endpoint.",
                "playbook": "Envoy JWT Filter Strict Verification Hotfix"
            },
            {
                "id": "INC-SAAS-006",
                "title": "Cloud Data Exfiltration",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 4,
                "data_sensitivity": 5,
                "attack_confidence": 0.85,
                "business_impact": 4,
                "assets": ["AURORA-MULTITENANT-DB"],
                "users": ["backend_api_dev", "platform_lead_sre", "iam_security_architect"],
                "attack_types": ["S3 Bucket Sync Leak", "Mass Read Query"],
                "mitre": ["T1530: Data from Cloud Storage", "T1048: Exfiltration"],
                "story": "Adversary abusing compromised read-only service account to initiate cross-account S3 sync of 1.4 TB telemetry archive.",
                "playbook": "Apply S3 Bucket Block Public Access & VPC Endpoint Lockdown"
            }
        ]
    },
    "government": {
        "id": "government",
        "name": "Government",
        "description": "Citizen data, critical infrastructure and national services",
        "weights": {
            "severity": 0.25,
            "asset_importance": 0.20,
            "affected_users": 0.15,
            "data_sensitivity": 0.20,
            "attack_confidence": 0.10,
            "business_impact": 0.10,
        },
        "default_version": "weighted-v1-government",
        "assets": [
            {"id": "AST-GOV-CIT", "hostname": "CITIZEN-IDENTITY-CORE", "department": "Civil Registry", "type": "Identity DB", "criticality": 5, "tier": "TIER 1", "func": "National Citizen ID & Biometric Records", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-GOV-GRID", "hostname": "GRID-SCADA-SUPERVISOR", "department": "Energy & Infrastructure", "type": "SCADA Host", "criticality": 5, "tier": "TIER 1", "func": "State Energy Distribution Dispatch", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-GOV-PORTAL", "hostname": "GOV-SERVICES-GATEWAY", "department": "Digital Government", "type": "Web Cluster", "criticality": 4, "tier": "TIER 2", "func": "Public Services & Benefits Portal", "internet": True, "data": "CONFIDENTIAL"},
            {"id": "AST-GOV-TAX", "hostname": "REVENUE-TAX-FILING", "department": "Revenue Dept", "type": "Financial App", "criticality": 4, "tier": "TIER 2", "func": "Annual Tax Processing Engine", "internet": True, "data": "RESTRICTED"},
        ],
        "users": [
            {"id": "USR-GOV-01", "name": "national_security_officer", "dept": "Homeland Defense", "role": "Lead Defense Analyst", "priv": True},
            {"id": "USR-GOV-02", "name": "registry_director", "dept": "Civil Registry", "role": "Database Administrator", "priv": True},
            {"id": "USR-GOV-03", "name": "public_portal_admin", "dept": "Digital Services", "role": "Web Operations Manager", "priv": False},
        ],
        "threats": [
            {
                "id": "INC-GOV-001",
                "title": "Nation-State Intrusion",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 3,
                "data_sensitivity": 5,
                "attack_confidence": 0.95,
                "business_impact": 5,
                "assets": ["CITIZEN-IDENTITY-CORE", "GRID-SCADA-SUPERVISOR"],
                "users": ["national_security_officer", "registry_director", "public_portal_admin"],
                "attack_types": ["Advanced Persistent Threat (APT)", "Zero-Day Exploitation"],
                "mitre": ["T1190: Exploit Public-Facing Application", "T1021: Remote Services"],
                "story": "Sophisticated state-sponsored actor (APT-41 equivalent) exploiting zero-day vulnerability in edge VPN router to establish persistent lateral persistence.",
                "playbook": "National Threat Emergency Response & Classified Enclave Quarantine"
            },
            {
                "id": "INC-GOV-002",
                "title": "Critical Infrastructure Attack",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 5,
                "data_sensitivity": 4,
                "attack_confidence": 0.90,
                "business_impact": 5,
                "assets": ["GRID-SCADA-SUPERVISOR"],
                "users": ["national_security_officer", "registry_director"],
                "attack_types": ["SCADA Protocol Tampering", "Substation Controller Overload"],
                "mitre": ["T0831: Manipulation of Control", "T0855: Unauthorized Command Message"],
                "story": "Anomalous DNP3 control commands sent to power distribution substation controllers, threatening regional electrical grid brownouts.",
                "playbook": "Switch SCADA Network to Isolated Island Mode"
            },
            {
                "id": "INC-GOV-003",
                "title": "Citizen Data Breach",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 5,
                "data_sensitivity": 5,
                "attack_confidence": 0.88,
                "business_impact": 4,
                "assets": ["CITIZEN-IDENTITY-CORE", "REVENUE-TAX-FILING"],
                "users": ["registry_director", "public_portal_admin", "national_security_officer"],
                "attack_types": ["Bulk SSN Exfiltration", "Privilege Escalation"],
                "mitre": ["T1005: Data from Local System", "T1048: Exfiltration"],
                "story": "Unauthorized dump of 1.2 million citizen social security identifiers and tax filings staged through encrypted external FTP channel.",
                "playbook": "Revoke Civilian Database Credentials & Launch Forensic Audit"
            },
            {
                "id": "INC-GOV-004",
                "title": "Sensitive Document Exfiltration",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 2,
                "data_sensitivity": 5,
                "attack_confidence": 0.90,
                "business_impact": 4,
                "assets": ["CITIZEN-IDENTITY-CORE"],
                "users": ["national_security_officer", "registry_director"],
                "attack_types": ["Classified Briefing Exfil", "USB Rubber Ducky Device"],
                "mitre": ["T1052: Exfiltration Over Physical Medium", "T1025: Data from Removable Media"],
                "story": "Physical rogue HID implant detected on secure terminal in high-clearance ministry conference wing copying policy whitepapers.",
                "playbook": "Physical Terminal Air-Gapping & Security Countermeasure Scans"
            },
            {
                "id": "INC-GOV-005",
                "title": "Government Portal Attack",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 5,
                "data_sensitivity": 3,
                "attack_confidence": 0.85,
                "business_impact": 4,
                "assets": ["GOV-SERVICES-GATEWAY"],
                "users": ["public_portal_admin", "registry_director"],
                "attack_types": ["DDoS Attack", "Defacement Attempt"],
                "mitre": ["T1498: Network Denial of Service", "T1491: Defacement"],
                "story": "Massive terabit volumetric DDoS paired with SQL injection attempts targeting voter registration and social welfare portals.",
                "playbook": "National Cyber Defense Perimeter Shield Activation"
            },
            {
                "id": "INC-GOV-006",
                "title": "Credential Compromise",
                "severity": 3,
                "asset_importance": 4,
                "affected_users": 4,
                "data_sensitivity": 4,
                "attack_confidence": 0.80,
                "business_impact": 3,
                "assets": ["REVENUE-TAX-FILING"],
                "users": ["public_portal_admin", "registry_director", "national_security_officer"],
                "attack_types": ["Staff Credential Compromise", "Shadow IT"],
                "mitre": ["T1078: Valid Accounts"],
                "story": "Department staff credentials compromised via unauthorized third-party file sharing tool installed on administrative laptop.",
                "playbook": "Disable Account Active Directory Profile & Re-Image Asset"
            }
        ]
    },
    "education": {
        "id": "education",
        "name": "Education",
        "description": "Student privacy, campus systems, research data and academic accounts",
        "weights": {
            "severity": 0.20,
            "asset_importance": 0.15,
            "affected_users": 0.20,
            "data_sensitivity": 0.20,
            "attack_confidence": 0.10,
            "business_impact": 0.15,
        },
        "default_version": "weighted-v1-education",
        "assets": [
            {"id": "AST-EDU-LMS", "hostname": "CANVAS-LMS-HOST01", "department": "Academic IT", "type": "Learning Management", "criticality": 4, "tier": "TIER 2", "func": "Coursework, Exams & Grading", "internet": True, "data": "CONFIDENTIAL"},
            {"id": "AST-EDU-RES", "hostname": "QUANTUM-RESEARCH-GRID", "department": "Physics & Engineering", "type": "HPC Supercomputer", "criticality": 5, "tier": "TIER 1", "func": "Grant-Funded Classified Quantum Research", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-EDU-SIS", "hostname": "STUDENT-INFO-SYSTEM", "department": "Registrar", "type": "Database Server", "criticality": 4, "tier": "TIER 2", "func": "Student Enrollment & Financial Aid", "internet": False, "data": "RESTRICTED"},
            {"id": "AST-EDU-CAMPUS", "hostname": "CAMPUS-WIFI-CONTROLLER", "department": "Network Ops", "type": "Wireless Controller", "criticality": 3, "tier": "TIER 3", "func": "Campus-wide Wi-Fi Access Points", "internet": True, "data": "INTERNAL"},
        ],
        "users": [
            {"id": "USR-EDU-01", "name": "prof_hawking_pi", "dept": "Research Lab", "role": "Principal Investigator", "priv": True},
            {"id": "USR-EDU-02", "name": "registrar_director", "dept": "Admissions", "role": "Registrar Administrator", "priv": True},
            {"id": "USR-EDU-03", "name": "student_affairs_admin", "dept": "Dean Office", "role": "Student Coordinator", "priv": False},
            {"id": "USR-EDU-04", "name": "campus_network_eng", "dept": "IT Services", "role": "Network Specialist", "priv": False},
        ],
        "threats": [
            {
                "id": "INC-EDU-001",
                "title": "University Ransomware",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 5,
                "data_sensitivity": 4,
                "attack_confidence": 0.95,
                "business_impact": 5,
                "assets": ["STUDENT-INFO-SYSTEM", "CANVAS-LMS-HOST01"],
                "users": ["registrar_director", "prof_hawking_pi", "student_affairs_admin", "campus_network_eng"],
                "attack_types": ["Campus Ransomware", "Backup Deletion"],
                "mitre": ["T1486: Data Encrypted for Impact", "T1490: Inhibit System Recovery"],
                "story": "Double-extortion ransomware encrypting student record databases and threatening publication of financial aid information before finals week.",
                "playbook": "Isolate Academic Network Subnets & Restore Air-Gapped Tapes"
            },
            {
                "id": "INC-EDU-002",
                "title": "Research Data Theft",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 2,
                "data_sensitivity": 5,
                "attack_confidence": 0.90,
                "business_impact": 4,
                "assets": ["QUANTUM-RESEARCH-GRID"],
                "users": ["prof_hawking_pi", "registrar_director"],
                "attack_types": ["IP Exfiltration", "Foreign Intelligence Targeting"],
                "mitre": ["T1005: Data from Local System", "T1048: Exfiltration"],
                "story": "Covert exfiltration of proprietary quantum algorithm research data funded by national defense grants to a foreign university mirror.",
                "playbook": "Air-Gap HPC Cluster & Notify Federal Grant Compliance"
            },
            {
                "id": "INC-EDU-003",
                "title": "Student Data Breach",
                "severity": 4,
                "asset_importance": 3,
                "affected_users": 5,
                "data_sensitivity": 5,
                "attack_confidence": 0.88,
                "business_impact": 4,
                "assets": ["STUDENT-INFO-SYSTEM"],
                "users": ["registrar_director", "student_affairs_admin", "prof_hawking_pi", "campus_network_eng"],
                "attack_types": ["FERPA Breach", "SQL Injection"],
                "mitre": ["T1190: Exploit Public-Facing Application", "T1005: Data from Local System"],
                "story": "SQL injection in student transcript request form leading to disclosure of 42,000 student grades, birth dates, and tuition payment cards.",
                "playbook": "FERPA Disclosure Protocol & WAF Virtual Patching"
            },
            {
                "id": "INC-EDU-004",
                "title": "Learning Management System Attack",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 5,
                "data_sensitivity": 3,
                "attack_confidence": 0.85,
                "business_impact": 4,
                "assets": ["CANVAS-LMS-HOST01"],
                "users": ["student_affairs_admin", "prof_hawking_pi", "registrar_director", "campus_network_eng"],
                "attack_types": ["Grade Tampering", "Privilege Escalation"],
                "mitre": ["T1068: Exploitation for Privilege Escalation", "T1565: Data Manipulation"],
                "story": "Unauthorized grade modification script elevating course test scores across undergraduate computer science curriculum.",
                "playbook": "Roll Back Gradebook Logs & Enforce Faculty FIDO2 MFA"
            },
            {
                "id": "INC-EDU-005",
                "title": "Campus Network Compromise",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 5,
                "data_sensitivity": 3,
                "attack_confidence": 0.80,
                "business_impact": 3,
                "assets": ["CAMPUS-WIFI-CONTROLLER"],
                "users": ["campus_network_eng", "student_affairs_admin", "registrar_director"],
                "attack_types": ["Rogue AP", "DNS Hijacking"],
                "mitre": ["T1557: Adversary-in-the-Middle", "T1071: Standard Protocol"],
                "story": "Evil twin wireless access points deployed across student union cafeteria intercepting unencrypted institutional credentials.",
                "playbook": "Wireless Intrusion Prevention Rogue AP Triangulation"
            },
            {
                "id": "INC-EDU-006",
                "title": "Faculty Account Takeover",
                "severity": 3,
                "asset_importance": 3,
                "affected_users": 3,
                "data_sensitivity": 4,
                "attack_confidence": 0.82,
                "business_impact": 3,
                "assets": ["CANVAS-LMS-HOST01"],
                "users": ["prof_hawking_pi", "registrar_director", "student_affairs_admin"],
                "attack_types": ["Phished Faculty Credentials", "Exam Leak"],
                "mitre": ["T1566: Phishing", "T1078: Valid Accounts"],
                "story": "Phished departmental faculty credentials used to access upcoming final exam question banks and distribution keys.",
                "playbook": "Reset Department Account Sessions & Re-Issue Examination Papers"
            }
        ]
    },
    "manufacturing": {
        "id": "manufacturing",
        "name": "Manufacturing",
        "description": "OT/ICS, SCADA, production continuity and industrial safety",
        "weights": {
            "severity": 0.25,
            "asset_importance": 0.20,
            "affected_users": 0.10,
            "data_sensitivity": 0.10,
            "attack_confidence": 0.15,
            "business_impact": 0.20,
        },
        "default_version": "weighted-v1-manufacturing",
        "assets": [
            {"id": "AST-MFG-SCADA", "hostname": "SCADA-PLANT-MASTER", "department": "Plant Automation", "type": "Industrial Server", "criticality": 5, "tier": "TIER 1", "func": "Assembly Line Robotics Supervisor", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-MFG-PLC", "hostname": "SIEMENS-S7-PLC-RACK", "department": "OT Operations", "type": "PLC Controller", "criticality": 5, "tier": "TIER 1", "func": "High-Pressure Hydraulic Stamping", "internet": False, "data": "TOP_SECRET"},
            {"id": "AST-MFG-MES", "hostname": "MES-DISPATCH-SERVER", "department": "Manufacturing Execution", "type": "MES Host", "criticality": 4, "tier": "TIER 2", "func": "Batch Recipe & Work-In-Progress Flow", "internet": False, "data": "RESTRICTED"},
            {"id": "AST-MFG-SUP", "hostname": "SUPPLIER-EDI-PORTAL", "department": "Logistics & Purchasing", "type": "EDI Gateway", "criticality": 4, "tier": "TIER 2", "func": "Raw Material Supplier Automation", "internet": True, "data": "CONFIDENTIAL"},
            {"id": "AST-MFG-CAD", "hostname": "DESIGN-CAD-VAULT", "department": "R&D Engineering", "type": "CAD Storage", "criticality": 4, "tier": "TIER 2", "func": "Patented Turbine Blueprints", "internet": False, "data": "CONFIDENTIAL"},
        ],
        "users": [
            {"id": "USR-MFG-01", "name": "lead_ot_engineer", "dept": "Plant Operations", "role": "Lead Automation Engineer", "priv": True},
            {"id": "USR-MFG-02", "name": "plant_operations_dir", "dept": "Operations", "role": "Plant General Manager", "priv": True},
            {"id": "USR-MFG-03", "name": "cad_patent_designer", "dept": "R&D", "role": "Principal Mechanical Engineer", "priv": False},
            {"id": "USR-MFG-04", "name": "supplier_coordinator", "dept": "Procurement", "role": "Logistics Planner", "priv": False},
        ],
        "threats": [
            {
                "id": "INC-MFG-001",
                "title": "OT/ICS Compromise",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 2,
                "data_sensitivity": 3,
                "attack_confidence": 0.95,
                "business_impact": 5,
                "assets": ["SCADA-PLANT-MASTER", "SIEMENS-S7-PLC-RACK"],
                "users": ["lead_ot_engineer", "plant_operations_dir"],
                "attack_types": ["PLC Logic Injection", "Safety System Overwrite"],
                "mitre": ["T0831: Manipulation of Control", "T0855: Unauthorized Command"],
                "story": "Malicious engineering workstation reprogramming safety-instrumented system (SIS) thresholds on heavy industrial hydraulic presses.",
                "playbook": "OT Safety Interlock Trip & Emergency Plant Floor Scram"
            },
            {
                "id": "INC-MFG-002",
                "title": "Production Line Disruption",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 2,
                "data_sensitivity": 2,
                "attack_confidence": 0.92,
                "business_impact": 5,
                "assets": ["SCADA-PLANT-MASTER", "MES-DISPATCH-SERVER"],
                "users": ["lead_ot_engineer", "plant_operations_dir"],
                "attack_types": ["Robotic Cell Stoppage", "Modbus Protocol Flood"],
                "mitre": ["T0814: Denial of Service", "T0804: Block Reporting"],
                "story": "Modbus TCP flood saturating assembly line conveyor bus, stalling $2.4M/hour automotive chassis welding operations.",
                "playbook": "Reboot Automation Switch & Switch to Offline Staging Buffer"
            },
            {
                "id": "INC-MFG-003",
                "title": "Industrial Ransomware",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 3,
                "data_sensitivity": 3,
                "attack_confidence": 0.94,
                "business_impact": 5,
                "assets": ["MES-DISPATCH-SERVER", "DESIGN-CAD-VAULT"],
                "users": ["plant_operations_dir", "lead_ot_engineer", "cad_patent_designer"],
                "attack_types": ["OT Historian Encryption", "Factory Floor Lockout"],
                "mitre": ["T1486: Data Encrypted for Impact", "T1489: Service Stop"],
                "story": "Targeted manufacturing ransomware (EKANS variant) terminating industrial processes and encrypting manufacturing execution system dispatchers.",
                "playbook": "Sever Purdue Model Level 3/2 Boundary Firewall"
            },
            {
                "id": "INC-MFG-004",
                "title": "SCADA Attack",
                "severity": 5,
                "asset_importance": 5,
                "affected_users": 1,
                "data_sensitivity": 2,
                "attack_confidence": 0.90,
                "business_impact": 5,
                "assets": ["SCADA-PLANT-MASTER"],
                "users": ["lead_ot_engineer"],
                "attack_types": ["HMI Screen Hijacking", "False Sensor Telemetry"],
                "mitre": ["T0836: Modify Parameter", "T0856: Spoof Reporting"],
                "story": "Rogue technician laptop spoofing thermocouple telemetry readings to HMI operators while heating chemical smelting reactors beyond tolerance.",
                "playbook": "Manual Pressure Relief Valve Activation & Air-Gap Controller"
            },
            {
                "id": "INC-MFG-005",
                "title": "Intellectual Property Theft",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 2,
                "data_sensitivity": 5,
                "attack_confidence": 0.88,
                "business_impact": 4,
                "assets": ["DESIGN-CAD-VAULT"],
                "users": ["cad_patent_designer", "lead_ot_engineer"],
                "attack_types": ["Blueprints Exfiltration", "Proprietary CAD Theft"],
                "mitre": ["T1005: Data from Local System", "T1048: Exfiltration"],
                "story": "Uncompressed export of 3D CAD turbine blade schematics and metallurgical stress test data transferred to foreign adversary server.",
                "playbook": "Quarantine Engineering Vault & Restrict Outbound USB Access"
            },
            {
                "id": "INC-MFG-006",
                "title": "Supplier Network Compromise",
                "severity": 4,
                "asset_importance": 4,
                "affected_users": 3,
                "data_sensitivity": 3,
                "attack_confidence": 0.85,
                "business_impact": 4,
                "assets": ["SUPPLIER-EDI-PORTAL"],
                "users": ["supplier_coordinator", "plant_operations_dir", "lead_ot_engineer"],
                "attack_types": ["Supply Chain Portal Abuse", "Poisoned Purchase Orders"],
                "mitre": ["T1199: Trusted Relationship", "T1078: Valid Accounts"],
                "story": "Compromised supplier credential injected fraudulent raw titanium consignment orders, threatening production delivery timeline.",
                "playbook": "Disable Supplier EDI API Keys & Perform Out-of-Band Verification"
            }
        ]
    }
}

def get_sector_profile(sector_id: str) -> Optional[Dict[str, Any]]:
    return SECTOR_PROFILES.get(sector_id.lower())

def get_all_sector_profiles() -> List[Dict[str, Any]]:
    result = []
    for s_id, s_data in SECTOR_PROFILES.items():
        result.append({
            "id": s_data["id"],
            "name": s_data["name"],
            "description": s_data["description"],
            "weights": s_data["weights"],
            "default_version": s_data["default_version"],
            "threat_count": len(s_data.get("threats", []))
        })
    return result

def load_sector_into_db(
    db: Session,
    sector_id: str,
    custom_weights: Optional[Dict[str, float]] = None,
    version_name: Optional[str] = None
) -> Dict[str, Any]:
    from app.services.ranking import RankingService
    from app.services.risk_scoring import RiskScoringService
    from app.services.audit import AuditService

    profile = get_sector_profile(sector_id)
    if not profile:
        raise ValueError(f"Unknown sector preset '{sector_id}'.")

    # 1. Clear previous incidents, junctions, events, assets, users, and detections
    db.query(IncidentEventJunction).delete()
    db.query(IncidentModel).delete()
    db.query(EventModel).delete()
    db.query(DetectionModel).delete()
    db.query(AssetModel).delete()
    db.query(UserModel).delete()

    # 2. Seed Sector Assets
    for a in profile.get("assets", []):
        db.add(AssetModel(
            asset_id=a["id"],
            hostname=a["hostname"],
            owner="Sector IT",
            department=a["department"],
            asset_type=a["type"],
            criticality=a["criticality"],
            asset_tier=a["tier"],
            business_function=a["func"],
            internet_facing=a["internet"],
            data_classification=a["data"]
        ))

    # 3. Seed Sector Users
    for u in profile.get("users", []):
        db.add(UserModel(
            user_id=u["id"],
            username=u["name"],
            department=u["dept"],
            role=u["role"],
            privileged=u["priv"],
            vip=False,
            risk_level="HIGH" if u["priv"] else "MEDIUM"
        ))

    now = datetime.now(timezone.utc)
    threats = profile.get("threats", [])
    
    # 4. Seed Sector Incidents & Canonical Telemetry Events
    for idx, t in enumerate(threats):
        inc_id = t["id"]
        created_time = now - timedelta(minutes=(idx * 18 + 5))

        inc = IncidentModel(
            incident_id=inc_id,
            title=t["title"],
            status="NEW" if idx == 0 else ("TRIAGED" if idx == 1 else "INVESTIGATING"),
            priority_score=0.0,
            priority_level="CRITICAL",
            attack_confidence=t["attack_confidence"],
            data_confidence=1.0,
            business_impact=t["business_impact"],
            data_sensitivity=t["data_sensitivity"],
            affected_assets_json=t["assets"],
            affected_users_json=t["users"],
            attack_types_json=t["attack_types"],
            mitre_techniques_json=t["mitre"],
            top_drivers_json=[],
            attack_story=t["story"],
            explanation=t["story"],
            recommended_playbook=t.get("playbook", "Automated Sector Defense Isolation"),
            related_alerts_json=[f"ALT-{inc_id}-{i+1}" for i in range(len(t["assets"]) * 2 + 1)],
            created_at=created_time,
            sla_deadline=created_time + timedelta(hours=2)
        )
        db.add(inc)

        # Generate canonical event models for accurate factor calculation
        for asset_host in t["assets"]:
            evt_id = f"EVT-{inc_id}-{asset_host}"
            is_tier_1 = t["asset_importance"] >= 5
            event = EventModel(
                event_id=evt_id,
                timestamp=created_time,
                source="SECTOR_EDR",
                source_type="edr",
                event_type="security_alert",
                category="ENDPOINT_EXECUTION" if "Execution" in t["title"] or "Ransomware" in t["title"] else "NETWORK_ANOMALY",
                severity=t["severity"],
                raw_event={"scenario": t["title"], "asset": asset_host},
                host=asset_host,
                user=t["users"][0] if t["users"] else "system",
                asset_tier="TIER 1" if is_tier_1 else "TIER 2",
                asset_criticality=t["asset_importance"],
                privileged_user=True,
                internet_facing=True if "Web" in asset_host or "PORTAL" in asset_host or "GATEWAY" in asset_host else False,
                data_sensitivity=t["data_sensitivity"],
                business_impact=t["business_impact"],
                is_duplicate=False
            )
            db.add(event)

            # Junction
            j = IncidentEventJunction(incident_id=inc_id, event_id=evt_id)
            db.add(j)

    # 5. Activate Scoring Configuration
    final_weights = custom_weights if custom_weights else profile["weights"]
    final_version = version_name if version_name else profile["default_version"]

    db.query(ScoringModelConfig).update({"is_active": False})
    
    existing_cfg = db.query(ScoringModelConfig).filter(ScoringModelConfig.version_name == final_version).first()
    if existing_cfg:
        existing_cfg.weights_json = final_weights
        existing_cfg.thresholds_json = {"critical": 90.0, "high": 75.0, "medium": 50.0, "low": 25.0}
        existing_cfg.is_active = True
        existing_cfg.created_by = f"sector_preset_{sector_id}"
    else:
        cfg = ScoringModelConfig(
            version_name=final_version,
            weights_json=final_weights,
            thresholds_json={"critical": 90.0, "high": 75.0, "medium": 50.0, "low": 25.0},
            is_active=True,
            created_by=f"sector_preset_{sector_id}"
        )
        db.add(cfg)
    db.commit()

    # 6. Recalculate 6-Factor Scores & Deterministic Ranking
    # This invokes the real scoring engine for each threat
    sorted_incidents = RankingService.get_prioritized_incidents(db)
    db.commit()

    AuditService.log(
        db,
        action="SECTOR_PRESET_ACTIVATED",
        entity="scoring_model",
        entity_id=final_version,
        details={"sector": sector_id, "weights": final_weights, "threats_processed": len(sorted_incidents)}
    )

    return {
        "status": "SUCCESS",
        "sector": sector_id,
        "name": profile["name"],
        "description": profile["description"],
        "version_name": final_version,
        "weights": final_weights,
        "threats_count": len(sorted_incidents),
        "top_threat": sorted_incidents[0].title if sorted_incidents else None,
        "top_score": sorted_incidents[0].priority_score if sorted_incidents else None
    }
