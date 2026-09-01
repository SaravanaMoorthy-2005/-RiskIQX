# Detection Rules Specification & MITRE ATT&CK Mapping

**CIP-SOC** includes 12 SIEM and EDR detection rules executing against normalized canonical events:

---

| Rule ID | Rule Name | Category | Severity | Confidence | MITRE ID | MITRE Technique Name |
|---|---|---|---|---|---|---|
| `RULE-BRUTE-FORCE` | Brute Force Authentication Attempt | AUTHENTICATION | 3 | 0.85 | T1110 | Brute Force |
| `RULE-IMPOSSIBLE-TRAVEL` | Impossible Travel Authentication Anomaly | AUTHENTICATION | 4 | 0.90 | T1078 | Valid Accounts |
| `RULE-PORT-SCAN` | Network Reconnaissance / Port Scan | NETWORK_ACTIVITY | 2 | 0.75 | T1046 | Network Service Discovery |
| `RULE-PRIV-ESC` | Privilege Escalation Activity | ENDPOINT_EXECUTION | 5 | 0.95 | T1068 | Exploitation for Privilege Escalation |
| `RULE-SUSP-POWERSHELL` | Suspicious Obfuscated PowerShell Execution | ENDPOINT_EXECUTION | 4 | 0.88 | T1059.001 | PowerShell |
| `RULE-CRED-ATTACK` | Credential Access / Password Spray | AUTHENTICATION | 4 | 0.85 | T1110.003 | Password Spraying |
| `RULE-DATA-EXFIL` | Large Scale Data Exfiltration | NETWORK_ACTIVITY | 5 | 0.92 | T1048 | Exfiltration Over Alternative Protocol |
| `RULE-LATERAL-MOVE` | Lateral Movement Activity | NETWORK_ACTIVITY | 4 | 0.87 | T1021 | Remote Services |
| `RULE-MALWARE-HASH` | Known Malicious File Hash Execution | FILE_SYSTEM | 5 | 0.98 | T1204 | User Execution |
| `RULE-RANSOMWARE` | Ransomware Mass File Encryption Pattern | FILE_SYSTEM | 5 | 0.96 | T1486 | Data Encrypted for Impact |
| `RULE-PHISHING` | Phishing Email with Malicious Indicator | EMAIL_SECURITY | 3 | 0.80 | T1566 | Phishing |
| `RULE-CLOUD-ANOMALY` | Cloud IAM Privilege Anomaly | CLOUD_ACTIVITY | 4 | 0.82 | T1098 | Account Manipulation |
