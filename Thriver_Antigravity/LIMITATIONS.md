# System Limitations & Prototype Boundary Disclosures

**CIP-SOC** is a local defensive cybersecurity prototype. The following limitations and safety boundaries apply:

---

## 1. Safety Boundary & Response Actions
- **Simulation Only**: All response playbooks (e.g. endpoint isolation, firewall blocking, account locking) execute in **SAFE SIMULATION MODE ONLY**.
- **No Destructive Capabilities**: The platform does NOT execute real endpoint isolation APIs, network interface commands, or active malware execution against host operating systems.

## 2. Telemetry & Data Sources
- **Synthetic Telemetry**: Telemetry events, asset catalogs, user directories, threat intelligence IOCs, and CVE vulnerability records are synthetic for demonstration purposes.
- **Rule-Based Detections**: Detection rules execute in-memory against normalized events using standard boolean expressions and string matching.

## 3. Future Integration Architecture
- The prototype is designed with modular service interfaces to allow future production integration with Wazuh, OpenSearch, Splunk, CrowdStrike, and Suricata via REST API adapters.
