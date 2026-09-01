# CIP-SOC Demo Walkthrough & Scenario Guide

This guide demonstrates how to present and validate the core product capabilities of **CIP-SOC**.

---

## 1. Step-by-Step Demonstration Workflow

1. **Launch Platform**:
   - Start backend (`python app/main.py`) and frontend (`npm run dev`).
   - Open `http://localhost:3000`.

2. **View Investigation Priority Queue**:
   - Observe that incidents are ordered strictly by **Contextual Risk Score (#1, #2, #3...)**, NOT by arbitrary creation order or severity alone.
   - Note the **Rank #1** incident highlighted with a red badge.

3. **Inspect "Why #1?" Dynamic Explanation**:
   - Click on the #1 ranked incident.
   - In the Incident Workspace, review the **Dynamic Score Driver Explanation** narrative detailing top contributing factors.

4. **Compare Pairwise ("Why #1 over #2?")**:
   - Click the **"Why Above #2?"** tab.
   - Inspect the factor delta matrix showing the exact point gap and narrative explaining why #1 outranks #2.

5. **Review Score Breakdown**:
   - Inspect the 6-Factor contribution bars (Severity, Asset Importance, Affected Users, Data Sensitivity, Attack Confidence, Business Impact).

6. **Execute Safe Playbook Simulation**:
   - Click **"Run Safe Playbook"**.
   - Click **"Run Step"** on a high-risk action (e.g. `ISOLATE_HOST_ENDPOINT`).
   - Observe the **HUMAN APPROVAL REQUIRED** modal warning.
   - Click **"Approve & Execute Safe Simulation"** and observe the **[SAFE SIMULATION ONLY]** execution log.

7. **Submit Analyst Feedback**:
   - Select **"Confirmed Incident"** or **"False Positive"**, enter investigation notes, and click **Submit Analyst Feedback**.

8. **Trigger Real-Time Attack Scenarios**:
   - Click **"Simulate Scenario"** in the top navigation bar.
   - Select **Ransomware Attack** or **Phishing Email**.
   - Observe immediate event ingestion, detection triggering, correlation, and dynamic queue re-ranking!
