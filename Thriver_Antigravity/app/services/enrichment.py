from sqlalchemy.orm import Session
from app.db.models import AssetModel, UserModel, ThreatIntelModel, VulnerabilityModel, EventModel
from app.models.canonical import CanonicalEvent

class EnrichmentService:
    @staticmethod
    def enrich_event(db: Session, event: CanonicalEvent) -> CanonicalEvent:
        """
        Enriches a canonical event using Asset Inventory, User Directory, Threat Intel IOCs, and Vulnerability DB.
        """
        # 1. Asset Enrichment
        if event.host or event.hostname or event.asset_id:
            query = event.host or event.hostname or event.asset_id
            asset = db.query(AssetModel).filter(
                (AssetModel.hostname == query) | (AssetModel.asset_id == query)
            ).first()
            if asset:
                event.asset_id = asset.asset_id
                event.asset_type = asset.asset_type
                event.asset_tier = asset.asset_tier
                event.asset_criticality = asset.criticality
                event.internet_facing = asset.internet_facing
                # Higher asset criticality elevates data sensitivity & business impact default
                event.data_sensitivity = max(event.data_sensitivity, asset.criticality)
                event.business_impact = max(event.business_impact, asset.criticality)

        # 2. User Enrichment
        if event.user or event.user_id:
            u_query = event.user or event.user_id
            user = db.query(UserModel).filter(
                (UserModel.username == u_query) | (UserModel.user_id == u_query)
            ).first()
            if user:
                event.user_id = user.user_id
                event.user_role = user.role
                event.privileged_user = user.privileged
                if user.privileged or user.vip:
                    # Privileged/VIP user increases contextual business impact
                    event.business_impact = max(event.business_impact, 4)

        # 3. Threat Intelligence Enrichment
        iocs_to_check = []
        if event.source_ip: iocs_to_check.append(("ip", event.source_ip))
        if event.destination_ip: iocs_to_check.append(("ip", event.destination_ip))
        if event.domain: iocs_to_check.append(("domain", event.domain))
        if event.file_hash: iocs_to_check.append(("hash", event.file_hash))
        if event.url: iocs_to_check.append(("url", event.url))

        ti_matched = False
        for ioc_type, ioc_val in iocs_to_check:
            ti = db.query(ThreatIntelModel).filter(
                ThreatIntelModel.ioc_type == ioc_type,
                ThreatIntelModel.ioc_value == ioc_val
            ).first()
            if ti and ti.is_malicious:
                ti_matched = True
                event.attack_confidence = max(event.attack_confidence, ti.ioc_confidence)
                event.severity = max(event.severity, 4)
                if not event.extra_metadata:
                    event.extra_metadata = {}
                event.extra_metadata["threat_intel_match"] = {
                    "ioc": ioc_val,
                    "malware_family": ti.malware_family,
                    "campaign": ti.campaign,
                    "threat_score": ti.threat_score
                }

        # 4. Vulnerability Context
        if event.asset_id:
            vuln = db.query(VulnerabilityModel).filter(
                VulnerabilityModel.affected_asset_id == event.asset_id
            ).first()
            if vuln and vuln.known_exploited:
                event.attack_confidence = min(1.0, event.attack_confidence + 0.15)
                if not event.extra_metadata:
                    event.extra_metadata = {}
                event.extra_metadata["vulnerability_context"] = {
                    "cve_id": vuln.cve_id,
                    "cvss_score": vuln.cvss_score,
                    "known_exploited": vuln.known_exploited
                }

        return event
