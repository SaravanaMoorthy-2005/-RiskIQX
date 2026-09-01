import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any
from app.models.canonical import CanonicalEvent

class EventNormalizationService:
    @staticmethod
    def normalize(raw_data: Dict[str, Any], source_type: str = "generic_siem") -> CanonicalEvent:
        """
        Normalizes heterogeneous raw security log payloads into a canonical event model.
        Supports SIEM, EDR, Firewall, IDS/IPS, Auth, Cloud, Email, and Vulnerability Scanner sources.
        """
        timestamp_str = raw_data.get("timestamp") or raw_data.get("time") or raw_data.get("@timestamp")
        if timestamp_str:
            try:
                if isinstance(timestamp_str, (int, float)):
                    ts = datetime.fromtimestamp(timestamp_str, tz=timezone.utc)
                else:
                    ts = datetime.fromisoformat(str(timestamp_str).replace('Z', '+00:00'))
            except Exception:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        source = raw_data.get("source") or source_type.upper()
        event_type = raw_data.get("event_type") or raw_data.get("action") or raw_data.get("activity") or "unknown_event"
        category = raw_data.get("category") or EventNormalizationService._infer_category(event_type, raw_data)
        severity = int(raw_data.get("severity") or raw_data.get("level") or 1)
        severity = max(1, min(5, severity))

        host = raw_data.get("host") or raw_data.get("hostname") or raw_data.get("endpoint")
        user = raw_data.get("user") or raw_data.get("username") or raw_data.get("account")
        src_ip = raw_data.get("source_ip") or raw_data.get("src_ip") or raw_data.get("client_ip")
        dst_ip = raw_data.get("destination_ip") or raw_data.get("dst_ip") or raw_data.get("server_ip")
        src_port = raw_data.get("source_port") or raw_data.get("src_port")
        dst_port = raw_data.get("destination_port") or raw_data.get("dst_port")

        process_name = raw_data.get("process_name") or raw_data.get("process") or raw_data.get("image")
        cmdline = raw_data.get("command_line") or raw_data.get("cmd") or raw_data.get("process_command_line")
        file_hash = raw_data.get("file_hash") or raw_data.get("sha256") or raw_data.get("md5")
        domain = raw_data.get("domain") or raw_data.get("query")
        url = raw_data.get("url")

        auth_result = raw_data.get("authentication_result") or raw_data.get("result") or raw_data.get("status")
        auth_method = raw_data.get("authentication_method") or raw_data.get("auth_type")

        # Create normalized event model
        normalized = CanonicalEvent(
            timestamp=ts,
            source=source,
            source_type=source_type,
            event_type=event_type,
            category=category,
            severity=severity,
            host=host,
            hostname=host,
            os=raw_data.get("os"),
            asset_id=raw_data.get("asset_id"),
            asset_type=raw_data.get("asset_type"),
            asset_tier=raw_data.get("asset_tier"),
            asset_criticality=raw_data.get("asset_criticality"),
            internet_facing=bool(raw_data.get("internet_facing", False)),
            user=user,
            user_id=raw_data.get("user_id"),
            user_role=raw_data.get("user_role"),
            privileged_user=bool(raw_data.get("privileged_user", False)),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=int(src_port) if src_port else None,
            destination_port=int(dst_port) if dst_port else None,
            domain=domain,
            url=url,
            file_hash=file_hash,
            process_name=process_name,
            command_line=cmdline,
            authentication_result=auth_result,
            authentication_method=auth_method,
            affected_users_count=int(raw_data.get("affected_users_count") or 1),
            data_sensitivity=int(raw_data.get("data_sensitivity") or 1),
            business_impact=int(raw_data.get("business_impact") or 1),
            attack_confidence=float(raw_data.get("attack_confidence") or 0.5),
            raw_event=raw_data,
            extra_metadata=raw_data.get("metadata", {})
        )
        return normalized

    @staticmethod
    def _infer_category(event_type: str, raw_data: Dict[str, Any]) -> str:
        et = event_type.lower()
        if "login" in et or "auth" in et or "password" in et or "session" in et:
            return "AUTHENTICATION"
        elif "process" in et or "command" in et or "execution" in et or "script" in et or "powershell" in et:
            return "ENDPOINT_EXECUTION"
        elif "network" in et or "connect" in et or "dns" in et or "traffic" in et or "port" in et:
            return "NETWORK_ACTIVITY"
        elif "file" in et or "share" in et or "write" in et or "encrypt" in et:
            return "FILE_SYSTEM"
        elif "cloud" in et or "api" in et or "iam" in et:
            return "CLOUD_ACTIVITY"
        elif "email" in et or "phish" in et or "mail" in et:
            return "EMAIL_SECURITY"
        return "GENERAL_SECURITY"
