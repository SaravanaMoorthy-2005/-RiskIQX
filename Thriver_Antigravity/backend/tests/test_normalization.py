import pytest
from app.services.normalization import EventNormalizationService

def test_event_normalization_fields():
    raw_payload = {
        "timestamp": "2026-09-01T12:00:00Z",
        "source": "EDR_Agent",
        "action": "process_creation",
        "host": "WORKSTATION-01",
        "user": "alice",
        "severity": 4,
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -Nop -Enc ABCDEF=="
    }

    norm = EventNormalizationService.normalize(raw_payload, source_type="generic_edr")
    assert norm.source == "EDR_Agent"
    assert norm.event_type == "process_creation"
    assert norm.category == "ENDPOINT_EXECUTION"
    assert norm.severity == 4
    assert norm.host == "WORKSTATION-01"
    assert norm.user == "alice"
    assert norm.process_name == "powershell.exe"
