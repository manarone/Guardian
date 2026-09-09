import json
from datetime import UTC
from pathlib import Path

import pytest

from guardian.connectors.sentinelone import (
    SentinelOneConnector,
    _to_s1_timestamp,
    normalize_threat,
)
from guardian.models import Severity

SAMPLE = json.loads(
    (Path(__file__).parent.parent / "samples" / "sentinelone_threat.json").read_text()
)


def test_normalizes_core_fields():
    alert = normalize_threat(SAMPLE)

    assert alert.source == "sentinelone"
    assert alert.source_id == "1878234567890123456"
    assert alert.title == "mimikatz.exe"
    assert alert.severity is Severity.HIGH
    assert alert.classification == "Malware"
    assert alert.vendor_status == "mitigated"
    assert alert.user == "CORP\\jdoe"
    assert alert.observed_at.year == 2026


def test_normalizes_host_and_process():
    alert = normalize_threat(SAMPLE)

    assert alert.host.hostname == "WIN-FIN-0427"
    assert alert.host.ip == "10.20.30.41"
    assert alert.host.os == "Windows 11 Pro"
    assert alert.process.sha256.startswith("912018ab")
    assert alert.process.signed is False
    assert "sekurlsa::logonpasswords" in alert.process.command_line


def test_extracts_indicators_and_techniques():
    alert = normalize_threat(SAMPLE)

    kinds = {i.type for i in alert.indicators}
    assert {"sha256", "path", "ip"} <= kinds
    assert alert.mitre_techniques == ["T1003.001 - LSASS Memory"]


def test_tolerates_a_sparse_payload():
    """S1 threat objects vary by agent version - missing fields must not raise."""
    alert = normalize_threat({"id": "42", "threatInfo": {}, "agentRealtimeInfo": {}})

    assert alert.source_id == "42"
    assert alert.title == "SentinelOne threat"
    assert alert.severity is Severity.MEDIUM
    assert alert.host.hostname is None


def test_ransomware_escalates_without_a_confidence_label():
    alert = normalize_threat({"threatInfo": {"classification": "Ransomware"}})
    assert alert.severity is Severity.CRITICAL


def test_multihomed_host_yields_one_indicator_per_address():
    alert = normalize_threat(
        {"agentRealtimeInfo": {"agentIpV4": "10.0.0.5, 192.168.1.9"}, "threatInfo": {}}
    )
    ips = [i.value for i in alert.indicators if i.type == "ip"]

    assert ips == ["10.0.0.5", "192.168.1.9"]
    assert alert.host.ip == "10.0.0.5"


def test_timestamp_format_matches_what_the_s1_api_expects():
    from datetime import datetime

    stamp = _to_s1_timestamp(datetime(2026, 9, 8, 14, 22, 31, 123456, tzinfo=UTC))
    assert stamp == "2026-09-08T14:22:31.123Z"


def test_connector_requires_credentials():
    with pytest.raises(ValueError):
        SentinelOneConnector(base_url="", api_token="")
