"""Tests for OCSF formatting and the Splunk/Datadog sink dispatchers."""
import json
from pathlib import Path

from prismor.runtime import sinks


def _event():
    finding = {
        "severity": "CRITICAL",
        "category": "secret_exfiltration",
        "ruleId": "secret-exfiltration",
        "action": "block",
        "title": "Secret file piped to network",
        "evidence": ".env | curl webhook.site",
        "id": "sess_4f2a:finding-1",
    }
    return sinks._build_event(finding, extra={"subject": {"user_id": "alice"}})


def test_format_ocsf_shape():
    ocsf = sinks._format_ocsf(_event())
    # Detection Finding class + matching type_uid (class_uid*100 + activity_id).
    assert ocsf["class_uid"] == 2004
    assert ocsf["category_uid"] == 2
    assert ocsf["type_uid"] == 200401
    assert ocsf["activity_id"] == 1
    # CRITICAL maps to OCSF severity_id 5.
    assert ocsf["severity_id"] == 5
    assert ocsf["metadata"]["product"]["vendor_name"] == "Prismor"
    assert ocsf["finding_info"]["title"] == "Secret file piped to network"
    assert ocsf["unmapped"]["rule_id"] == "secret-exfiltration"
    assert ocsf["unmapped"]["subject"] == {"user_id": "alice"}
    # Must be JSON-serializable (SIEMs ingest JSON).
    json.dumps(ocsf)


def test_severity_mapping():
    for name, sid in (("LOW", 2), ("MEDIUM", 3), ("HIGH", 4), ("CRITICAL", 5)):
        ev = sinks._build_event({"severity": name, "title": "t"})
        assert sinks._format_ocsf(ev)["severity_id"] == sid


def test_file_sink_ocsf_format(tmp_path: Path):
    out = tmp_path / "audit.log"
    sinks._dispatch_file({"path": str(out), "format": "ocsf"}, _event())
    line = out.read_text().strip()
    parsed = json.loads(line)  # one OCSF JSON object per line
    assert parsed["class_uid"] == 2004
    assert parsed["severity_id"] == 5


def test_dispatchers_registered():
    assert "splunk" in sinks._DISPATCHERS
    assert "datadog" in sinks._DISPATCHERS


def test_splunk_and_datadog_post(monkeypatch):
    # Capture the outbound request instead of hitting the network.
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *_):
            return b""

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["body"] = json.loads(req.data.decode())
        return _Resp()

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    sinks._dispatch_splunk_hec(
        {"url": "https://splunk.example:8088/services/collector", "token": "tok123"}, _event()
    )
    assert captured["headers"]["authorization"] == "Splunk tok123"
    assert captured["body"]["event"]["class_uid"] == 2004

    sinks._dispatch_datadog({"api_key": "ddkey"}, _event())
    assert captured["headers"]["dd-api-key"] == "ddkey"
    assert "datadoghq.com" in captured["url"]
    # Datadog payload is a list with one log record carrying the OCSF message.
    assert json.loads(captured["body"][0]["message"])["class_uid"] == 2004


def test_dispatchers_swallow_errors_without_config():
    # Missing required config must no-op, never raise (dispatch is best-effort).
    sinks._dispatch_splunk_hec({}, _event())
    sinks._dispatch_datadog({}, _event())
