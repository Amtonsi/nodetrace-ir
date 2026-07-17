from nodetrace_ir.collectors.event_normalization import normalize_windows_event


TIME = "2026-07-13T10:00:00+00:00"
SOURCE = "Windows Event Log: Microsoft-Windows-Sysmon/Operational"
REF = "Microsoft-Windows-Sysmon/Operational#42"


def event(event_id: int, **fields):
    return {"Id": event_id, "RecordId": 42, "EventData": fields}


def test_sysmon_process_creation_links_seed_parent_user_and_hash() -> None:
    sample = event(
        1,
        ProcessGuid="{11111111-1111-1111-1111-111111111111}",
        ProcessId="8420",
        Image=r"C:\Cases\sample.exe",
        CommandLine=r'"C:\Cases\sample.exe" /silent',
        Hashes="SHA256=ABCDEF,MD5=1234",
        ParentProcessGuid="{22222222-2222-2222-2222-222222222222}",
        ParentProcessId="1200",
        ParentImage=r"C:\Windows\explorer.exe",
        User=r"HOST\analyst",
    )

    evidence, relations = normalize_windows_event(
        sample,
        "sysmon",
        TIME,
        SOURCE,
        REF,
        suspect_path=r"C:\Cases\sample.exe",
        seed_key="file:sha256:abcdef",
    )

    keys = {item.key() for item in evidence}
    assert "file:sha256:abcdef" not in keys  # the existing seed projection must not be overwritten
    assert "process:guid:11111111-1111-1111-1111-111111111111" in keys
    assert "process:guid:22222222-2222-2222-2222-222222222222" in keys
    assert "user:host\\analyst" in keys
    relation_types = {item.relation_type for item in relations}
    assert {"executed_as", "spawned", "started"} <= relation_types
    assert all(item.confidence == "high" for item in relations)
    assert any(item.source_key == "file:sha256:abcdef" and item.relation_type == "executed_as" for item in relations)


def test_sysmon_network_file_registry_and_dns_are_direct_relations() -> None:
    process = {
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
        "ProcessId": "8420",
        "Image": r"C:\Cases\sample.exe",
    }
    cases = [
        (3, {**process, "DestinationIp": "203.0.113.77", "DestinationPort": "443"}, "connected_to"),
        (11, {**process, "TargetFilename": r"C:\ProgramData\drop.exe"}, "created"),
        (13, {**process, "TargetObject": r"HKCU\Software\Demo\Run", "Details": "drop.exe"}, "modified_registry"),
        (22, {**process, "QueryName": "telemetry.example"}, "resolved"),
    ]
    for event_id, fields, expected in cases:
        evidence, relations = normalize_windows_event(event(event_id, **fields), "sysmon", TIME, SOURCE, REF)
        assert evidence
        assert expected in {item.relation_type for item in relations}
        assert all(item.confidence == "high" for item in relations)


def test_service_event_links_recorded_image_path_without_temporal_inference() -> None:
    sample = event(
        7045,
        ServiceName="WinSync",
        ImagePath=r'"C:\ProgramData\WinSync\winsync.exe" --service',
        StartType="auto start",
        AccountName="LocalSystem",
    )
    evidence, relations = normalize_windows_event(sample, "system_7045", TIME, "Windows Event Log: System", "System#42")
    assert {item.entity_type for item in evidence} == {"service", "file"}
    assert len(relations) == 1
    assert relations[0].relation_type == "installed_as_service"
    assert relations[0].confidence == "high"


def test_powershell_suspicious_terms_are_indicators_not_execution() -> None:
    sample = event(4104, ScriptBlockId="demo", ScriptBlockText="[Convert]::FromBase64String($x)")
    evidence, relations = normalize_windows_event(sample, "powershell_4104", TIME, "PowerShell 4104", "PowerShell#42")
    assert evidence[0].severity == "high"
    assert "frombase64string" in evidence[0].properties["suspicious_terms"]
    assert relations == []


def test_defender_similar_filename_does_not_link_seed_as_high_confidence() -> None:
    sample = event(1116, **{"Threat Name": "Demo", "Path": r"C:\Cases\bad.exe.old"})
    _, relations = normalize_windows_event(
        sample,
        "defender",
        TIME,
        "Defender",
        "Defender#42",
        suspect_path=r"C:\Cases\bad.exe",
        seed_key="file:sha256:seed",
    )
    assert relations
    assert all(item.source_key != "file:sha256:seed" for item in relations)
