from __future__ import annotations

import pytest

from nodetrace_ir.collectors.evtx_native import NativeEvtxError, parse_event_xml


EVENT_XML = """<?xml version="1.0" encoding="utf-16"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{00000000-0000-0000-0000-000000000000}" />
    <EventID>1</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-07-16T10:20:30.1234567Z" />
    <EventRecordID>77</EventRecordID>
    <Execution ProcessID="123" ThreadID="456" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>affected-host</Computer>
  </System>
  <EventData>
    <Data Name="Image">D:\\Users\\alice\\payload.exe</Data>
    <Data Name="CommandLine">payload.exe --silent</Data>
    <Data>unnamed</Data>
  </EventData>
</Event>
"""


def test_rendered_event_xml_preserves_normalization_fields() -> None:
    event = parse_event_xml(EVENT_XML)

    assert event["Id"] == 1
    assert event["RecordId"] == 77
    assert event["ProviderName"] == "Microsoft-Windows-Sysmon"
    assert event["TimeCreatedUtc"] == "2026-07-16T10:20:30.1234567Z"
    assert event["ProcessId"] == 123
    assert event["ThreadId"] == 456
    assert event["MachineName"] == "affected-host"
    assert event["EventData"]["Image"].endswith("payload.exe")
    assert event["EventData"]["CommandLine"] == "payload.exe --silent"
    assert event["EventData"]["Data"] == "unnamed"


def test_rendered_event_xml_rejects_malformed_or_systemless_input() -> None:
    with pytest.raises(NativeEvtxError, match="malformed"):
        parse_event_xml("<Event>")
    with pytest.raises(NativeEvtxError, match="no System"):
        parse_event_xml("<Event />")
