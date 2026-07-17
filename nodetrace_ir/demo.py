from __future__ import annotations

from datetime import datetime, timedelta, timezone
import socket
from typing import Any

from .contracts import CollectorResult, EvidenceDraft, GapDraft, RelationDraft, utc_now


def _time(base: datetime, minutes: int, seconds: int = 0) -> str:
    return (base + timedelta(minutes=minutes, seconds=seconds)).replace(microsecond=0).isoformat()


def create_demo_case(database: Any) -> Any:
    """Create a visibly rich, explicitly synthetic investigation case."""
    case = database.create_case(
        "ДЕМО: цепочка заражения вложением",
        suspect_path=r"C:\Users\analyst\Downloads\Счёт_июль.pdf.exe",
        description="Синтетический кейс для знакомства с интерфейсом. Никакие реальные файлы и адреса не исследовались.",
        hostname=socket.gethostname(),
        properties={"synthetic": True, "lookback_days": 7, "timezone": "UTC+8"},
    )
    run = database.start_collection_run(case.id, collector_count=1, options={"demo": True})
    base = datetime.now(timezone.utc) - timedelta(hours=5)
    evidence = [
        EvidenceDraft(
            "delivery_source", "Почтовое вложение «Счёт_июль.pdf.exe»", _time(base, -1),
            "synthetic_demo", "delivery:demo:mail-attachment", "DEMO-MAIL-01", "medium", "high",
            {
                "channel": "email_attachment",
                "sender": "billing@example.invalid",
                "recipient": r"WORKSTATION\analyst",
                "synthetic": True,
            },
            {"note": "Synthetic delivery source. This is demonstration data, not a real message."},
        ),
        EvidenceDraft(
            "file", "Счёт_июль.pdf.exe", _time(base, 0), "synthetic_demo", "file:seed:demo",
            "DEMO-FILE-01", "high", "critical",
            {"is_seed": True, "path": r"C:\Users\analyst\Downloads\Счёт_июль.pdf.exe", "sha256": "7c1f" + "a6" * 30, "size": 284672, "signature": "Unsigned", "zone_id": 3},
            {"note": "Synthetic seed. The file does not exist and was never executed."},
        ),
        EvidenceDraft(
            "user", r"WORKSTATION\analyst", _time(base, 0), "Security 4688", "user:demo:analyst",
            "Security/4688/120044", "high", "info", {"sid": "S-1-5-21-DEMO-1001"}, {},
        ),
        EvidenceDraft(
            "process", "Счёт_июль.pdf.exe (PID 8420)", _time(base, 0, 4), "Sysmon Event 1", "process:demo:8420",
            "Sysmon/1/8901", "high", "critical", {"pid": 8420, "parent_pid": 6124, "image": r"C:\Users\analyst\Downloads\Счёт_июль.pdf.exe", "command_line": '"C:\\Users\\analyst\\Downloads\\Счёт_июль.pdf.exe"'}, {},
        ),
        EvidenceDraft(
            "process", "powershell.exe (PID 8512)", _time(base, 0, 7), "Sysmon Event 1 + PowerShell 4104", "process:demo:8512",
            "Sysmon/1/8902", "high", "high", {"pid": 8512, "parent_pid": 8420, "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "command_line": "powershell -w hidden -enc <redacted>"}, {"script_block": "[synthetic redacted content]"},
        ),
        EvidenceDraft(
            "event", "Обфусцированный PowerShell ScriptBlock", _time(base, 0, 8), "PowerShell Operational 4104", "event:demo:ps4104",
            "PowerShell/4104/44021", "high", "high", {"event_id": 4104, "keywords": ["DownloadString", "Start-Process"], "content_redacted": True}, {},
        ),
        EvidenceDraft(
            "domain", "cdn-update.example", _time(base, 0, 10), "Sysmon Event 22", "domain:demo:cdn-update.example",
            "Sysmon/22/8903", "high", "high", {"query": "cdn-update.example", "reserved_demo_domain": True}, {},
        ),
        EvidenceDraft(
            "ip", "203.0.113.77:443", _time(base, 0, 13), "Sysmon Event 3", "ip:demo:203.0.113.77:443",
            "Sysmon/3/8904", "high", "high", {"ip": "203.0.113.77", "port": 443, "protocol": "tcp", "reserved_demo_address": True}, {},
        ),
        EvidenceDraft(
            "file", "winsync.exe", _time(base, 1, 2), "Sysmon Event 11", "file:demo:winsync",
            "Sysmon/11/8905", "high", "critical", {"path": r"C:\ProgramData\WinSync\winsync.exe", "sha256": "1144" + "b7" * 30, "signature": "Unsigned"}, {},
        ),
        EvidenceDraft(
            "registry", "HKCU\\...\\Run\\WinSync", _time(base, 1, 8), "Sysmon Event 13", "registry:demo:winsync-run",
            "Sysmon/13/8906", "high", "high", {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "WinSync", "value": r"C:\ProgramData\WinSync\winsync.exe"}, {},
        ),
        EvidenceDraft(
            "scheduled_task", "WinSync Update Check", _time(base, 1, 15), "TaskScheduler Operational 106", "task:demo:winsync",
            "TaskScheduler/106/3312", "high", "high", {"path": r"\WinSync Update Check", "command": r"C:\ProgramData\WinSync\winsync.exe /background", "trigger": "Logon"}, {},
        ),
        EvidenceDraft(
            "process", "rundll32.exe (PID 8728)", _time(base, 2, 3), "Sysmon Event 1", "process:demo:8728",
            "Sysmon/1/8907", "high", "high", {"pid": 8728, "parent_pid": 8512, "image": r"C:\Windows\System32\rundll32.exe", "command_line": r"rundll32.exe C:\ProgramData\WinSync\stage.dll,Start"}, {},
        ),
        EvidenceDraft(
            "alert", "Microsoft Defender: Trojan:Win32/SyntheticDemo", _time(base, 4, 0), "Defender Operational 1116", "alert:demo:defender",
            "Defender/1116/7021", "high", "critical", {"action": "Detected", "path": r"C:\ProgramData\WinSync\winsync.exe", "synthetic": True}, {},
        ),
        EvidenceDraft(
            "prefetch", "SCHЕТ_ИЮЛЬ.PDF.EXE-DEMO.pf", _time(base, 0, 20), "Prefetch metadata", "prefetch:demo:seed",
            r"C:\Windows\Prefetch\DEMO.pf", "medium", "medium", {"indicator_only": True, "note": "Prefetch is supporting evidence, not standalone proof of execution."}, {},
        ),
        EvidenceDraft(
            "file", "notes.tmp", _time(base, 1, 5), "Filesystem temporal context", "file:demo:nearby",
            r"C:\Users\analyst\AppData\Local\Temp\notes.tmp", "low", "low", {"path": r"C:\Users\analyst\AppData\Local\Temp\notes.tmp", "temporal_only": True}, {},
        ),
    ]
    relations = [
        RelationDraft(
            "delivery:demo:mail-attachment", "file:seed:demo", "reported_delivery_source", "medium",
            "Synthetic mail telemetry associates the attachment name with the file seed; demonstration only.",
            _time(base, 0),
        ),
        RelationDraft("user:demo:analyst", "process:demo:8420", "started", "high", "Security 4688 associates the token/user with the process.", _time(base, 0, 4)),
        RelationDraft("file:seed:demo", "process:demo:8420", "executed_as", "high", "Sysmon Image equals the suspect path and records the file hash.", _time(base, 0, 4)),
        RelationDraft("process:demo:8420", "process:demo:8512", "spawned", "high", "Matching ParentProcessGuid in Sysmon Event 1.", _time(base, 0, 7)),
        RelationDraft("process:demo:8512", "event:demo:ps4104", "produced", "high", "PowerShell process and ScriptBlock share the same host process identifier.", _time(base, 0, 8)),
        RelationDraft("process:demo:8512", "domain:demo:cdn-update.example", "resolved", "high", "Sysmon Event 22 contains the ProcessGuid of powershell.exe.", _time(base, 0, 10)),
        RelationDraft("process:demo:8512", "ip:demo:203.0.113.77:443", "connected_to", "high", "Sysmon Event 3 contains the same ProcessGuid.", _time(base, 0, 13)),
        RelationDraft("process:demo:8512", "file:demo:winsync", "created", "high", "Sysmon Event 11 contains the same ProcessGuid and target path.", _time(base, 1, 2)),
        RelationDraft("file:demo:winsync", "registry:demo:winsync-run", "persisted_via", "high", "Registry value directly names the dropped file.", _time(base, 1, 8)),
        RelationDraft("file:demo:winsync", "task:demo:winsync", "persisted_via", "high", "Scheduled task action directly names the dropped file.", _time(base, 1, 15)),
        RelationDraft("process:demo:8512", "process:demo:8728", "spawned", "high", "Matching ParentProcessGuid in Sysmon Event 1.", _time(base, 2, 3)),
        RelationDraft("file:demo:winsync", "alert:demo:defender", "detected_as", "high", "Defender detection path equals the dropped file path.", _time(base, 4, 0)),
        RelationDraft("file:seed:demo", "prefetch:demo:seed", "indicated_by", "medium", "Prefetch name is consistent with the executable name; use with other evidence.", _time(base, 0, 20)),
        RelationDraft("process:demo:8512", "file:demo:nearby", "temporally_near", "low", "Only modification-time proximity; no process attribution source exists.", _time(base, 1, 5)),
    ]
    gaps = [
        GapDraft("demo", "USN Journal", "Журнал уже был частично перезаписан.", "Ранние файловые изменения могут отсутствовать.", "Получить офлайн-образ и проверить $MFT/теневые копии."),
        GapDraft("demo", "EDR telemetry", "На узле не был установлен EDR до инцидента.", "Нельзя гарантировать полную цепочку действий и межпроцессные связи.", "Для будущего мониторинга заранее настроить EDR/Sysmon и централизованный сбор."),
        GapDraft("demo", "Compromised host trust", "Данные собраны из работающей потенциально заражённой ОС.", "Rootkit может скрыть процессы или подменить ответы API.", "Для доказательств высокой значимости провести офлайн-сбор из доверенной среды."),
    ]
    result = CollectorResult("synthetic_demo", _time(base, 0), utc_now(), "success", evidence, relations, gaps, {"synthetic": True})
    database.ingest_collector_result(case.id, run.id, result)
    database.finish_collection_run(run.id, "completed", successful_count=1)
    database.log_action(case.id, "demo_case_created", {"synthetic": True})
    return database.get_case(case.id)
