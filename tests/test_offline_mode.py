from __future__ import annotations

from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from nodetrace_ir.app import NodeTraceApp, build_parser, main
from nodetrace_ir.collectors import default_offline_collectors
from nodetrace_ir.collectors.event_logs import EventLogCollector
from nodetrace_ir.collectors.file_seed import FileSeedCollector
from nodetrace_ir.collectors.helpers import PowerShellResult
from nodetrace_ir.collectors.offline import OfflineCoverageCollector
from nodetrace_ir.collectors.prefetch import PrefetchCollector
from nodetrace_ir.contracts import CollectionContext, CollectorResult, utc_now
from nodetrace_ir.database import Database
from nodetrace_ir.pipeline import IncidentPipeline


def _offline_root(tmp_path: Path) -> Path:
    root = tmp_path / "affected"
    (root / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
    (root / "Windows" / "Prefetch").mkdir(parents=True)
    return root


def _context(tmp_path: Path, suspect: Path, offline_root: Path) -> CollectionContext:
    return CollectionContext(
        case_id=1,
        suspect_path=str(suspect),
        started_at=utc_now(),
        lookback_days=30,
        artifact_dir=tmp_path / "artifacts",
        cancel_event=Event(),
        options={"target_mode": "offline", "offline_root": str(offline_root)},
    )


def test_winpe_cli_requires_explicit_data_dir(tmp_path: Path) -> None:
    root = _offline_root(tmp_path)

    with pytest.raises(SystemExit) as exc:
        main(["--winpe", "--offline-root", str(root), "--create-demo-only"])

    assert exc.value.code == 2


def test_winpe_data_dir_cannot_write_inside_offline_target(tmp_path: Path) -> None:
    root = _offline_root(tmp_path)
    target_storage = root / "NodeTraceCases"

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--winpe",
                "--offline-root",
                str(root),
                "--data-dir",
                str(target_storage),
                "--create-demo-only",
            ]
        )

    assert exc.value.code == 2
    assert not target_storage.exists()


def test_cli_exposes_winpe_and_offline_root() -> None:
    args = build_parser().parse_args(
        ["--winpe", "--offline-root", "D:\\", "--data-dir", r"E:\NodeTrace"]
    )

    assert args.winpe is True
    assert args.offline_root == Path("D:\\")
    assert args.data_dir == Path(r"E:\NodeTrace")


def test_default_offline_collectors_exclude_live_host_sources() -> None:
    names = [collector.name for collector in default_offline_collectors()]

    assert names == [
        "file_seed",
        "offline_browser_downloads",
        "offline_usb_history",
        "event_logs",
        "prefetch",
        "offline_coverage",
    ]
    assert {"live_processes", "network", "persistence", "filesystem_context"}.isdisjoint(names)


class _OfflineRecorder:
    name = "offline_recorder"
    display_name = "Offline recorder"
    supports_offline = True

    def __init__(self) -> None:
        self.options: dict[str, object] = {}

    def collect(self, context: CollectionContext) -> CollectorResult:
        self.options = dict(context.options)
        now = utc_now()
        return CollectorResult(self.name, now, now, "completed")


class _UnsafeLiveCollector:
    name = "live_processes"
    display_name = "Unsafe live fixture"

    def __init__(self) -> None:
        self.called = False

    def collect(self, context: CollectionContext) -> CollectorResult:
        self.called = True
        raise AssertionError("a live-host collector ran in offline mode")


def test_offline_pipeline_filters_live_collectors_and_records_volatile_gaps(
    tmp_path: Path,
) -> None:
    root = _offline_root(tmp_path)
    database = Database(tmp_path / "cases.sqlite3")
    case = database.create_case(
        "Offline target",
        properties={"target_mode": "offline", "offline_root": str(root)},
    )
    recorder = _OfflineRecorder()
    unsafe = _UnsafeLiveCollector()

    result = IncidentPipeline(
        database,
        artifact_root=tmp_path / "artifacts",
        collectors=[unsafe, recorder],
    ).run(
        case.id,
        options={"target_mode": "offline", "offline_root": str(root)},
    )

    assert result.detection.status == "partial"
    assert "not configured" in result.detection.message
    assert result.detection.details["avz_started"] is False
    assert result.detection.details["suspect_file_scanned"] is False
    assert result.detection.details["offline_root_scanned"] is False
    avz_gap = next(gap for gap in database.list_gaps(case.id) if gap.collector == "avz_detection")
    assert "not configured" in avz_gap.reason
    assert "matching x86" in avz_gap.recommendation
    assert unsafe.called is False
    assert recorder.options["target_mode"] == "offline"
    assert recorder.options["offline_root"] == str(root.absolute())
    assert result.investigation is not None
    assert {outcome.collector for outcome in result.investigation.outcomes} == {
        "offline_recorder",
        "offline_coverage",
    }
    gaps = [gap for gap in database.list_gaps(case.id) if gap.collector == "offline_coverage"]
    assert {gap.source for gap in gaps} == {
        "Offline target live processes",
        "Offline target network state",
        "Offline target volatile state",
    }


def test_offline_event_log_collector_uses_get_winevent_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nodetrace_ir.collectors import event_logs

    root = _offline_root(tmp_path)
    suspect = root / "payload.exe"
    suspect.write_bytes(b"fixture")
    evtx = root / "Windows" / "System32" / "winevt" / "Logs" / "System.evtx"
    evtx.write_bytes(b"fixture evtx")
    captured: dict[str, object] = {}

    def fake_query(script: str, **kwargs: object) -> PowerShellResult:
        captured["script"] = script
        captured["env"] = kwargs["env"]
        return PowerShellResult(
            ok=True,
            data={
                "StartTimeUtc": "2026-01-01T00:00:00Z",
                "EndTimeUtc": "2026-01-02T00:00:00Z",
                "Streams": [
                    {
                        "Key": "system_7045",
                        "Label": "Service installation",
                        "LogName": "System",
                        "Path": str(evtx),
                        "Available": True,
                        "Enabled": True,
                        "Events": [
                            {
                                "Id": 7045,
                                "RecordId": 7,
                                "LogName": "System",
                                "TimeCreatedUtc": "2026-01-01T12:00:00Z",
                                "Message": "A service was installed",
                            }
                        ],
                    }
                ],
            },
        )

    monkeypatch.setattr(event_logs.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(event_logs.helpers, "run_powershell_json", fake_query)

    result = EventLogCollector().collect(_context(tmp_path, suspect, root))

    assert "Get-WinEvent -Path $evtxPath" in str(captured["script"])
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["NODETRACE_OFFLINE_EVTX_DIR"] == str(evtx.parent)
    assert result.evidence[0].source == f"Offline EVTX: {evtx}"
    assert result.evidence[0].source_ref == f"{evtx}#7"
    assert result.raw_payload["target_mode"] == "offline"


def test_winpe_event_log_failure_states_get_winevent_is_unsupported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nodetrace_ir.collectors import event_logs

    root = _offline_root(tmp_path)
    suspect = root / "payload.exe"
    suspect.write_bytes(b"fixture")
    # Force the native wevtapi backend to reject an existing malformed file so
    # this test exercises the documented PowerShell fallback failure.
    (root / "Windows" / "System32" / "winevt" / "Logs" / "System.evtx").write_bytes(
        b"not an evtx fixture"
    )
    context = _context(tmp_path, suspect, root)
    context.options["winpe"] = True
    monkeypatch.setattr(event_logs.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        event_logs.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=False,
            error="Trusted inbox Windows PowerShell executable was not found",
        ),
    )

    result = EventLogCollector().collect(context)

    assert result.status == "failed"
    assert "Get-WinEvent as unsupported in Windows PE" in result.gaps[0].reason
    assert "PowerShell optional components alone" in result.gaps[0].recommendation


def test_winpe_file_seed_keeps_hash_when_powershell_metadata_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nodetrace_ir.collectors import file_seed

    root = _offline_root(tmp_path)
    suspect = root / "payload.exe"
    suspect.write_bytes(b"fixture")
    context = _context(tmp_path, suspect, root)
    context.options["winpe"] = True
    monkeypatch.setattr(file_seed.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        file_seed.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=False,
            error="Trusted inbox Windows PowerShell executable was not found",
        ),
    )

    result = FileSeedCollector().collect(context)

    assert result.status == "partial"
    assert len(result.evidence) == 1
    assert result.evidence[0].properties["sha256"]
    assert "file hashes" in result.gaps[0].impact
    assert "PowerShell/WMI optional components" in result.gaps[0].recommendation


def test_offline_prefetch_is_read_from_mounted_windows_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nodetrace_ir.collectors import prefetch

    root = _offline_root(tmp_path)
    suspect = root / "Users" / "analyst" / "MALWARE.EXE"
    suspect.parent.mkdir(parents=True)
    suspect.write_bytes(b"fixture")
    matching = root / "Windows" / "Prefetch" / "MALWARE.EXE-ABCDEF01.pf"
    matching.write_bytes(b"opaque")
    decoy = tmp_path / "live-prefetch"
    decoy.mkdir()
    monkeypatch.setattr(prefetch.helpers, "is_windows", lambda: True)
    context = _context(tmp_path, suspect, root)
    context.options["prefetch_directory"] = str(decoy)

    result = PrefetchCollector().collect(context)

    assert [item.source_ref for item in result.evidence] == [str(matching)]
    assert result.evidence[0].source == "Offline Windows Prefetch directory metadata"
    assert result.raw_payload["prefetch_directory"] == str(root / "Windows" / "Prefetch")


def test_auto_created_case_records_offline_target(tmp_path: Path) -> None:
    root = _offline_root(tmp_path)
    database = Database(tmp_path / "cases.sqlite3")
    app = NodeTraceApp.__new__(NodeTraceApp)
    app.target_mode = "offline"
    app.offline_root = root
    app.winpe = True
    app.database = database
    app.current_case_id = None
    app.current_case = None
    app._closing = False
    app._worker = None
    app.status_var = SimpleNamespace(set=lambda _value: None)
    started: list[bool] = []

    def refresh(*, select_id: int) -> None:
        app.current_case_id = select_id
        app.current_case = database.get_case(select_id)

    app._refresh_cases = refresh
    app._start_collection = lambda: started.append(True)

    app._auto_startup_investigation()

    assert app.current_case is not None
    assert app.current_case.hostname == "offline-target"
    assert app.current_case.properties["target_mode"] == "offline"
    assert app.current_case.properties["offline_root"] == str(root)
    assert app.current_case.properties["winpe"] is True
    assert app.current_case.properties["live_host_telemetry_collected"] is False
    assert started == [True]


def test_offline_coverage_collector_never_emits_evidence(tmp_path: Path) -> None:
    root = _offline_root(tmp_path)
    suspect = root / "sample.exe"
    suspect.write_bytes(b"fixture")

    result = OfflineCoverageCollector().collect(_context(tmp_path, suspect, root))

    assert result.evidence == []
    assert result.status == "partial"
    assert result.raw_payload["winpe_host_telemetry_collected"] is False
