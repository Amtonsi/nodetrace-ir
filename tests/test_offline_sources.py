from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import sqlite3
from threading import Event

from nodetrace_ir.collectors._common import content_file_key
from nodetrace_ir.collectors.offline_sources import (
    OfflineBrowserDownloadCollector,
    OfflineUsbHistoryCollector,
)
from nodetrace_ir.contracts import CollectionContext, utc_now


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "affected"
    (root / "Windows" / "INF").mkdir(parents=True)
    return root


def _context(tmp_path: Path, root: Path, suspect: Path) -> CollectionContext:
    return CollectionContext(
        case_id=1,
        suspect_path=str(suspect),
        started_at=utc_now(),
        lookback_days=90,
        artifact_dir=tmp_path / "artifacts",
        cancel_event=Event(),
        options={"target_mode": "offline", "offline_root": str(root)},
    )


def _history(root: Path, *, target_path: str, urls: list[str]) -> Path:
    path = (
        root
        / "Users"
        / "alice"
        / "AppData"
        / "Local"
        / "Microsoft"
        / "Edge"
        / "User Data"
        / "Default"
        / "History"
    )
    path.parent.mkdir(parents=True)
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY,
            current_path TEXT,
            target_path TEXT,
            start_time INTEGER,
            end_time INTEGER,
            received_bytes INTEGER,
            total_bytes INTEGER,
            state INTEGER,
            danger_type INTEGER,
            interrupt_reason INTEGER,
            referrer TEXT,
            tab_url TEXT,
            tab_referrer_url TEXT,
            mime_type TEXT,
            original_mime_type TEXT,
            guid TEXT
        );
        CREATE TABLE downloads_url_chains (
            id INTEGER,
            chain_index INTEGER,
            url TEXT
        );
        """
    )
    connection.execute(
        """
        INSERT INTO downloads VALUES (
            7, ?, ?, 13380163200000000, 13380163201000000,
            128, 128, 1, 0, 0,
            'https://portal.example/downloads',
            'https://portal.example/downloads',
            'https://search.example/',
            'application/octet-stream',
            'application/octet-stream',
            'fixture-guid'
        )
        """,
        (target_path, target_path),
    )
    connection.executemany(
        "INSERT INTO downloads_url_chains VALUES (7, ?, ?)",
        list(enumerate(urls)),
    )
    connection.commit()
    connection.close()
    return path


def test_offline_edge_history_reports_exact_final_url_for_exact_target_path(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    suspect = root / "Users" / "alice" / "Downloads" / "payload.exe"
    suspect.parent.mkdir(parents=True)
    suspect.write_bytes(b"payload fixture")
    history = _history(
        root,
        target_path=r"C:\Users\alice\Downloads\payload.exe",
        urls=[
            "https://redirect.example/start?id=42",
            "https://cdn.example/files/payload.exe?token=exact",
        ],
    )
    original_hash = sha256(history.read_bytes()).hexdigest()
    original_mtime = history.stat().st_mtime_ns

    result = OfflineBrowserDownloadCollector().collect(_context(tmp_path, root, suspect))

    assert result.status == "completed"
    assert len(result.evidence) == 1
    origin = result.evidence[0]
    assert origin.entity_type == "download_origin"
    assert origin.label == "https://cdn.example/files/payload.exe?token=exact"
    assert origin.properties["url"] == origin.label
    assert origin.properties["download_url"] == origin.label
    assert origin.properties["initial_url"] == "https://redirect.example/start?id=42"
    assert origin.properties["redirect_chain"] == [
        "https://redirect.example/start?id=42",
        "https://cdn.example/files/payload.exe?token=exact",
    ]
    assert origin.properties["match_basis"] == "exact_drive_neutral_target_path"
    assert origin.properties["content_identity_proven"] is False
    relation = result.relations[0]
    assert relation.relation_type == "reported_download_source"
    assert relation.confidence == "medium"
    assert relation.target_key == content_file_key(suspect)
    assert "does not prove" in relation.rationale
    assert history.stat().st_mtime_ns == original_mtime
    assert sha256(history.read_bytes()).hexdigest() == original_hash
    assert {path.name for path in history.parent.iterdir()} == {"History"}
    assert result.raw_payload["read_only_immutable"] is True


def test_offline_browser_filename_only_match_is_explicit_hypothesis(tmp_path: Path) -> None:
    root = _root(tmp_path)
    suspect = root / "Users" / "alice" / "Downloads" / "payload.exe"
    suspect.parent.mkdir(parents=True)
    suspect.write_bytes(b"current bytes")
    _history(
        root,
        target_path=r"C:\Temp\payload.exe",
        urls=["https://example.test/unrelated/payload.exe"],
    )

    result = OfflineBrowserDownloadCollector().collect(_context(tmp_path, root, suspect))

    assert result.evidence[0].properties["match_basis"] == "filename_only"
    assert result.relations[0].confidence == "low"
    assert "hypothesis" in result.relations[0].rationale


def test_offline_browser_ignores_wal_to_avoid_target_writes_and_records_gap(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    suspect = root / "Users" / "alice" / "Downloads" / "payload.exe"
    suspect.parent.mkdir(parents=True)
    suspect.write_bytes(b"current bytes")
    history = _history(
        root,
        target_path=r"C:\Users\alice\Downloads\payload.exe",
        urls=["https://example.test/payload.exe"],
    )
    history.with_name("History-wal").write_bytes(b"preserved pending records")

    result = OfflineBrowserDownloadCollector().collect(_context(tmp_path, root, suspect))

    assert result.status == "partial"
    gap = next(item for item in result.gaps if item.source == "Chromium History WAL")
    assert "immutable read-only mode" in gap.reason
    assert result.raw_payload["wal_databases_ignored"] == [str(history)]


def test_offline_setupapi_emits_exact_usb_ids_without_file_relation(tmp_path: Path) -> None:
    root = _root(tmp_path)
    suspect = root / "Users" / "alice" / "Downloads" / "payload.exe"
    suspect.parent.mkdir(parents=True)
    suspect.write_bytes(b"payload")
    setupapi = root / "Windows" / "INF" / "setupapi.dev.log"
    setupapi.write_text(
        """
>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001230101117392&0]
>>>  Section start 2026/01/02 10:20:30.100
<<<  Section end 2026/01/02 10:20:31.000
<<<  [Exit status: SUCCESS]
>>>  [Device Install (DiShowUpdateDevice) - USB\\VID_0781&PID_5581\\20051737611A0C302B64]
>>>  Section start 2026/02/03 11:22:33.200
<<<  Section end 2026/02/03 11:22:34.000
<<<  [Exit status: SUCCESS]
>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001230101117392&0]
>>>  Section start 2026/03/04 12:23:34.300
<<<  Section end 2026/03/04 12:23:35.000
<<<  [Exit status: SUCCESS]
""".lstrip(),
        encoding="utf-16",
    )

    result = OfflineUsbHistoryCollector().collect(_context(tmp_path, root, suspect))

    assert result.status == "completed"
    assert len(result.evidence) == 2
    assert result.relations == []
    storage = next(
        item for item in result.evidence if item.properties["device_class"] == "USBSTOR"
    )
    assert storage.properties["pnp_device_id"] == (
        r"USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\4C530001230101117392&0"
    )
    assert storage.properties["device_serial_number"] == "4C530001230101117392"
    assert storage.properties["vendor"] == "SanDisk"
    assert storage.properties["product"] == "Ultra"
    assert storage.properties["occurrence_count"] == 2
    assert storage.properties["historical_delivery_proven"] is False
    assert storage.properties["relation_to_suspect_file"] == "not established"
    usb = next(item for item in result.evidence if item.properties["device_class"] == "USB")
    assert usb.properties["vid"] == "0781"
    assert usb.properties["pid"] == "5581"
    assert result.raw_payload["usb_file_relations_emitted"] == 0
    assert result.raw_payload["causation_claimed"] is False


def test_offline_setupapi_missing_log_is_explicit_coverage_gap(tmp_path: Path) -> None:
    root = _root(tmp_path)
    suspect = root / "payload.exe"
    suspect.write_bytes(b"payload")

    result = OfflineUsbHistoryCollector().collect(_context(tmp_path, root, suspect))

    assert result.status == "partial"
    assert result.evidence == []
    assert "setupapi.dev.log" in result.gaps[0].source
