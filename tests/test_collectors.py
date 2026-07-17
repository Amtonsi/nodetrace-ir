from __future__ import annotations

import base64
from hashlib import md5, sha1, sha256
import json
from pathlib import Path
import subprocess
from threading import Event
from types import SimpleNamespace

import pytest

from nodetrace_ir.collectors import (
    EventLogCollector,
    FileSeedCollector,
    FilesystemContextCollector,
    LiveProcessCollector,
    NetworkCollector,
    PersistenceCollector,
    PrefetchCollector,
    default_collectors,
)
from nodetrace_ir.collectors import event_logs, file_seed, filesystem, helpers, network, persistence, prefetch, processes
from nodetrace_ir.collectors.helpers import PowerShellResult, hash_file
from nodetrace_ir.contracts import CollectionContext, utc_now


def make_context(tmp_path: Path, suspect: Path, **options) -> CollectionContext:
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(exist_ok=True)
    return CollectionContext(
        case_id=1,
        suspect_path=str(suspect),
        started_at=utc_now(),
        lookback_days=7,
        artifact_dir=artifact_dir,
        cancel_event=Event(),
        options=options,
    )


def test_hash_file_calculates_all_requested_hashes(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    payload = b"defensive-read-only-test\x00\xff"
    sample.write_bytes(payload)

    hashes = hash_file(sample, chunk_size=4096)

    assert hashes == {
        "sha256": sha256(payload).hexdigest(),
        "sha1": sha1(payload).hexdigest(),
        "md5": md5(payload).hexdigest(),
    }


def test_powershell_helper_decodes_utf8_json_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"message": "Журнал событий недоступен"}
    envelope = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii")
    monkeypatch.setattr(helpers, "is_windows", lambda: True)
    monkeypatch.setattr(helpers, "_trusted_powershell_path", lambda: Path(r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
    monkeypatch.setattr(helpers, "_windows_directory", lambda: Path(r"C:\\Windows"))
    monkeypatch.setattr(
        helpers.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=envelope, stderr=""),
    )

    result = helpers.run_powershell_json("@{ ok = $true } | ConvertTo-Json")

    assert result.ok is True
    assert result.data == payload


def test_powershell_helper_captures_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "is_windows", lambda: True)
    monkeypatch.setattr(helpers, "_trusted_powershell_path", lambda: Path(r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
    monkeypatch.setattr(helpers, "_windows_directory", lambda: Path(r"C:\\Windows"))

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("powershell", 3, output=b"partial", stderr=b"late")

    monkeypatch.setattr(helpers.subprocess, "run", timeout)

    result = helpers.run_powershell_json("{} | ConvertTo-Json", timeout=3)

    assert result.ok is False
    assert result.timed_out is True
    assert result.stdout == "partial"
    assert "timed out" in result.error


def test_default_collectors_have_deterministic_unique_names() -> None:
    collectors = default_collectors()
    names = [collector.name for collector in collectors]
    assert names == [
        "file_seed",
        "live_processes",
        "network",
        "persistence",
        "event_logs",
        "filesystem_context",
        "prefetch",
    ]
    assert len(names) == len(set(names))


def test_file_seed_storage_inventory_script_remains_read_only() -> None:
    lowered = FileSeedCollector._WINDOWS_METADATA_SCRIPT.casefold()
    assert "get-ciminstance" in lowered
    assert "get-cimassociatedinstance" in lowered
    for forbidden in (
        "remove-item",
        "set-ciminstance",
        "remove-ciminstance",
        "invoke-cimmethod",
        "format-volume",
        "clear-disk",
        "initialize-disk",
        "set-disk",
        "start-process",
    ):
        assert forbidden not in lowered


def test_file_seed_collects_hash_zone_and_signature(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    suspect = tmp_path / "invoice.exe"
    suspect.write_bytes(b"not executable and never launched")
    context = make_context(tmp_path, suspect)
    monkeypatch.setattr(file_seed.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        file_seed.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=True,
            data={
                "MetadataSha256": sha256(b"not executable and never launched").hexdigest(),
                "IdentityError": None,
                "ZoneIdentifier": {
                    "Present": True,
                    "Length": 180,
                    "Content": (
                        "[ZoneTransfer]\r\nZoneId=3\r\n"
                        "HostUrl=https://downloads.example.test/invoice.exe\r\n"
                        "ReferrerUrl=https://mail.example.test/message/42\r\n"
                    ),
                    "Error": None,
                },
                "Signature": {"Status": "NotSigned", "SignerThumbprint": None},
                "SignatureError": None,
                "StorageLocation": {
                    "DriveLetter": "C:",
                    "DriveType": 3,
                    "DriveTypeName": "LocalDisk",
                    "VolumeLabel": "SYSTEM",
                    "FileSystem": "NTFS",
                    "VolumeSerialNumber": "1122AABB",
                    "VolumeGuid": "\\\\?\\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\\",
                    "DiskModel": "Internal NVMe",
                    "DiskInterfaceType": "SCSI",
                    "DiskMediaType": "Fixed hard disk media",
                    "PNPDeviceID": r"SCSI\DISK&VEN_NVME&PROD_INTERNAL\0",
                    "DeviceSerialNumber": "INTERNAL-001",
                    "DiskDeviceID": r"\\.\PHYSICALDRIVE0",
                    "PhysicalDiskCount": 1,
                },
                "StorageError": None,
            },
        ),
    )

    result = FileSeedCollector().collect(context)

    assert result.status == "completed"
    seed = next(item for item in result.evidence if item.entity_type == "file")
    assert seed.stable_key.startswith("file:sha256:")
    assert len(seed.properties["sha256"]) == 64
    assert seed.properties["zone_identifier_present"] is True
    assert seed.properties["zone_id"] == "3"
    assert seed.properties["host_url"] == "https://downloads.example.test/invoice.exe"
    assert seed.properties["current_storage"]["volume_serial_number"] == "1122AABB"
    assert seed.properties["current_storage"]["disk_interface_type"] == "SCSI"
    origins = [item for item in result.evidence if item.entity_type == "download_origin"]
    assert {item.properties["origin_role"] for item in origins} == {"HostUrl", "ReferrerUrl"}
    assert {item.entity_type for item in result.evidence} >= {
        "file",
        "alternate_data_stream",
        "authenticode_signature",
        "download_origin",
    }
    assert not any(item.entity_type == "removable_media" for item in result.evidence)
    assert {relation.relation_type for relation in result.relations} == {
        "has_alternate_stream",
        "has_signature_state",
        "reported_download_source",
    }


def test_file_seed_records_exact_current_usb_device_without_claiming_delivery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = tmp_path / "payload.exe"
    content = b"current removable-storage observation"
    suspect.write_bytes(content)
    expected_sha256 = sha256(content).hexdigest()
    monkeypatch.setattr(file_seed.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        file_seed.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=True,
            data={
                "MetadataSha256": expected_sha256,
                "IdentityError": None,
                "ZoneIdentifier": {
                    "Present": False,
                    "Length": None,
                    "Content": None,
                    "Error": None,
                },
                "Signature": {"Status": "NotSigned", "SignerThumbprint": None},
                "SignatureError": None,
                "StorageLocation": {
                    "DriveLetter": "E:",
                    "DriveType": 2,
                    "DriveTypeName": "Removable",
                    "VolumeLabel": "IR-TRANSFER",
                    "FileSystem": "exFAT",
                    "VolumeSerialNumber": "A1B2-C3D4",
                    "VolumeGuid": "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\",
                    "DiskModel": "Kingston DataTraveler 3.0 USB Device",
                    "DiskInterfaceType": "USB",
                    "DiskMediaType": "Removable Media",
                    "PNPDeviceID": r"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0\001122334455&0",
                    "DeviceSerialNumber": "001122334455",
                    "DiskDeviceID": r"\\.\PHYSICALDRIVE2",
                    "PhysicalDiskCount": 1,
                },
                "StorageError": None,
            },
        ),
    )

    result = FileSeedCollector().collect(make_context(tmp_path, suspect))

    assert result.status == "completed"
    seed = next(item for item in result.evidence if item.entity_type == "file")
    assert seed.properties["current_storage"] == {
        "drive_letter": "E:",
        "drive_type_name": "Removable",
        "volume_label": "IR-TRANSFER",
        "file_system": "exFAT",
        "volume_serial_number": "A1B2-C3D4",
        "volume_guid": "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\",
        "disk_model": "Kingston DataTraveler 3.0 USB Device",
        "disk_interface_type": "USB",
        "disk_media_type": "Removable Media",
        "pnp_device_id": r"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0\001122334455&0",
        "device_serial_number": "001122334455",
        "disk_device_id": r"\\.\PHYSICALDRIVE2",
        "drive_type": 2,
        "physical_disk_count": 1,
    }
    media = next(item for item in result.evidence if item.entity_type == "removable_media")
    assert media.confidence == "high"
    assert media.label.startswith("USB 001122334455 ·")
    assert media.properties["historical_delivery_proven"] is False
    assert media.properties["device_serial_number"] == "001122334455"
    assert media.properties["pnp_device_id"].startswith("USBSTOR\\")
    assert media.properties["classification_basis"] == [
        "Win32_LogicalDisk.DriveType=2 (removable disk)",
        "Win32_DiskDrive.InterfaceType=USB",
        "Win32_DiskDrive.PNPDeviceID identifies a USB device",
        "Win32_DiskDrive.MediaType identifies removable media",
    ]
    relation = next(
        item for item in result.relations if item.relation_type == "present_on_removable_media"
    )
    assert relation.source_key == media.stable_key
    assert relation.target_key == seed.stable_key
    assert relation.confidence == "high"
    assert "current location" in relation.rationale
    assert "does not prove" in relation.rationale


def test_file_seed_non_windows_keeps_hash_and_reports_gap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = tmp_path / "artifact.dat"
    suspect.write_bytes(b"evidence")
    monkeypatch.setattr(file_seed.helpers, "is_windows", lambda: False)

    result = FileSeedCollector().collect(make_context(tmp_path, suspect))

    assert result.status == "partial"
    assert len(result.evidence) == 1
    assert result.evidence[0].properties["sha1"] == sha1(b"evidence").hexdigest()
    assert result.gaps and "Authenticode" in result.gaps[0].source


def test_live_process_collector_builds_parent_relation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = tmp_path / "sample.exe"
    suspect.write_bytes(b"x")
    monkeypatch.setattr(processes.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        processes.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=True,
            data=[
                {"ProcessId": 10, "ParentProcessId": 4, "Name": "parent.exe", "CreationDateUtc": "2026-01-01T00:00:00Z"},
                {"ProcessId": 11, "ParentProcessId": 10, "Name": "child.exe", "CreationDateUtc": "2026-01-01T00:01:00Z"},
            ],
        ),
    )

    result = LiveProcessCollector().collect(make_context(tmp_path, suspect))

    assert result.status == "completed"
    keys = {item.properties["pid"]: item.stable_key for item in result.evidence}
    assert set(keys) == {10, 11}
    assert all(key.startswith("process:instance:") for key in keys.values())
    assert len(result.relations) == 1
    assert result.relations[0].source_key == keys[10]
    assert result.relations[0].target_key == keys[11]
    assert result.relations[0].confidence == "medium"


def test_network_collector_maps_process_and_dns(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    suspect = tmp_path / "sample.exe"
    suspect.write_bytes(b"x")
    monkeypatch.setattr(network.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        network.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=True,
            data={
                "Tcp": [
                    {
                        "LocalAddress": "10.0.0.5",
                        "LocalPort": 50000,
                        "RemoteAddress": "203.0.113.7",
                        "RemotePort": 443,
                        "State": "Established",
                        "OwningProcess": 42,
                    }
                ],
                "Processes": [{"ProcessId": 42, "Name": "sample.exe", "ExecutablePath": str(suspect)}],
                "Dns": [{"Entry": "example.test", "Data": "203.0.113.7", "Type": "A", "TimeToLive": 30}],
                "Errors": [],
            },
        ),
    )

    result = NetworkCollector().collect(make_context(tmp_path, suspect))

    assert result.status == "completed"
    assert {item.entity_type for item in result.evidence} == {
        "network_connection",
        "network_endpoint",
        "dns_cache_record",
    }
    owner = next(relation for relation in result.relations if relation.relation_type == "owns_connection")
    assert owner.source_key.startswith("process:instance:")
    assert owner.confidence == "high"


def test_persistence_collector_links_exact_suspect_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = tmp_path / "evil.exe"
    suspect.write_bytes(b"x")
    monkeypatch.setattr(persistence.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        persistence.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=True,
            data={
                "RunValues": [{"RegistryPath": "HKCU:\\Run", "ValueName": "Updater", "Command": f'"{suspect}" -quiet'}],
                "Services": [],
                "ScheduledTasks": [],
                "StartupItems": [],
                "Errors": [],
            },
        ),
    )

    result = PersistenceCollector().collect(make_context(tmp_path, suspect))

    assert len(result.evidence) == 1
    assert result.evidence[0].entity_type == "run_key_value"
    assert len(result.relations) == 1
    assert result.relations[0].confidence == "high"
    assert result.relations[0].source_key.startswith("file:sha256:")


def test_persistence_does_not_link_filename_substring_as_seed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = tmp_path / "bad.exe"
    suspect.write_bytes(b"x")
    monkeypatch.setattr(persistence.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        persistence.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=True,
            data={
                "RunValues": [{"RegistryPath": "HKCU:\\Run", "ValueName": "Updater", "Command": str(tmp_path / "bad.exe.old")}],
                "Services": [], "ScheduledTasks": [], "StartupItems": [], "Errors": [],
            },
        ),
    )
    result = PersistenceCollector().collect(make_context(tmp_path, suspect))
    assert result.evidence
    assert result.relations == []


def test_event_log_collector_records_absent_log_gap_and_event(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = tmp_path / "sample.exe"
    suspect.write_bytes(b"x")
    monkeypatch.setattr(event_logs.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        event_logs.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=True,
            data={
                "StartTimeUtc": "2026-01-01T00:00:00Z",
                "Streams": [
                    {
                        "Key": "sysmon",
                        "Label": "Sysmon",
                        "LogName": "Microsoft-Windows-Sysmon/Operational",
                        "Available": False,
                        "Enabled": None,
                        "QueryError": "log not found",
                        "Events": [],
                    },
                    {
                        "Key": "system_7045",
                        "Label": "Service installation",
                        "LogName": "System",
                        "Available": True,
                        "Enabled": True,
                        "Events": [
                            {
                                "Id": 7045,
                                "RecordId": 99,
                                "LogName": "System",
                                "TimeCreatedUtc": "2026-01-02T00:00:00Z",
                                "Message": "A service was installed",
                            }
                        ],
                    },
                ],
            },
        ),
    )

    result = EventLogCollector().collect(make_context(tmp_path, suspect))

    assert result.status == "partial"
    assert len(result.gaps) == 1
    assert result.gaps[0].source == "Microsoft-Windows-Sysmon/Operational"
    assert len(result.evidence) == 1
    assert result.evidence[0].properties["event_id"] == 7045
    assert result.evidence[0].confidence == "high"


def test_filesystem_context_is_bounded_and_relations_are_low_confidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = tmp_path / "sample.exe"
    neighbor = tmp_path / "dropped.dll"
    suspect.write_bytes(b"seed")
    neighbor.write_bytes(b"neighbor")
    monkeypatch.setattr(filesystem.helpers, "is_windows", lambda: False)
    monkeypatch.setattr(filesystem.tempfile, "gettempdir", lambda: str(tmp_path))
    context = make_context(
        tmp_path,
        suspect,
        filesystem_max_entries=100,
        filesystem_max_depth=0,
        filesystem_time_window_hours=1,
    )

    result = FilesystemContextCollector().collect(context)

    found = next(item for item in result.evidence if item.source_ref == str(neighbor))
    assert found.confidence == "low"
    relation = next(item for item in result.relations if item.target_key == found.stable_key)
    assert relation.confidence == "low"
    assert "does not prove causation" in relation.rationale
    assert result.raw_payload["scanned_entries"] <= 100


def test_prefetch_collector_reads_metadata_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    suspect = tmp_path / "MALWARE.EXE"
    suspect.write_bytes(b"seed")
    prefetch_dir = tmp_path / "Prefetch"
    prefetch_dir.mkdir()
    matching = prefetch_dir / "MALWARE.EXE-ABCDEF01.pf"
    matching.write_bytes(b"opaque prefetch bytes")
    (prefetch_dir / "OTHER.EXE-01234567.pf").write_bytes(b"other")
    monkeypatch.setattr(prefetch.helpers, "is_windows", lambda: True)

    result = PrefetchCollector().collect(
        make_context(tmp_path, suspect, prefetch_directory=str(prefetch_dir), prefetch_max_entries=100)
    )

    assert result.status == "completed"
    assert len(result.evidence) == 1
    assert result.evidence[0].source_ref == str(matching)
    assert result.evidence[0].properties["content_parsed"] is False
    assert result.relations[0].confidence == "medium"


@pytest.mark.parametrize(
    ("module", "collector"),
    [
        (processes, LiveProcessCollector()),
        (network, NetworkCollector()),
        (persistence, PersistenceCollector()),
        (event_logs, EventLogCollector()),
        (prefetch, PrefetchCollector()),
    ],
)
def test_windows_only_collectors_return_gaps_off_windows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module,
    collector,
) -> None:
    suspect = tmp_path / "sample.exe"
    suspect.write_bytes(b"x")
    monkeypatch.setattr(module.helpers, "is_windows", lambda: False)

    result = collector.collect(make_context(tmp_path, suspect))

    assert result.status == "partial"
    assert result.gaps
    assert not result.evidence
