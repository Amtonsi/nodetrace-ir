from __future__ import annotations

import importlib.util
import json
from pathlib import Path, PurePosixPath
import struct
import subprocess
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "build_fat16_disk.py"
SPEC = importlib.util.spec_from_file_location("nodetrace_fat16_builder", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
fat16 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fat16
SPEC.loader.exec_module(fat16)


def _files() -> dict[PurePosixPath, bytes]:
    return {
        PurePosixPath("Windows/System32/Config/SYSTEM"): b"synthetic SYSTEM hive\n",
        PurePosixPath("Windows/System32/Config/SOFTWARE"): b"synthetic SOFTWARE hive\n",
        PurePosixPath("NODETRACE_EVIDENCE_VOLUME"): b"NodeTrace IR marker\n",
        PurePosixPath("Long evidence name/русский.txt"): "данные".encode(),
    }


def test_builder_creates_deterministic_mbr_partitioned_fat16(tmp_path: Path) -> None:
    first = tmp_path / "first.raw"
    second = tmp_path / "second.raw"

    result = fat16.build_image(
        first,
        files=_files(),
        directories=[PurePosixPath("Empty Directory")],
        volume_label="IR_EVIDENCE",
        size_mib=16,
    )
    fat16.build_image(
        second,
        files=_files(),
        directories=[PurePosixPath("Empty Directory")],
        volume_label="IR_EVIDENCE",
        size_mib=16,
    )

    image = first.read_bytes()
    assert image == second.read_bytes()
    assert len(image) == 16 * 1024 * 1024
    assert image[510:512] == b"\x55\xaa"
    assert image[450] == 0x0E
    partition_lba, partition_sectors = struct.unpack_from("<II", image, 454)
    assert partition_lba == 2048
    assert partition_sectors == (len(image) // 512) - 2048

    boot_offset = partition_lba * 512
    boot = image[boot_offset : boot_offset + 512]
    assert boot[510:512] == b"\x55\xaa"
    assert struct.unpack_from("<H", boot, 11)[0] == 512
    assert boot[16] == 2
    assert struct.unpack_from("<H", boot, 17)[0] == 512
    assert boot[43:54] == b"IR_EVIDENCE"
    assert boot[54:62] == b"FAT16   "
    assert result["sha256"] == fat16.hashlib.sha256(image).hexdigest()

    reserved = struct.unpack_from("<H", boot, 14)[0]
    fat_sectors = struct.unpack_from("<H", boot, 22)[0]
    first_fat = boot_offset + reserved * 512
    second_fat = first_fat + fat_sectors * 512
    assert image[first_fat:second_fat] == image[second_fat : second_fat + fat_sectors * 512]


def test_inspector_recovers_nested_files_lfn_and_contents(tmp_path: Path) -> None:
    image_path = tmp_path / "probe.raw"
    fat16.build_image(
        image_path,
        files=_files(),
        directories=[PurePosixPath("Empty Directory")],
        volume_label="PROBE",
        size_mib=16,
    )

    inspection = fat16.inspect_image(image_path)
    entries = {entry["path"]: entry for entry in inspection["entries"]}
    assert inspection["schema"] == "nodetrace-ir/fat16-inspection/v1"
    assert inspection["volume_label"] == "PROBE"
    assert entries["Windows/System32/Config/SYSTEM"]["size"] == len(b"synthetic SYSTEM hive\n")
    assert entries["Windows/System32/Config/SOFTWARE"]["type"] == "file"
    assert entries["NODETRACE_EVIDENCE_VOLUME"]["type"] == "file"
    assert entries["Long evidence name/русский.txt"]["sha256"] == fat16.hashlib.sha256(
        "данные".encode()
    ).hexdigest()
    assert entries["Empty Directory"]["type"] == "directory"


def test_cli_build_and_inspect_emit_machine_readable_manifests(tmp_path: Path) -> None:
    source = tmp_path / "marker.txt"
    source.write_bytes(b"marker")
    image = tmp_path / "disk.raw"
    build_manifest = tmp_path / "build.json"
    inspect_manifest = tmp_path / "inspect.json"

    build = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "build",
            "--output",
            str(image),
            "--label",
            "PROBE",
            "--size-mib",
            "16",
            "--file",
            f"{source}=NODETRACE_EVIDENCE_VOLUME",
            "--json-output",
            str(build_manifest),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    inspect = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "inspect",
            "--image",
            str(image),
            "--json-output",
            str(inspect_manifest),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert inspect.returncode == 0, inspect.stdout + inspect.stderr
    assert json.loads(build_manifest.read_text(encoding="utf-8"))["volume_label"] == "PROBE"
    paths = {entry["path"] for entry in json.loads(inspect_manifest.read_text(encoding="utf-8"))["entries"]}
    assert "NODETRACE_EVIDENCE_VOLUME" in paths


def test_builder_refuses_overwrite_and_parent_traversal(tmp_path: Path) -> None:
    output = tmp_path / "disk.raw"
    output.write_bytes(b"owned")
    with pytest.raises(fat16.Fat16Error, match="overwrite"):
        fat16.build_image(output, files={}, volume_label="PROBE", size_mib=16)
    with pytest.raises(fat16.Fat16Error, match="unsafe"):
        fat16.build_image(
            tmp_path / "new.raw",
            files={PurePosixPath("../escape"): b"no"},
            volume_label="PROBE",
            size_mib=16,
        )
