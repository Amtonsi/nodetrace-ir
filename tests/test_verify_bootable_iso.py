from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = PROJECT_ROOT / "scripts" / "verify_bootable_iso.py"
SECTOR_SIZE = 2048


def _load_verifier():
    spec = importlib.util.spec_from_file_location("nodetrace_iso_verifier", VERIFIER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _both_u16(value: int) -> bytes:
    return struct.pack("<H", value) + struct.pack(">H", value)


def _both_u32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _directory_record(
    extent: int,
    size: int,
    identifier: bytes,
    *,
    directory: bool,
) -> bytes:
    padding = b"\x00" if len(identifier) % 2 == 0 else b""
    result = bytearray(33 + len(identifier) + len(padding))
    result[0] = len(result)
    result[2:10] = _both_u32(extent)
    result[10:18] = _both_u32(size)
    result[18:25] = bytes((126, 1, 1, 0, 0, 0, 0))
    result[25] = 2 if directory else 0
    result[28:32] = _both_u16(1)
    result[32] = len(identifier)
    result[33 : 33 + len(identifier)] = identifier
    return bytes(result)


def _volume_descriptor(
    descriptor_type: int,
    total_sectors: int,
    root_extent: int,
    *,
    joliet: bool,
) -> bytes:
    descriptor = bytearray(SECTOR_SIZE)
    descriptor[0] = descriptor_type
    descriptor[1:6] = b"CD001"
    descriptor[6] = 1
    descriptor[40:72] = b"TEST_BOOT_ISO".ljust(32, b" ")
    descriptor[80:88] = _both_u32(total_sectors)
    descriptor[120:124] = _both_u16(1)
    descriptor[124:128] = _both_u16(1)
    descriptor[128:132] = _both_u16(SECTOR_SIZE)
    descriptor[156:190] = _directory_record(
        root_extent, SECTOR_SIZE, b"\x00", directory=True
    )
    if joliet:
        descriptor[88:91] = b"%/E"
    return bytes(descriptor)


def _boot_record(catalog_lba: int) -> bytes:
    descriptor = bytearray(SECTOR_SIZE)
    descriptor[0] = 0
    descriptor[1:6] = b"CD001"
    descriptor[6] = 1
    descriptor[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b" ")
    struct.pack_into("<I", descriptor, 71, catalog_lba)
    return bytes(descriptor)


def _terminator() -> bytes:
    descriptor = bytearray(SECTOR_SIZE)
    descriptor[0] = 255
    descriptor[1:6] = b"CD001"
    descriptor[6] = 1
    return bytes(descriptor)


def _udf_vrs_descriptor(identifier: bytes) -> bytes:
    assert len(identifier) == 5
    descriptor = bytearray(SECTOR_SIZE)
    descriptor[0] = 0
    descriptor[1:6] = identifier
    descriptor[6] = 1
    return bytes(descriptor)

def _validation(platform: int = 0) -> bytes:
    validation = bytearray(32)
    validation[0] = 1
    validation[1] = platform
    validation[4:28] = b"NODETRACE TEST".ljust(24, b" ")
    validation[30:32] = b"\x55\xaa"
    words = struct.unpack("<16H", validation)
    struct.pack_into("<H", validation, 28, (-sum(words)) & 0xFFFF)
    assert sum(struct.unpack("<16H", validation)) & 0xFFFF == 0
    return bytes(validation)


def _boot_entry(lba: int, *, sectors_512: int = 4) -> bytes:
    entry = bytearray(32)
    entry[0] = 0x88
    entry[1] = 0
    struct.pack_into("<H", entry, 6, sectors_512)
    struct.pack_into("<I", entry, 8, lba)
    return bytes(entry)


def _root_directory(extent: int, file_identifier: bytes) -> bytes:
    records = [
        _directory_record(extent, SECTOR_SIZE, b"\x00", directory=True),
        _directory_record(extent, SECTOR_SIZE, b"\x01", directory=True),
        _directory_record(28, 2, file_identifier, directory=False),
    ]
    return b"".join(records).ljust(SECTOR_SIZE, b"\x00")


def _synthetic_iso(
    path: Path,
    *,
    efi: bool = False,
    boot_record: bool = True,
    udf_nsr02: bool = True,
) -> Path:
    sectors = 32
    image = bytearray(sectors * SECTOR_SIZE)
    image[16 * SECTOR_SIZE : 17 * SECTOR_SIZE] = _volume_descriptor(
        1, sectors, 26, joliet=False
    )
    if boot_record:
        image[17 * SECTOR_SIZE : 18 * SECTOR_SIZE] = _boot_record(23)
    else:
        image[17 * SECTOR_SIZE : 18 * SECTOR_SIZE] = bytes(
            [2]
        ) + b"CD001\x01" + bytes(SECTOR_SIZE - 7)
    supplementary = bytearray(_volume_descriptor(2, sectors, 27, joliet=True))
    image[18 * SECTOR_SIZE : 19 * SECTOR_SIZE] = supplementary
    image[19 * SECTOR_SIZE : 20 * SECTOR_SIZE] = _terminator()
    if udf_nsr02:
        for sector_number, identifier in zip(
            range(20, 23), (b"BEA01", b"NSR02", b"TEA01")
        ):
            image[
                sector_number * SECTOR_SIZE : (sector_number + 1) * SECTOR_SIZE
            ] = _udf_vrs_descriptor(identifier)

    catalog = bytearray(SECTOR_SIZE)
    catalog[0:32] = _validation()
    catalog[32:64] = _boot_entry(24)
    if efi:
        catalog[64] = 0x91
        catalog[65] = 0xEF
        struct.pack_into("<H", catalog, 66, 1)
        catalog[68:96] = b"UEFI".ljust(28, b" ")
        catalog[96:128] = _boot_entry(25)
    image[23 * SECTOR_SIZE : 24 * SECTOR_SIZE] = catalog
    image[24 * SECTOR_SIZE : 25 * SECTOR_SIZE] = b"BIOS".ljust(SECTOR_SIZE, b"\x00")
    image[25 * SECTOR_SIZE : 26 * SECTOR_SIZE] = b"UEFI".ljust(SECTOR_SIZE, b"\x00")
    image[26 * SECTOR_SIZE : 27 * SECTOR_SIZE] = _root_directory(
        26, b"NODETRAC.EX;1"
    )
    image[27 * SECTOR_SIZE : 28 * SECTOR_SIZE] = _root_directory(
        27, "NodeTraceIR.exe".encode("utf-16-be")
    )
    image[28 * SECTOR_SIZE : 28 * SECTOR_SIZE + 2] = b"MZ"
    path.write_bytes(image)
    return path


def test_verifier_accepts_hybrid_bios_uefi_and_joliet_path(tmp_path: Path) -> None:
    verifier = _load_verifier()
    image = _synthetic_iso(tmp_path / "hybrid.iso", efi=True)

    report = verifier.verify_iso(
        image, ["/NodeTraceIR.exe"], require_udf_nsr02=True
    )

    assert report["valid"] is True
    assert report["boot_modes"] == ["BIOS", "UEFI"]
    assert report["image"]["size"] == image.stat().st_size
    assert report["image"]["sha256"] == hashlib.sha256(image.read_bytes()).hexdigest()
    assert report["iso9660"]["has_joliet"] is True
    assert report["udf_nsr02"] == {
        "start_sector": 20,
        "descriptors": [
            {"identifier": "BEA01", "sector": 20},
            {"identifier": "NSR02", "sector": 21},
            {"identifier": "TEA01", "sector": 22},
        ],
    }
    assert report["el_torito"]["catalog_lba"] == 23
    assert [entry["platform"] for entry in report["el_torito"]["entries"]] == [
        "BIOS",
        "UEFI",
    ]
    assert report["expected_paths"] == [
        {
            "requested": "/NodeTraceIR.exe",
            "normalized": "NodeTraceIR.exe",
            "found": True,
            "namespaces": ["joliet"],
        }
    ]


def test_verifier_rejects_data_only_iso(tmp_path: Path) -> None:
    verifier = _load_verifier()
    image = _synthetic_iso(tmp_path / "data.iso", boot_record=False)

    report = verifier.verify_iso(image)

    assert report["valid"] is False
    assert report["boot_modes"] == []
    assert any("El Torito boot record was not found" in error for error in report["errors"])


def test_verifier_rejects_bad_catalog_checksum(tmp_path: Path) -> None:
    verifier = _load_verifier()
    image = _synthetic_iso(tmp_path / "bad-checksum.iso")
    data = bytearray(image.read_bytes())
    data[23 * SECTOR_SIZE + 4] ^= 0x01
    image.write_bytes(data)

    report = verifier.verify_iso(image)

    assert report["valid"] is False
    assert any("checksum is invalid" in error for error in report["errors"])


def test_verifier_rejects_boot_image_outside_volume(tmp_path: Path) -> None:
    verifier = _load_verifier()
    image = _synthetic_iso(tmp_path / "bad-lba.iso")
    data = bytearray(image.read_bytes())
    struct.pack_into("<I", data, 23 * SECTOR_SIZE + 32 + 8, 99)
    image.write_bytes(data)

    report = verifier.verify_iso(image)

    assert report["valid"] is False
    assert report["boot_modes"] == []
    assert any("outside the declared ISO volume" in error for error in report["errors"])


def test_verifier_rejects_each_invalid_udf_nsr02_descriptor(tmp_path: Path) -> None:
    verifier = _load_verifier()

    for offset, identifier in enumerate(("BEA01", "NSR02", "TEA01")):
        image = _synthetic_iso(tmp_path / f"bad-{identifier}.iso")
        data = bytearray(image.read_bytes())
        data[(20 + offset) * SECTOR_SIZE + 1] ^= 0x01
        image.write_bytes(data)

        report = verifier.verify_iso(image, require_udf_nsr02=True)

        assert report["valid"] is False
        assert any(
            f"requires {identifier} at sector {20 + offset}" in error
            for error in report["errors"]
        )

def test_cli_prints_json_and_fails_for_missing_expected_path(tmp_path: Path) -> None:
    image = _synthetic_iso(tmp_path / "bios.iso")

    result = subprocess.run(
        [
            sys.executable,
            str(VERIFIER_PATH),
            str(image),
            "--expect-path",
            "missing.file",
            "--compact",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert report["valid"] is False
    assert report["boot_modes"] == ["BIOS"]
    assert report["expected_paths"][0]["found"] is False
    assert any("Expected ISO path not found" in error for error in report["errors"])

def test_cli_requires_udf_nsr02_sequence(tmp_path: Path) -> None:
    image = _synthetic_iso(tmp_path / "no-udf.iso", udf_nsr02=False)

    result = subprocess.run(
        [
            sys.executable,
            str(VERIFIER_PATH),
            str(image),
            "--require-udf-nsr02",
            "--compact",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert report["valid"] is False
    assert any(
        "UDF Volume Recognition Sequence requires BEA01 at sector 20" in error
        for error in report["errors"]
    )
