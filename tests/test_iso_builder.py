from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = PROJECT_ROOT / "scripts" / "build_iso.py"
VERIFIER_PATH = PROJECT_ROOT / "scripts" / "verify_bootable_iso.py"
FETCHER_PATH = PROJECT_ROOT / "tools" / "fetch_avz.ps1"
LAUNCHER_PATH = PROJECT_ROOT / "iso" / "START_NODETRACE_IR.cmd"
SECTOR_SIZE = 2048


def _load_builder():
    spec = importlib.util.spec_from_file_location("nodetrace_iso_builder", BUILDER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_verifier():
    spec = importlib.util.spec_from_file_location("nodetrace_iso_verifier_for_builder", VERIFIER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _read_joliet_root_names(image: Path) -> set[str]:
    sector = SECTOR_SIZE
    with image.open("rb") as handle:
        handle.seek(17 * sector)
        supplementary = handle.read(sector)
        extent = struct.unpack_from("<I", supplementary, 158)[0]
        length = struct.unpack_from("<I", supplementary, 166)[0]
        handle.seek(extent * sector)
        directory = handle.read(length)
    names: set[str] = set()
    offset = 0
    while offset < len(directory):
        record_length = directory[offset]
        if not record_length:
            offset = ((offset // sector) + 1) * sector
            continue
        identifier_length = directory[offset + 32]
        identifier = directory[offset + 33 : offset + 33 + identifier_length]
        if identifier not in {b"\x00", b"\x01"}:
            name = identifier.decode("utf-16-be")
            stem, separator, version = name.rpartition(";")
            if separator and version.isdigit():
                name = stem[:-1] if stem.endswith(".") else stem
            names.add(name)
        offset += record_length
    return names


def _volume_descriptors(image: Path) -> list[tuple[int, bytes]]:
    descriptors: list[tuple[int, bytes]] = []
    with image.open("rb") as handle:
        for extent in range(16, 80):
            handle.seek(extent * SECTOR_SIZE)
            descriptor = handle.read(SECTOR_SIZE)
            assert len(descriptor) == SECTOR_SIZE
            assert descriptor[1:7] == b"CD001\x01"
            descriptors.append((extent, descriptor))
            if descriptor[0] == 255:
                return descriptors
    raise AssertionError("volume descriptor terminator was not found")


def _find_joliet_record(image: Path, relative_path: str) -> tuple[int, int, bool]:
    descriptors = _volume_descriptors(image)
    supplementary = next(
        descriptor
        for _, descriptor in descriptors
        if descriptor[0] == 2 and descriptor[88:91] == b"%/E"
    )
    current_extent = struct.unpack_from("<I", supplementary, 158)[0]
    current_size = struct.unpack_from("<I", supplementary, 166)[0]
    components = relative_path.replace("\\", "/").strip("/").split("/")

    for component_index, component in enumerate(components):
        with image.open("rb") as handle:
            handle.seek(current_extent * SECTOR_SIZE)
            directory = handle.read(current_size)
        match: tuple[int, int, bool] | None = None
        offset = 0
        while offset < len(directory):
            record_length = directory[offset]
            if not record_length:
                offset = ((offset // SECTOR_SIZE) + 1) * SECTOR_SIZE
                continue
            record = directory[offset : offset + record_length]
            identifier_length = record[32]
            identifier = record[33 : 33 + identifier_length]
            offset += record_length
            if identifier in {b"\x00", b"\x01"}:
                continue
            name = identifier.decode("utf-16-be")
            stem, separator, version = name.rpartition(";")
            if separator and version.isdigit():
                name = stem[:-1] if stem.endswith(".") else stem
            if name == component:
                match = (
                    struct.unpack_from("<I", record, 2)[0],
                    struct.unpack_from("<I", record, 10)[0],
                    bool(record[25] & 0x02),
                )
                break
        assert match is not None, f"Joliet path component was not found: {component}"
        if component_index < len(components) - 1:
            assert match[2] is True
            current_extent, current_size = match[0], match[1]
    assert match is not None
    return match


def _read_iso_path_table(image: Path) -> list[tuple[str, int]]:
    primary = next(
        descriptor for _, descriptor in _volume_descriptors(image) if descriptor[0] == 1
    )
    table_size = struct.unpack_from("<I", primary, 132)[0]
    table_extent = struct.unpack_from("<I", primary, 140)[0]
    with image.open("rb") as handle:
        handle.seek(table_extent * SECTOR_SIZE)
        table = handle.read(table_size)

    entries: list[tuple[str, int]] = []
    offset = 0
    while offset < len(table):
        identifier_length = table[offset]
        parent_number = struct.unpack_from("<H", table, offset + 6)[0]
        identifier = table[offset + 8 : offset + 8 + identifier_length]
        name = "." if identifier == b"\x00" else identifier.decode("ascii")
        entries.append((name, parent_number))
        offset += 8 + identifier_length + (identifier_length % 2)
    return entries


def _root_identifiers(image: Path, *, joliet: bool) -> list[bytes]:
    descriptors = _volume_descriptors(image)
    descriptor = next(
        value
        for _, value in descriptors
        if value[0] == (2 if joliet else 1)
        and (not joliet or value[88:91] == b"%/E")
    )
    extent = struct.unpack_from("<I", descriptor, 158)[0]
    length = struct.unpack_from("<I", descriptor, 166)[0]
    with image.open("rb") as handle:
        handle.seek(extent * SECTOR_SIZE)
        directory = handle.read(length)

    identifiers: list[bytes] = []
    offset = 0
    while offset < len(directory):
        record_length = directory[offset]
        if not record_length:
            offset = ((offset // SECTOR_SIZE) + 1) * SECTOR_SIZE
            continue
        identifier_length = directory[offset + 32]
        identifier = directory[offset + 33 : offset + 33 + identifier_length]
        offset += record_length
        if identifier not in {b"\x00", b"\x01"}:
            identifiers.append(identifier)
    return identifiers


def _fake_staging(tmp_path: Path) -> Path:
    staging = tmp_path / "staging"
    (staging / "AVZ").mkdir(parents=True)
    (staging / "NodeTraceIR.exe").write_bytes(b"MZ" + bytes(range(64)))
    (staging / "README_RU.txt").write_text("Диагностический носитель\n", encoding="utf-8")
    with zipfile.ZipFile(staging / "AVZ" / "avz4.zip", "w") as archive:
        archive.writestr("avz4/avz.exe", b"test-only, not AVZ")
    with zipfile.ZipFile(staging / "AVZ" / "avzbase.zip", "w") as archive:
        archive.writestr("Base/main.avz", b"test database")
    return staging


def test_iso_builder_is_deterministic_and_has_joliet(tmp_path: Path) -> None:
    builder = _load_builder()
    staging = _fake_staging(tmp_path)
    first = tmp_path / "first.iso"
    second = tmp_path / "second.iso"

    first_hash = builder.build_iso(staging, first)
    second_hash = builder.build_iso(staging, second)

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash == hashlib.sha256(first.read_bytes()).hexdigest()
    assert first.stat().st_size % 2048 == 0
    with first.open("rb") as handle:
        handle.seek(16 * 2048)
        assert handle.read(7) == b"\x01CD001\x01"
        handle.seek(17 * 2048)
        assert handle.read(7) == b"\x02CD001\x01"
    assert _read_joliet_root_names(first) == {"AVZ", "NodeTraceIR.exe", "README_RU.txt"}


@pytest.mark.parametrize(
    ("platform", "platform_id", "boot_path", "image_size"),
    (
        ("bios", 0x00, "Boot/Legacy/etfsboot.com", 2050),
        ("efi", 0xEF, "EFI/Boot/efisys.bin", 4097),
    ),
)
def test_iso_builder_writes_valid_single_platform_el_torito_catalog(
    tmp_path: Path,
    platform: str,
    platform_id: int,
    boot_path: str,
    image_size: int,
) -> None:
    builder = _load_builder()
    staging = _fake_staging(tmp_path)
    boot_file = staging.joinpath(*boot_path.split("/"))
    boot_file.parent.mkdir(parents=True, exist_ok=True)
    boot_payload = bytes((index * 17 + 3) % 256 for index in range(image_size))
    boot_file.write_bytes(boot_payload)
    # A later root sibling exposes depth-first path-table numbering defects.
    (staging / "Zulu").mkdir()
    (staging / "Zulu" / "keep.txt").write_text("keep", encoding="ascii")
    first = tmp_path / f"{platform}-first.iso"
    second = tmp_path / f"{platform}-second.iso"

    first_hash = builder.build_iso(
        staging,
        first,
        boot_image=boot_path,
        boot_platform=platform,
    )
    second_hash = builder.build_iso(
        staging,
        second,
        boot_image=boot_path,
        boot_platform=platform,
    )

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash == hashlib.sha256(first.read_bytes()).hexdigest()
    descriptors = _volume_descriptors(first)
    assert [descriptor[0] for _, descriptor in descriptors] == [1, 0, 2, 255]
    primary = descriptors[0][1]
    boot_record = descriptors[1][1]
    assert struct.unpack_from("<I", primary, 80)[0] == first.stat().st_size // SECTOR_SIZE
    assert boot_record[7:39] == b"EL TORITO SPECIFICATION".ljust(32, b"\x00")
    assert boot_record[39:71] == b"\x00" * 32
    assert boot_record[75:] == b"\x00" * (SECTOR_SIZE - 75)

    catalog_extent = struct.unpack_from("<I", boot_record, 71)[0]
    with first.open("rb") as handle:
        handle.seek(catalog_extent * SECTOR_SIZE)
        catalog = handle.read(SECTOR_SIZE)
    validation = catalog[:32]
    initial = catalog[32:64]
    assert validation[0] == 0x01
    assert validation[1] == platform_id
    assert validation[2:4] == b"\x00\x00"
    assert validation[4:28] == b"NODETRACE IR".ljust(24, b"\x00")
    assert sum(struct.unpack("<16H", validation)) & 0xFFFF == 0
    assert validation[30:32] == b"\x55\xaa"
    assert initial[0] == 0x88
    assert initial[1] == 0x00
    assert initial[2:6] == b"\x00" * 4
    assert struct.unpack_from("<H", initial, 6)[0] == (image_size + 511) // 512
    boot_extent = struct.unpack_from("<I", initial, 8)[0]
    assert initial[12:] == b"\x00" * 20
    assert catalog[64:] == b"\x00" * (SECTOR_SIZE - 64)

    joliet_extent, joliet_size, is_directory = _find_joliet_record(first, boot_path)
    assert is_directory is False
    assert joliet_extent == boot_extent
    assert joliet_size == image_size
    with first.open("rb") as handle:
        handle.seek(boot_extent * SECTOR_SIZE)
        assert handle.read(image_size) == boot_payload
        padding_size = (-image_size) % SECTOR_SIZE
        assert handle.read(padding_size) == b"\x00" * padding_size

    verification = _load_verifier().verify_iso(first, [boot_path])
    assert verification["valid"] is True, verification["errors"]
    assert verification["boot_modes"] == ["BIOS" if platform == "bios" else "UEFI"]
    assert verification["expected_paths"][0]["found"] is True


def test_iso_builder_writes_hybrid_bios_default_and_uefi_section(tmp_path: Path) -> None:
    builder = _load_builder()
    staging = _fake_staging(tmp_path)
    bios_path = "Boot/etfsboot.com"
    efi_path = "EFI/Boot/efisys.bin"
    bios_file = staging.joinpath(*bios_path.split("/"))
    efi_file = staging.joinpath(*efi_path.split("/"))
    bios_file.parent.mkdir(parents=True)
    efi_file.parent.mkdir(parents=True)
    bios_payload = bytes((index * 5 + 1) % 256 for index in range(4096))
    efi_payload = bytes((index * 7 + 2) % 256 for index in range(1024 * 1024))
    bios_file.write_bytes(bios_payload)
    efi_file.write_bytes(efi_payload)
    first = tmp_path / "hybrid-first.iso"
    second = tmp_path / "hybrid-second.iso"

    first_hash = builder.build_iso(
        staging,
        first,
        bios_boot_image=bios_path,
        efi_boot_image=efi_path,
    )
    second_hash = builder.build_iso(
        staging,
        second,
        bios_boot_image=bios_path,
        efi_boot_image=efi_path,
    )

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash == hashlib.sha256(first.read_bytes()).hexdigest()
    descriptors = _volume_descriptors(first)
    assert [descriptor[0] for _, descriptor in descriptors] == [1, 0, 2, 255]
    boot_record = descriptors[1][1]
    catalog_extent = struct.unpack_from("<I", boot_record, 71)[0]
    with first.open("rb") as handle:
        handle.seek(catalog_extent * SECTOR_SIZE)
        catalog = handle.read(SECTOR_SIZE)

    validation = catalog[0:32]
    bios_entry = catalog[32:64]
    efi_header = catalog[64:96]
    efi_entry = catalog[96:128]
    assert validation[0:2] == b"\x01\x00"
    assert sum(struct.unpack("<16H", validation)) & 0xFFFF == 0
    assert bios_entry[0:2] == b"\x88\x00"
    assert struct.unpack_from("<H", bios_entry, 6)[0] == len(bios_payload) // 512
    assert efi_header[0:2] == b"\x91\xef"
    assert struct.unpack_from("<H", efi_header, 2)[0] == 1
    assert efi_header[4:32] == b"NODETRACE IR EFI".ljust(28, b"\x00")
    assert efi_entry[0:2] == b"\x88\x00"
    assert struct.unpack_from("<H", efi_entry, 6)[0] == len(efi_payload) // 512
    assert catalog[128:] == b"\x00" * (SECTOR_SIZE - 128)

    bios_extent, bios_size, bios_is_directory = _find_joliet_record(first, bios_path)
    efi_extent, efi_size, efi_is_directory = _find_joliet_record(first, efi_path)
    assert struct.unpack_from("<I", bios_entry, 8)[0] == bios_extent
    assert struct.unpack_from("<I", efi_entry, 8)[0] == efi_extent
    assert (bios_size, bios_is_directory) == (len(bios_payload), False)
    assert (efi_size, efi_is_directory) == (len(efi_payload), False)

    verification = _load_verifier().verify_iso(first, [bios_path, efi_path])
    assert verification["valid"] is True, verification["errors"]
    assert verification["boot_modes"] == ["BIOS", "UEFI"]
    assert all(item["found"] for item in verification["expected_paths"])


def test_iso_builder_cli_exposes_explicit_hybrid_boot_images() -> None:
    builder = _load_builder()

    arguments = builder._parse_args(
        [
            "--staging",
            "staging",
            "--output",
            "hybrid.iso",
            "--bios-boot-image",
            "Boot/etfsboot.com",
            "--efi-boot-image",
            "EFI/Boot/efisys.bin",
        ]
    )

    assert arguments.bios_boot_image == "Boot/etfsboot.com"
    assert arguments.efi_boot_image == "EFI/Boot/efisys.bin"


def test_iso_path_table_numbers_nested_directories_breadth_first(tmp_path: Path) -> None:
    builder = _load_builder()
    staging = tmp_path / "staging"
    (staging / "A" / "Nested").mkdir(parents=True)
    (staging / "B").mkdir()
    (staging / "A" / "Nested" / "boot.img").write_bytes(b"boot" * 256)
    (staging / "B" / "keep.txt").write_text("keep", encoding="ascii")
    image = tmp_path / "nested.iso"

    builder.build_iso(
        staging,
        image,
        boot_image="A/Nested/boot.img",
        boot_platform="bios",
    )

    assert _read_iso_path_table(image) == [
        (".", 1),
        ("A", 1),
        ("B", 1),
        ("NESTED", 2),
    ]


def test_iso_directory_records_follow_namespace_identifier_order(tmp_path: Path) -> None:
    builder = _load_builder()
    staging = tmp_path / "staging"
    (staging / "Boot").mkdir(parents=True)
    (staging / "EFI").mkdir()
    (staging / "Boot" / "etfsboot.com").write_bytes(b"boot" * 512)
    (staging / "EFI" / "keep.txt").write_text("keep", encoding="ascii")
    (staging / "bootmgr").write_bytes(b"MZ")
    (staging / "Äther.txt").write_text("unicode", encoding="utf-8")
    image = tmp_path / "ordered.iso"

    builder.build_iso(
        staging,
        image,
        boot_image="Boot/etfsboot.com",
        boot_platform="bios",
    )

    iso_identifiers = _root_identifiers(image, joliet=False)
    joliet_identifiers = _root_identifiers(image, joliet=True)
    assert iso_identifiers == sorted(iso_identifiers)
    assert joliet_identifiers == sorted(joliet_identifiers)
    assert b"BOOTMGR.;1" in iso_identifiers
    assert "bootmgr.;1".encode("utf-16-be") in joliet_identifiers
    supplementary = next(
        descriptor
        for _, descriptor in _volume_descriptors(image)
        if descriptor[0] == 2
    )
    assert supplementary[8:40] == "NODETRACE IR".encode("utf-16-be").ljust(32, b"\x00")
    assert supplementary[318:446] == "NODETRACE IR PROJECT".encode("utf-16-be").ljust(
        128, b"\x00"
    )


def test_iso_builder_rejects_empty_or_incompletely_configured_boot_image(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    staging = _fake_staging(tmp_path)
    (staging / "empty.img").write_bytes(b"")

    with pytest.raises(builder.IsoBuildError, match="must be supplied together"):
        builder.build_iso(staging, tmp_path / "missing-platform.iso", boot_image="empty.img")
    with pytest.raises(builder.IsoBuildError, match="must not be empty"):
        builder.build_iso(
            staging,
            tmp_path / "empty.iso",
            boot_image="empty.img",
            boot_platform="bios",
        )
    with pytest.raises(builder.IsoBuildError, match="cannot be combined"):
        builder.build_iso(
            staging,
            tmp_path / "mixed-api.iso",
            boot_image="empty.img",
            boot_platform="bios",
            efi_boot_image="empty.img",
        )


def test_iso_builder_rejects_ambiguous_one_sector_uefi_image(tmp_path: Path) -> None:
    builder = _load_builder()
    staging = _fake_staging(tmp_path)
    (staging / "tiny-efi.img").write_bytes(b"E" * 512)

    with pytest.raises(builder.IsoBuildError, match="through end-of-disc"):
        builder.build_iso(
            staging,
            tmp_path / "tiny-efi.iso",
            efi_boot_image="tiny-efi.img",
        )


def test_iso_builder_rejects_output_inside_staging(tmp_path: Path) -> None:
    builder = _load_builder()
    staging = _fake_staging(tmp_path)
    with pytest.raises(builder.IsoBuildError, match="outside the staging"):
        builder.build_iso(staging, staging / "recursive.iso")


def test_iso_builder_rejects_symlink_or_reparse_point(tmp_path: Path) -> None:
    builder = _load_builder()
    staging = _fake_staging(tmp_path)
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    link = staging / "linked.txt"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("Creating symlinks is not permitted on this test host")
    with pytest.raises(builder.IsoBuildError, match="Symlinks/reparse"):
        builder.build_iso(staging, tmp_path / "unsafe.iso")


def test_iso_launcher_contract_is_manual_and_non_remediating() -> None:
    launcher = LAUNCHER_PATH.read_text(encoding="utf-8")
    assert "NODETRACE_IR_DATA_DIR=%LOCALAPPDATA%\\NodeTraceIR\\cases" in launcher
    assert "NODETRACE_AVZ_EXE=" in launcher
    assert "NODETRACE_AVZ_DISTRIBUTION=noncommercial-consent" in launcher
    assert "NODETRACE_AVZ_ARCHIVE=" in launcher
    assert "NODETRACE_AVZ_BASE_ARCHIVE=" in launcher
    assert "Expand-Archive" in launcher
    assert '"%~dp0NodeTraceIR.exe"' in launcher
    assert not any(
        line.strip().casefold().startswith('"%nodetrace_avz_exe%"')
        for line in launcher.splitlines()
    )
    assert not (PROJECT_ROOT / "iso" / "autorun.inf").exists()


def _manifest_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> dict[str, object]:
    with archive.open(info) as stream:
        entry_sha256 = hashlib.sha256(stream.read()).hexdigest()
    return {
        "path": info.filename,
        "size": info.file_size,
        "compressed_size": info.compress_size,
        "crc32": f"{info.CRC:08X}",
        "sha256": entry_sha256,
    }


def _fake_manifest(cache: Path, manifest_path: Path) -> None:
    archives = []
    for name in ("avz4.zip", "avzbase.zip"):
        path = cache / name
        with zipfile.ZipFile(path) as archive:
            entries = [_manifest_entry(archive, info) for info in archive.infolist()]
        archives.append(
            {
                "name": name,
                "url": f"https://z-oleg.com/{name}",
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "md5": hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest(),
                "zip": {
                    "entry_count": len(entries),
                    "uncompressed_size": sum(int(item["size"]) for item in entries),
                    "entries": entries,
                },
            }
        )
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "archives": archives}), encoding="utf-8"
    )


@pytest.mark.skipif(os.name != "nt", reason="PowerShell verification wrapper is Windows-only")
def test_fetch_avz_verify_only_accepts_synthetic_archives(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell is unavailable")
    cache = tmp_path / "cache"
    staging = _fake_staging(tmp_path)
    shutil.copytree(staging / "AVZ", cache)
    manifest = tmp_path / "manifest.json"
    _fake_manifest(cache, manifest)

    result = subprocess.run(
        [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            str(FETCHER_PATH),
            "-AcceptNonCommercialLicense",
            "-VerifyOnly",
            "-Destination",
            str(cache),
            "-ManifestPath",
            str(manifest),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "per-entry CRC-32/SHA-256" in result.stdout

    (cache / "avzbase.zip").write_bytes((cache / "avzbase.zip").read_bytes() + b"tamper")
    rejected = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(FETCHER_PATH),
            "-AcceptNonCommercialLicense",
            "-VerifyOnly",
            "-Destination",
            str(cache),
            "-ManifestPath",
            str(manifest),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert rejected.returncode != 0
    assert "size mismatch" in rejected.stderr


@pytest.mark.skipif(os.name != "nt", reason="PowerShell verification wrapper is Windows-only")
def test_fetch_avz_default_paths_work_under_windows_powershell(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell is unavailable")

    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    shutil.copy2(FETCHER_PATH, tools_dir / "fetch_avz.ps1")
    staging = _fake_staging(tmp_path)
    shutil.copytree(staging / "AVZ", tools_dir / "cache")
    _fake_manifest(tools_dir / "cache", tools_dir / "avz-manifest.json")

    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(tools_dir / "fetch_avz.ps1"),
            "-AcceptNonCommercialLicense",
            "-VerifyOnly",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "per-entry CRC-32/SHA-256" in result.stdout
