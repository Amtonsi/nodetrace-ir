from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = PROJECT_ROOT / "scripts" / "build_fat12_efi.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("nodetrace_fat12_builder", BUILDER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _efi_payload(*, machine: int = 0x014C, size: int = 1900, subsystem: int = 10) -> bytes:
    """Return a small structurally valid PE/COFF EFI application fixture."""

    assert size >= 0x178
    payload = bytearray((index * 29 + 7) & 0xFF for index in range(size))
    payload[0:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", payload, 0x3C, pe_offset)
    payload[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        payload,
        pe_offset + 4,
        machine,
        0,
        0,
        0,
        0,
        224,
        0x0102,
    )
    optional_offset = pe_offset + 24
    struct.pack_into("<H", payload, optional_offset, 0x10B)
    struct.pack_into("<H", payload, optional_offset + 68, subsystem)
    return bytes(payload)


def _bpb(image: bytes) -> dict[str, int]:
    total_16 = struct.unpack_from("<H", image, 19)[0]
    total_32 = struct.unpack_from("<I", image, 32)[0]
    return {
        "bytes_per_sector": struct.unpack_from("<H", image, 11)[0],
        "sectors_per_cluster": image[13],
        "reserved": struct.unpack_from("<H", image, 14)[0],
        "fat_count": image[16],
        "root_entries": struct.unpack_from("<H", image, 17)[0],
        "total_sectors": total_16 or total_32,
        "media": image[21],
        "sectors_per_fat": struct.unpack_from("<H", image, 22)[0],
    }


def _short_name(entry: bytes) -> str:
    base = entry[0:8].decode("ascii").rstrip(" ")
    extension = entry[8:11].decode("ascii").rstrip(" ")
    return base + (f".{extension}" if extension else "")


def _entries(directory: bytes) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for offset in range(0, len(directory), 32):
        entry = directory[offset : offset + 32]
        if len(entry) < 32 or entry[0] == 0x00:
            break
        if entry[0] == 0xE5 or entry[11] == 0x0F or entry[11] & 0x08:
            continue
        result[_short_name(entry)] = entry
    return result


def _test_lfn_checksum(short_name: bytes) -> int:
    checksum = 0
    for value in short_name:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + value
        checksum &= 0xFF
    return checksum


def _decode_test_lfn(entries: list[bytes], short_entry: bytes) -> str:
    """Decode VFAT entries without relying on the production implementation."""

    assert entries
    count = entries[0][0] & 0x1F
    assert entries[0][0] & 0x40
    assert count == len(entries)
    chunks: dict[int, bytes] = {}
    for disk_index, entry in enumerate(entries):
        sequence = entry[0] & 0x1F
        assert sequence == count - disk_index
        assert entry[11] == 0x0F
        assert entry[12] == 0
        assert entry[13] == _test_lfn_checksum(short_entry[0:11])
        assert entry[26:28] == b"\x00\x00"
        chunks[sequence] = entry[1:11] + entry[14:26] + entry[28:32]
    encoded = b"".join(chunks[index] for index in range(1, count + 1))
    terminator = encoded.index(b"\x00\x00")
    if terminator & 1:
        terminator += 1
    return encoded[:terminator].decode("utf-16le")


def _named_entries(directory: bytes) -> dict[str, bytes]:
    """Return short and VFAT names from a raw directory for test lookups."""

    result: dict[str, bytes] = {}
    pending: list[bytes] = []
    for offset in range(0, len(directory), 32):
        entry = directory[offset : offset + 32]
        if len(entry) < 32 or entry[0] == 0x00:
            break
        if entry[0] == 0xE5:
            pending.clear()
            continue
        if entry[11] == 0x0F:
            pending.append(entry)
            continue
        if entry[11] & 0x08:
            pending.clear()
            continue
        result[_short_name(entry)] = entry
        if pending:
            result[_decode_test_lfn(pending, entry)] = entry
            pending.clear()
    assert not pending
    return result


def _fat12_value(fat: bytes, cluster: int) -> int:
    offset = cluster + cluster // 2
    pair = fat[offset] | (fat[offset + 1] << 8)
    return (pair >> 4) & 0xFFF if cluster & 1 else pair & 0xFFF


class _FatReader:
    """Independent minimal FAT12 parser used to validate generated images."""

    def __init__(self, image: bytes):
        self.image = image
        self.bpb = _bpb(image)
        sector = self.bpb["bytes_per_sector"]
        root_sectors = (
            self.bpb["root_entries"] * 32 + sector - 1
        ) // sector
        self.fat_start = self.bpb["reserved"] * sector
        self.fat_size = self.bpb["sectors_per_fat"] * sector
        self.root_start = (
            self.bpb["reserved"]
            + self.bpb["fat_count"] * self.bpb["sectors_per_fat"]
        ) * sector
        self.root_size = root_sectors * sector
        self.data_start = self.root_start + self.root_size
        self.cluster_size = self.bpb["sectors_per_cluster"] * sector
        self.fat = image[self.fat_start : self.fat_start + self.fat_size]

    def cluster(self, number: int) -> bytes:
        start = self.data_start + (number - 2) * self.cluster_size
        return self.image[start : start + self.cluster_size]

    def lookup(self, path: str) -> bytes:
        directory = self.image[self.root_start : self.root_start + self.root_size]
        components = path.upper().split("/")
        entry = b""
        for index, component in enumerate(components):
            entries = {name.upper(): value for name, value in _named_entries(directory).items()}
            entry = entries[component]
            if index + 1 < len(components):
                assert entry[11] & 0x10
                directory = self.cluster(struct.unpack_from("<H", entry, 26)[0])
        return entry

    def read_file(self, path: str) -> bytes:
        entry = self.lookup(path)
        assert not entry[11] & 0x10
        remaining = struct.unpack_from("<I", entry, 28)[0]
        cluster = struct.unpack_from("<H", entry, 26)[0]
        content = bytearray()
        seen: set[int] = set()
        while remaining:
            assert cluster not in seen
            assert 2 <= cluster < 0xFF0
            seen.add(cluster)
            chunk = self.cluster(cluster)
            take = min(remaining, len(chunk))
            content.extend(chunk[:take])
            remaining -= take
            next_cluster = _fat12_value(self.fat, cluster)
            if remaining:
                assert 2 <= next_cluster < 0xFF0
            else:
                assert next_cluster >= 0xFF8
            cluster = next_cluster
        return bytes(content)


def test_builds_deterministic_fat12_image_and_preserves_payload(tmp_path: Path) -> None:
    builder = _load_builder()
    payload = _efi_payload()
    source = tmp_path / "bootia32.efi"
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    source.write_bytes(payload)

    result = builder.build_fat12_efi(source, first)
    builder.build_fat12_efi(source, second)

    image = first.read_bytes()
    assert image == second.read_bytes()
    assert len(image) == 1440 * 1024
    assert image[510:512] == b"\x55\xAA"
    assert image[54:62] == b"FAT12   "
    assert image[43:54] == b"NODETRACE  "
    assert result.sha256 == hashlib.sha256(image).hexdigest().upper()

    bpb = _bpb(image)
    assert bpb == {
        "bytes_per_sector": 512,
        "sectors_per_cluster": 1,
        "reserved": 1,
        "fat_count": 2,
        "root_entries": 224,
        "total_sectors": 2880,
        "media": 0xF8,
        "sectors_per_fat": 9,
    }
    fat_start = bpb["reserved"] * bpb["bytes_per_sector"]
    fat_size = bpb["sectors_per_fat"] * bpb["bytes_per_sector"]
    first_fat = image[fat_start : fat_start + fat_size]
    second_fat = image[fat_start + fat_size : fat_start + fat_size * 2]
    assert first_fat == second_fat
    assert first_fat[:3] == b"\xF8\xFF\xFF"

    reader = _FatReader(image)
    assert reader.read_file("EFI/BOOT/BOOTIA32.EFI") == payload
    efi_entry = reader.lookup("EFI")
    boot_entry = reader.lookup("EFI/BOOT")
    assert efi_entry[11] == 0x10
    assert boot_entry[11] == 0x10
    boot_directory = reader.cluster(struct.unpack_from("<H", boot_entry, 26)[0])
    assert _entries(boot_directory)[".."]


def test_supports_configurable_83_destination_and_larger_image(tmp_path: Path) -> None:
    builder = _load_builder()
    payload = _efi_payload(machine=0x8664, size=5000)
    source = tmp_path / "loader.efi"
    output = tmp_path / "custom.img"
    source.write_bytes(payload)

    result = builder.build_fat12_efi(
        source,
        output,
        destination=r"tools\boot\custom.efi",
        size_kib=2880,
        volume_label="IRBOOT",
    )

    image = output.read_bytes()
    reader = _FatReader(image)
    assert result.destination == "TOOLS/BOOT/CUSTOM.EFI"
    assert len(image) == 2880 * 1024
    assert _bpb(image)["sectors_per_cluster"] == 2
    assert image[43:54] == b"IRBOOT     "
    assert reader.read_file("TOOLS/BOOT/CUSTOM.EFI") == payload


def test_adds_standard_bcd_path_and_is_deterministic(tmp_path: Path) -> None:
    builder = _load_builder()
    efi_payload = _efi_payload(size=2300)
    bcd_payload = bytes((index * 17 + 31) & 0xFF for index in range(3700))
    efi_source = tmp_path / "bootia32.efi"
    bcd_source = tmp_path / "BCD"
    first = tmp_path / "first-bcd.bin"
    second = tmp_path / "second-bcd.bin"
    efi_source.write_bytes(efi_payload)
    bcd_source.write_bytes(bcd_payload)

    result = builder.build_fat12_efi(efi_source, first, bcd=bcd_source)
    builder.build_fat12_efi(efi_source, second, bcd=bcd_source)

    image = first.read_bytes()
    assert image == second.read_bytes()
    assert result.bcd_destination == "EFI/Microsoft/Boot/BCD"
    assert result.bcd_payload_size == len(bcd_payload)
    assert result.sha256 == hashlib.sha256(image).hexdigest().upper()

    # This parser is local to the test and independently traverses both FAT
    # chains and the Microsoft VFAT long-name entry.
    reader = _FatReader(image)
    assert reader.read_file("EFI/BOOT/BOOTIA32.EFI") == efi_payload
    assert reader.read_file("EFI/Microsoft/Boot/BCD") == bcd_payload
    microsoft_entry = reader.lookup("EFI/Microsoft")
    assert _short_name(microsoft_entry) == "MICROS~1"

    # The exported reader provides a second, post-build verification surface
    # for callers that want to compare hashes without mounting the image.
    assert builder.read_fat12_file(first, "EFI/BOOT/BOOTIA32.EFI") == efi_payload
    assert builder.read_fat12_file(first, "EFI/Microsoft/Boot/BCD") == bcd_payload


def test_bcd_tree_rejects_short_alias_collision_and_unusable_inputs(tmp_path: Path) -> None:
    builder = _load_builder()
    efi_source = tmp_path / "bootia32.efi"
    bcd_source = tmp_path / "BCD"
    efi_source.write_bytes(_efi_payload())
    bcd_source.write_bytes(b"valid-bcd-fixture")

    with pytest.raises(builder.Fat12BuildError, match="alias collision"):
        builder.build_fat12_efi(
            efi_source,
            tmp_path / "collision.bin",
            destination="EFI/MICROS~1/BOOTIA32.EFI",
            bcd=bcd_source,
        )

    empty_bcd = tmp_path / "empty-bcd"
    empty_bcd.write_bytes(b"")
    with pytest.raises(builder.Fat12BuildError, match="BCD input must not be empty"):
        builder.build_fat12_efi(
            efi_source,
            tmp_path / "empty.bin",
            bcd=empty_bcd,
        )

    bcd_directory = tmp_path / "bcd-directory"
    bcd_directory.mkdir()
    with pytest.raises(builder.Fat12BuildError, match="BCD input must be a regular file"):
        builder.build_fat12_efi(
            efi_source,
            tmp_path / "directory.bin",
            bcd=bcd_directory,
        )


def test_bcd_input_symlink_is_rejected_when_supported(tmp_path: Path) -> None:
    builder = _load_builder()
    efi_source = tmp_path / "bootia32.efi"
    real_bcd = tmp_path / "real-bcd"
    linked_bcd = tmp_path / "linked-bcd"
    efi_source.write_bytes(_efi_payload())
    real_bcd.write_bytes(b"bcd")
    try:
        linked_bcd.symlink_to(real_bcd)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(builder.Fat12BuildError, match="symbolic link"):
        builder.build_fat12_efi(
            efi_source,
            tmp_path / "symlink.bin",
            bcd=linked_bcd,
        )


def test_combined_efi_and_bcd_payloads_must_fit_image(tmp_path: Path) -> None:
    builder = _load_builder()
    efi_source = tmp_path / "bootia32.efi"
    bcd_source = tmp_path / "BCD"
    efi_source.write_bytes(_efi_payload(size=900_000))
    bcd_source.write_bytes(b"B" * 600_000)

    with pytest.raises(builder.Fat12BuildError, match="payloads are too large"):
        builder.build_fat12_efi(
            efi_source,
            tmp_path / "too-large.bin",
            bcd=bcd_source,
        )


@pytest.mark.parametrize(
    "destination",
    [
        "../BOOTIA32.EFI",
        "/EFI/BOOT/BOOTIA32.EFI",
        r"C:\EFI\BOOT\BOOTIA32.EFI",
        "EFI//BOOTIA32.EFI",
        "EFI/TOO-LONG-NAME/BOOTIA32.EFI",
        "EFI/BOOT/BOOTIA32.EXE",
        "EFI/BOOT/CON.EFI",
        "EFI/BOOT/BOOT.IA32.EFI",
        "EFI/BOOT/BOOT IA.EFI",
    ],
)
def test_rejects_unsafe_or_unrepresentable_destination(
    tmp_path: Path, destination: str
) -> None:
    builder = _load_builder()
    source = tmp_path / "boot.efi"
    source.write_bytes(_efi_payload())

    with pytest.raises(builder.Fat12BuildError):
        builder.build_fat12_efi(source, tmp_path / "out.img", destination=destination)


def test_rejects_non_efi_pe_and_wrong_conventional_boot_architecture(tmp_path: Path) -> None:
    builder = _load_builder()
    source = tmp_path / "input.efi"

    source.write_bytes(b"not an executable")
    with pytest.raises(builder.Fat12BuildError, match="PE/COFF"):
        builder.build_fat12_efi(source, tmp_path / "bad.img")

    source.write_bytes(_efi_payload(subsystem=3))
    with pytest.raises(builder.Fat12BuildError, match="subsystem"):
        builder.build_fat12_efi(source, tmp_path / "subsystem.img")

    source.write_bytes(_efi_payload(machine=0x8664))
    with pytest.raises(builder.Fat12BuildError, match="BOOTIA32"):
        builder.build_fat12_efi(source, tmp_path / "architecture.img")


def test_rejects_payload_that_does_not_fit_selected_image(tmp_path: Path) -> None:
    builder = _load_builder()
    source = tmp_path / "huge.efi"
    source.write_bytes(_efi_payload(size=1_500_000))

    with pytest.raises(builder.Fat12BuildError, match="too large"):
        builder.build_fat12_efi(source, tmp_path / "out.img")


@pytest.mark.parametrize("size_kib", [0, 1439, 32768, True, 1440.5])
def test_rejects_invalid_image_sizes(tmp_path: Path, size_kib: object) -> None:
    builder = _load_builder()
    source = tmp_path / "boot.efi"
    source.write_bytes(_efi_payload())

    with pytest.raises(builder.Fat12BuildError, match="image size"):
        builder.build_fat12_efi(source, tmp_path / "out.img", size_kib=size_kib)
