#!/usr/bin/env python3
"""Create a deterministic FAT12 image containing an EFI application.

The resulting image is a FAT "superfloppy" intended to be referenced by an
El Torito UEFI no-emulation boot entry.  It uses stable short 8.3 names.  The
optional standard ``Microsoft`` directory also receives the required VFAT
long-name entry backed by the deterministic ``MICROS~1`` alias.

Example::

    python scripts/build_fat12_efi.py bootia32.efi efisys.bin

By default the application is stored as ``EFI/BOOT/BOOTIA32.EFI`` in a
1.44 MiB image.  An optional BCD store can be added at the standard
``EFI/Microsoft/Boot/BCD`` path with ``--bcd``.  ``--destination`` and
``--size-kib`` can be used for another firmware path or a larger FAT12 image.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


BYTES_PER_SECTOR = 512
RESERVED_SECTORS = 1
FAT_COUNT = 2
ROOT_ENTRY_COUNT = 224
MEDIA_DESCRIPTOR = 0xF8
DEFAULT_IMAGE_SIZE_KIB = 1440
DEFAULT_DESTINATION = "EFI/BOOT/BOOTIA32.EFI"
DEFAULT_BCD_DESTINATION = "EFI/Microsoft/Boot/BCD"
DEFAULT_VOLUME_LABEL = "NODETRACE"
MIN_IMAGE_SIZE_KIB = 1440
MAX_IMAGE_SIZE_KIB = 32767
MAX_FAT12_CLUSTERS = 4084
MAX_PATH_COMPONENTS = 32
FAT12_EOC = 0xFFF

_SHORT_NAME_PART = re.compile(r"^[A-Za-z0-9!#$%&'()@^_`{}~-]+$")
_RESERVED_DOS_NAMES = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    "CLOCK$",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_BOOT_MACHINE_BY_NAME = {
    "BOOTIA32.EFI": 0x014C,
    "BOOTX64.EFI": 0x8664,
    "BOOTARM.EFI": 0x01C2,
    "BOOTAA64.EFI": 0xAA64,
    "BOOTRISCV32.EFI": 0x5032,
    "BOOTRISCV64.EFI": 0x5064,
    "BOOTRISCV128.EFI": 0x5128,
}


class Fat12BuildError(RuntimeError):
    """Raised when the requested image cannot be represented safely."""


@dataclass(frozen=True)
class Fat12Layout:
    """Calculated on-disk FAT12 geometry."""

    total_sectors: int
    sectors_per_cluster: int
    sectors_per_fat: int
    root_directory_sectors: int
    data_start_sector: int
    cluster_count: int

    @property
    def cluster_size(self) -> int:
        return self.sectors_per_cluster * BYTES_PER_SECTOR

    @property
    def image_size(self) -> int:
        return self.total_sectors * BYTES_PER_SECTOR


@dataclass(frozen=True)
class BuildResult:
    """Summary of a successfully written image."""

    output: Path
    destination: str
    image_size: int
    payload_size: int
    sha256: str
    layout: Fat12Layout
    bcd_destination: str | None = None
    bcd_payload_size: int = 0


@dataclass
class _FileNode:
    """A file staged in the in-memory FAT directory tree."""

    name: str
    short_name: bytes
    payload: bytes
    clusters: list[int] | None = None


@dataclass
class _DirectoryNode:
    """A FAT directory with a stable short name and optional VFAT name."""

    name: str
    short_name: bytes | None
    parent: "_DirectoryNode | None"
    long_name: str | None = None
    cluster: int = 0
    directories: list["_DirectoryNode"] | None = None
    files: list[_FileNode] | None = None

    def __post_init__(self) -> None:
        if self.directories is None:
            self.directories = []
        if self.files is None:
            self.files = []


def _ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def _calculate_layout(size_kib: int) -> Fat12Layout:
    if isinstance(size_kib, bool) or not isinstance(size_kib, int):
        raise Fat12BuildError("image size must be an integer number of KiB")
    if not MIN_IMAGE_SIZE_KIB <= size_kib <= MAX_IMAGE_SIZE_KIB:
        raise Fat12BuildError(
            f"image size must be between {MIN_IMAGE_SIZE_KIB} and "
            f"{MAX_IMAGE_SIZE_KIB} KiB"
        )

    image_bytes = size_kib * 1024
    if image_bytes % BYTES_PER_SECTOR:
        raise Fat12BuildError("image size must be a multiple of 512 bytes")
    total_sectors = image_bytes // BYTES_PER_SECTOR
    root_sectors = _ceil_div(ROOT_ENTRY_COUNT * 32, BYTES_PER_SECTOR)

    for sectors_per_cluster in (1, 2, 4, 8, 16, 32, 64):
        sectors_per_fat = 1
        for _ in range(32):
            data_sectors = (
                total_sectors
                - RESERVED_SECTORS
                - FAT_COUNT * sectors_per_fat
                - root_sectors
            )
            if data_sectors <= 0:
                break
            cluster_count = data_sectors // sectors_per_cluster
            fat_bytes = _ceil_div((cluster_count + 2) * 3, 2)
            required_fat_sectors = _ceil_div(fat_bytes, BYTES_PER_SECTOR)
            if required_fat_sectors == sectors_per_fat:
                if 1 <= cluster_count <= MAX_FAT12_CLUSTERS:
                    data_start = (
                        RESERVED_SECTORS
                        + FAT_COUNT * sectors_per_fat
                        + root_sectors
                    )
                    return Fat12Layout(
                        total_sectors=total_sectors,
                        sectors_per_cluster=sectors_per_cluster,
                        sectors_per_fat=sectors_per_fat,
                        root_directory_sectors=root_sectors,
                        data_start_sector=data_start,
                        cluster_count=cluster_count,
                    )
                break
            sectors_per_fat = required_fat_sectors

    raise Fat12BuildError("requested image geometry cannot be represented as FAT12")


def _split_short_name(component: str) -> tuple[str, str]:
    if component in {"", ".", ".."}:
        raise Fat12BuildError("destination contains an empty or relative component")
    if component != component.strip():
        raise Fat12BuildError(f"destination component has surrounding whitespace: {component!r}")
    if component.endswith(".") or component.count(".") > 1:
        raise Fat12BuildError(f"destination component is not an 8.3 name: {component!r}")

    if "." in component:
        base, extension = component.split(".", 1)
    else:
        base, extension = component, ""
    if not 1 <= len(base) <= 8 or len(extension) > 3:
        raise Fat12BuildError(f"destination component is not an 8.3 name: {component!r}")
    if not _SHORT_NAME_PART.fullmatch(base) or (
        extension and not _SHORT_NAME_PART.fullmatch(extension)
    ):
        raise Fat12BuildError(
            f"destination component contains unsupported FAT characters: {component!r}"
        )

    base_upper = base.upper()
    extension_upper = extension.upper()
    if base_upper in _RESERVED_DOS_NAMES:
        raise Fat12BuildError(f"destination uses a reserved DOS name: {component!r}")
    return base_upper, extension_upper


def _encode_short_name(component: str) -> bytes:
    base, extension = _split_short_name(component)
    return base.encode("ascii").ljust(8, b" ") + extension.encode("ascii").ljust(3, b" ")


def _validate_destination(destination: str) -> tuple[str, ...]:
    if not isinstance(destination, str):
        raise Fat12BuildError("destination must be a string")
    if not destination or len(destination) > 255:
        raise Fat12BuildError("destination must contain between 1 and 255 characters")
    if destination.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", destination):
        raise Fat12BuildError("destination must be a relative path inside the FAT image")

    normalized = destination.replace("\\", "/")
    components = normalized.split("/")
    if not 1 <= len(components) <= MAX_PATH_COMPONENTS:
        raise Fat12BuildError(
            f"destination must contain at most {MAX_PATH_COMPONENTS} components"
        )
    canonical: list[str] = []
    for component in components:
        base, extension = _split_short_name(component)
        canonical.append(base + (f".{extension}" if extension else ""))

    if not canonical[-1].endswith(".EFI"):
        raise Fat12BuildError("destination file must have the .EFI extension")
    return tuple(canonical)


def _lfn_checksum(short_name: bytes) -> int:
    """Return the checksum linking a VFAT long-name entry to its 8.3 entry."""

    if len(short_name) != 11:
        raise AssertionError("a FAT short name must be exactly 11 bytes")
    checksum = 0
    for value in short_name:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + value
        checksum &= 0xFF
    return checksum


def _long_name_entries(long_name: str, short_name: bytes) -> list[bytes]:
    """Encode deterministic VFAT entries immediately preceding a short entry."""

    if not long_name or long_name in {".", ".."}:
        raise Fat12BuildError("VFAT long name must not be empty or relative")
    if any(character in '"*/:<>?\\|' or ord(character) < 0x20 for character in long_name):
        raise Fat12BuildError(f"VFAT long name contains unsupported characters: {long_name!r}")
    try:
        encoded = long_name.encode("utf-16le")
    except UnicodeEncodeError as exc:
        raise Fat12BuildError(f"VFAT long name cannot be encoded: {long_name!r}") from exc
    code_units = [encoded[index : index + 2] for index in range(0, len(encoded), 2)]
    if len(code_units) > 255:
        raise Fat12BuildError("VFAT long name exceeds 255 UTF-16 code units")
    code_units.append(b"\x00\x00")
    while len(code_units) % 13:
        code_units.append(b"\xFF\xFF")

    checksum = _lfn_checksum(short_name)
    chunks = [code_units[index : index + 13] for index in range(0, len(code_units), 13)]
    entries: list[bytes] = []
    for chunk_index in range(len(chunks) - 1, -1, -1):
        chunk = chunks[chunk_index]
        sequence = chunk_index + 1
        if chunk_index == len(chunks) - 1:
            sequence |= 0x40
        entry = bytearray(32)
        entry[0] = sequence
        entry[11] = 0x0F
        entry[12] = 0
        entry[13] = checksum
        struct.pack_into("<H", entry, 26, 0)
        entry[1:11] = b"".join(chunk[0:5])
        entry[14:26] = b"".join(chunk[5:11])
        entry[28:32] = b"".join(chunk[11:13])
        entries.append(bytes(entry))
    return entries


def _short_name_in_use(directory: _DirectoryNode, short_name: bytes) -> bool:
    return any(child.short_name == short_name for child in directory.directories or []) or any(
        child.short_name == short_name for child in directory.files or []
    )


def _add_directory(
    parent: _DirectoryNode,
    *,
    name: str,
    short_component: str,
    long_name: str | None = None,
) -> _DirectoryNode:
    """Add or merge a directory while rejecting short-name alias collisions."""

    short_name = _encode_short_name(short_component)
    for child in parent.directories or []:
        if child.name.casefold() == name.casefold():
            if child.short_name != short_name or child.long_name != long_name:
                raise Fat12BuildError(f"conflicting FAT representation for directory {name!r}")
            return child
    if any(child.name.casefold() == name.casefold() for child in parent.files or []):
        raise Fat12BuildError(f"file and directory paths collide at {name!r}")
    if _short_name_in_use(parent, short_name):
        raise Fat12BuildError(f"8.3 alias collision for directory {name!r}")
    child = _DirectoryNode(
        name=name,
        short_name=short_name,
        parent=parent,
        long_name=long_name,
    )
    if parent.directories is None:
        raise AssertionError("directory children were not initialized")
    parent.directories.append(child)
    return child


def _add_file(
    parent: _DirectoryNode,
    *,
    name: str,
    short_component: str,
    payload: bytes,
) -> _FileNode:
    short_name = _encode_short_name(short_component)
    if any(child.name.casefold() == name.casefold() for child in parent.directories or []):
        raise Fat12BuildError(f"file and directory paths collide at {name!r}")
    if any(child.name.casefold() == name.casefold() for child in parent.files or []):
        raise Fat12BuildError(f"duplicate file path at {name!r}")
    if _short_name_in_use(parent, short_name):
        raise Fat12BuildError(f"8.3 alias collision for file {name!r}")
    child = _FileNode(name=name, short_name=short_name, payload=payload)
    if parent.files is None:
        raise AssertionError("file children were not initialized")
    parent.files.append(child)
    return child


def _add_efi_path(root: _DirectoryNode, components: tuple[str, ...], payload: bytes) -> None:
    directory = root
    for component in components[:-1]:
        directory = _add_directory(
            directory,
            name=component,
            short_component=component,
        )
    _add_file(
        directory,
        name=components[-1],
        short_component=components[-1],
        payload=payload,
    )


def _add_standard_bcd_path(root: _DirectoryNode, payload: bytes) -> None:
    """Add EFI/Microsoft/Boot/BCD with a deterministic VFAT alias."""

    directory = _add_directory(root, name="EFI", short_component="EFI")
    directory = _add_directory(
        directory,
        name="Microsoft",
        short_component="MICROS~1",
        long_name="Microsoft",
    )
    directory = _add_directory(directory, name="BOOT", short_component="BOOT")
    _add_file(directory, name="BCD", short_component="BCD", payload=payload)


def _walk_directories(root: _DirectoryNode) -> list[_DirectoryNode]:
    ordered: list[_DirectoryNode] = []

    def visit(directory: _DirectoryNode) -> None:
        for child in directory.directories or []:
            ordered.append(child)
            visit(child)

    visit(root)
    return ordered


def _walk_files(root: _DirectoryNode) -> list[_FileNode]:
    ordered: list[_FileNode] = []

    def visit(directory: _DirectoryNode) -> None:
        ordered.extend(directory.files or [])
        for child in directory.directories or []:
            visit(child)

    visit(root)
    return ordered


def _validate_volume_label(volume_label: str) -> bytes:
    if not isinstance(volume_label, str):
        raise Fat12BuildError("volume label must be a string")
    if volume_label != volume_label.strip() or not 1 <= len(volume_label) <= 11:
        raise Fat12BuildError("volume label must contain 1 to 11 characters without padding")
    if "." in volume_label or not _SHORT_NAME_PART.fullmatch(volume_label):
        raise Fat12BuildError("volume label contains unsupported FAT characters")
    return volume_label.upper().encode("ascii").ljust(11, b" ")


def _validate_efi_payload(payload: bytes, destination_name: str) -> tuple[int, int]:
    if len(payload) < 0x40 or payload[:2] != b"MZ":
        raise Fat12BuildError("input is not a PE/COFF EFI executable (missing MZ header)")
    pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(payload):
        raise Fat12BuildError("input has an invalid PE header offset")
    if payload[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise Fat12BuildError("input is not a PE/COFF EFI executable (missing PE signature)")

    machine, _section_count, _timestamp, _symbols, _symbol_count, optional_size, _flags = (
        struct.unpack_from("<HHIIIHH", payload, pe_offset + 4)
    )
    optional_offset = pe_offset + 24
    if optional_size < 70 or optional_offset + optional_size > len(payload):
        raise Fat12BuildError("input has a truncated PE optional header")
    optional_magic = struct.unpack_from("<H", payload, optional_offset)[0]
    if optional_magic not in {0x10B, 0x20B}:
        raise Fat12BuildError("input uses an unsupported PE optional-header format")
    subsystem = struct.unpack_from("<H", payload, optional_offset + 68)[0]
    if subsystem != 10:  # IMAGE_SUBSYSTEM_EFI_APPLICATION
        raise Fat12BuildError(
            "input PE subsystem is not IMAGE_SUBSYSTEM_EFI_APPLICATION (10)"
        )

    expected_machine = _BOOT_MACHINE_BY_NAME.get(destination_name.upper())
    if expected_machine is not None and machine != expected_machine:
        raise Fat12BuildError(
            f"input machine 0x{machine:04X} does not match {destination_name} "
            f"(expected 0x{expected_machine:04X})"
        )
    return machine, subsystem


def _directory_entry(
    short_name: bytes,
    *,
    attributes: int,
    first_cluster: int = 0,
    size: int = 0,
) -> bytes:
    if len(short_name) != 11:
        raise AssertionError("a FAT short name must be exactly 11 bytes")
    if not 0 <= first_cluster <= 0xFFFF or not 0 <= size <= 0xFFFFFFFF:
        raise AssertionError("directory entry values are out of range")

    # 1980-01-01 00:00:00 is the earliest representable DOS timestamp and
    # makes every build independent of the source file's host metadata.
    dos_date = (1 << 5) | 1
    entry = bytearray(32)
    entry[0:11] = short_name
    entry[11] = attributes
    struct.pack_into("<H", entry, 14, 0)  # creation time
    struct.pack_into("<H", entry, 16, dos_date)
    struct.pack_into("<H", entry, 18, dos_date)  # last-access date
    struct.pack_into("<H", entry, 20, 0)  # high cluster, always zero for FAT12
    struct.pack_into("<H", entry, 22, 0)  # modification time
    struct.pack_into("<H", entry, 24, dos_date)
    struct.pack_into("<H", entry, 26, first_cluster)
    struct.pack_into("<I", entry, 28, size)
    return bytes(entry)


def _set_fat12_entry(fat: bytearray, cluster: int, value: int) -> None:
    if cluster < 0 or not 0 <= value <= 0xFFF:
        raise AssertionError("invalid FAT12 entry")
    offset = cluster + cluster // 2
    if offset + 1 >= len(fat):
        raise AssertionError("FAT12 entry exceeds the allocated table")
    if cluster & 1:
        fat[offset] = (fat[offset] & 0x0F) | ((value & 0x00F) << 4)
        fat[offset + 1] = (value >> 4) & 0xFF
    else:
        fat[offset] = value & 0xFF
        fat[offset + 1] = (fat[offset + 1] & 0xF0) | ((value >> 8) & 0x0F)


def _boot_sector(layout: Fat12Layout, volume_label: bytes) -> bytes:
    sector = bytearray(BYTES_PER_SECTOR)
    sector[0:3] = b"\xEB\x3C\x90"
    sector[3:11] = b"NODETRCE"
    struct.pack_into("<H", sector, 11, BYTES_PER_SECTOR)
    sector[13] = layout.sectors_per_cluster
    struct.pack_into("<H", sector, 14, RESERVED_SECTORS)
    sector[16] = FAT_COUNT
    struct.pack_into("<H", sector, 17, ROOT_ENTRY_COUNT)
    if layout.total_sectors <= 0xFFFF:
        struct.pack_into("<H", sector, 19, layout.total_sectors)
    else:
        struct.pack_into("<I", sector, 32, layout.total_sectors)
    sector[21] = MEDIA_DESCRIPTOR
    struct.pack_into("<H", sector, 22, layout.sectors_per_fat)
    struct.pack_into("<H", sector, 24, 18)  # conventional geometry; informational
    struct.pack_into("<H", sector, 26, 2)
    struct.pack_into("<I", sector, 28, 0)
    sector[36] = 0x80
    sector[38] = 0x29
    struct.pack_into("<I", sector, 39, 0x5254494E)  # fixed, reproducible serial
    sector[43:54] = volume_label
    sector[54:62] = b"FAT12   "
    sector[510:512] = b"\x55\xAA"
    return bytes(sector)


def _read_source(source: Path, *, description: str = "EFI input") -> bytes:
    try:
        before = source.lstat()
    except OSError as exc:
        raise Fat12BuildError(f"cannot inspect {description} {source}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise Fat12BuildError(f"{description} must not be a symbolic link")
    if not stat.S_ISREG(before.st_mode):
        raise Fat12BuildError(f"{description} must be a regular file")
    if before.st_size <= 0:
        raise Fat12BuildError(f"{description} must not be empty")
    if before.st_size > 0xFFFFFFFF:
        raise Fat12BuildError(f"{description} is too large for a FAT directory entry")
    try:
        payload = source.read_bytes()
        after = source.stat()
    except OSError as exc:
        raise Fat12BuildError(f"cannot read {description} {source}: {exc}") from exc
    before_signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_signature = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_signature != after_signature or len(payload) != before.st_size:
        raise Fat12BuildError(f"{description} changed while it was being read")
    return payload


def _write_atomic(output: Path, image: bytes) -> None:
    if output.exists() and output.is_dir():
        raise Fat12BuildError("output path names an existing directory")
    if output.is_symlink():
        raise Fat12BuildError("output path must not be a symbolic link")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(image)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except (OSError, UnboundLocalError):
            pass
        raise Fat12BuildError(f"cannot write FAT image {output}: {exc}") from exc


def _directory_bytes(
    directory: _DirectoryNode,
    *,
    capacity: int,
    volume_label: bytes | None = None,
) -> bytes:
    records: list[bytes] = []
    if volume_label is not None:
        records.append(_directory_entry(volume_label, attributes=0x08))
    else:
        records.append(
            _directory_entry(
                b".          ", attributes=0x10, first_cluster=directory.cluster
            )
        )
        parent_cluster = directory.parent.cluster if directory.parent is not None else 0
        records.append(
            _directory_entry(
                b"..         ", attributes=0x10, first_cluster=parent_cluster
            )
        )

    for child in directory.directories or []:
        if child.short_name is None:
            raise AssertionError("non-root directory has no short name")
        if child.long_name is not None:
            records.extend(_long_name_entries(child.long_name, child.short_name))
        records.append(
            _directory_entry(
                child.short_name,
                attributes=0x10,
                first_cluster=child.cluster,
            )
        )
    for child in directory.files or []:
        if not child.clusters:
            raise AssertionError("non-empty file has no allocated clusters")
        records.append(
            _directory_entry(
                child.short_name,
                attributes=0x20,
                first_cluster=child.clusters[0],
                size=len(child.payload),
            )
        )

    required = len(records) * 32
    if required > capacity:
        location = "root" if volume_label is not None else directory.name
        raise Fat12BuildError(
            f"directory {location!r} needs {required} bytes but only {capacity} are available"
        )
    result = bytearray(capacity)
    for index, record in enumerate(records):
        result[index * 32 : (index + 1) * 32] = record
    return bytes(result)


def _fat12_entry_value(fat: bytes, cluster: int) -> int:
    offset = cluster + cluster // 2
    if cluster < 0 or offset + 1 >= len(fat):
        raise Fat12BuildError("FAT12 chain references an out-of-range cluster")
    pair = fat[offset] | (fat[offset + 1] << 8)
    return (pair >> 4) & 0xFFF if cluster & 1 else pair & 0xFFF


def _decode_short_name(entry: bytes) -> str:
    try:
        base = entry[0:8].decode("ascii").rstrip(" ")
        extension = entry[8:11].decode("ascii").rstrip(" ")
    except UnicodeDecodeError as exc:
        raise Fat12BuildError("FAT directory contains a non-ASCII short name") from exc
    return base + (f".{extension}" if extension else "")


def _decode_long_name(entries: list[bytes], short_name: bytes) -> str | None:
    if not entries:
        return None
    count = entries[0][0] & 0x1F
    if not entries[0][0] & 0x40 or count != len(entries):
        raise Fat12BuildError("FAT directory contains a malformed VFAT name sequence")
    expected_checksum = _lfn_checksum(short_name)
    chunks: dict[int, bytes] = {}
    for index, entry in enumerate(entries):
        sequence = entry[0] & 0x1F
        if sequence != count - index or sequence in chunks:
            raise Fat12BuildError("FAT directory contains an unordered VFAT name sequence")
        if entry[11] != 0x0F or entry[12] != 0 or entry[13] != expected_checksum:
            raise Fat12BuildError("FAT directory contains a detached VFAT name entry")
        if struct.unpack_from("<H", entry, 26)[0] != 0:
            raise Fat12BuildError("FAT directory contains an invalid VFAT cluster field")
        chunks[sequence] = entry[1:11] + entry[14:26] + entry[28:32]

    encoded = b"".join(chunks[index] for index in range(1, count + 1))
    code_units = [encoded[index : index + 2] for index in range(0, len(encoded), 2)]
    name_units: list[bytes] = []
    terminated = False
    for unit in code_units:
        if unit == b"\x00\x00":
            terminated = True
            continue
        if terminated:
            if unit != b"\xFF\xFF":
                raise Fat12BuildError("FAT directory has data after a VFAT terminator")
            continue
        if unit == b"\xFF\xFF":
            raise Fat12BuildError("FAT directory has padding before a VFAT terminator")
        name_units.append(unit)
    if not terminated:
        raise Fat12BuildError("FAT directory contains an unterminated VFAT name")
    try:
        return b"".join(name_units).decode("utf-16le")
    except UnicodeDecodeError as exc:
        raise Fat12BuildError("FAT directory contains an invalid VFAT name") from exc


def _parse_directory(directory: bytes) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    pending_long_names: list[bytes] = []
    for offset in range(0, len(directory), 32):
        entry = directory[offset : offset + 32]
        if len(entry) < 32 or entry[0] == 0x00:
            break
        if entry[0] == 0xE5:
            pending_long_names.clear()
            continue
        if entry[11] == 0x0F:
            pending_long_names.append(entry)
            continue
        if entry[11] & 0x08:
            pending_long_names.clear()
            continue
        short_name = _decode_short_name(entry)
        long_name = _decode_long_name(pending_long_names, entry[0:11])
        pending_long_names.clear()
        for name in (short_name, long_name):
            if name is None:
                continue
            key = name.casefold()
            if key in result:
                raise Fat12BuildError(f"duplicate FAT directory name {name!r}")
            result[key] = entry
    if pending_long_names:
        raise Fat12BuildError("FAT directory ends with an orphaned VFAT name")
    return result


def read_fat12_file(image: Path | str | bytes | bytearray, path: str) -> bytes:
    """Read one file by path from a FAT12 image with strict bounds checking.

    This exported helper is also used after every build to verify that both
    input payloads can be recovered byte-for-byte through their firmware paths.
    """

    if isinstance(image, (str, Path)):
        image_path = Path(image)
        try:
            if image_path.is_symlink():
                raise Fat12BuildError("FAT image must not be a symbolic link")
            raw = image_path.read_bytes()
        except OSError as exc:
            raise Fat12BuildError(f"cannot read FAT image {image_path}: {exc}") from exc
    elif isinstance(image, (bytes, bytearray)):
        raw = bytes(image)
    else:
        raise Fat12BuildError("FAT image must be a path or bytes")
    if len(raw) < BYTES_PER_SECTOR or len(raw) > MAX_IMAGE_SIZE_KIB * 1024:
        raise Fat12BuildError("FAT image size is outside supported bounds")
    if raw[510:512] != b"\x55\xAA":
        raise Fat12BuildError("FAT image has no boot-sector signature")

    bytes_per_sector = struct.unpack_from("<H", raw, 11)[0]
    sectors_per_cluster = raw[13]
    reserved = struct.unpack_from("<H", raw, 14)[0]
    fat_count = raw[16]
    root_entries = struct.unpack_from("<H", raw, 17)[0]
    total_sectors = struct.unpack_from("<H", raw, 19)[0] or struct.unpack_from("<I", raw, 32)[0]
    sectors_per_fat = struct.unpack_from("<H", raw, 22)[0]
    if (
        bytes_per_sector != BYTES_PER_SECTOR
        or sectors_per_cluster not in {1, 2, 4, 8, 16, 32, 64}
        or reserved < 1
        or fat_count < 1
        or root_entries < 1
        or sectors_per_fat < 1
        or total_sectors * bytes_per_sector != len(raw)
    ):
        raise Fat12BuildError("FAT image has an unsupported or inconsistent BPB")

    root_sectors = _ceil_div(root_entries * 32, bytes_per_sector)
    fat_start = reserved * bytes_per_sector
    fat_size = sectors_per_fat * bytes_per_sector
    root_start = (reserved + fat_count * sectors_per_fat) * bytes_per_sector
    root_size = root_sectors * bytes_per_sector
    data_start = root_start + root_size
    cluster_size = sectors_per_cluster * bytes_per_sector
    if data_start > len(raw) or fat_start + fat_size > len(raw):
        raise Fat12BuildError("FAT image metadata extends beyond the image")
    cluster_count = (len(raw) - data_start) // cluster_size
    if not 1 <= cluster_count <= MAX_FAT12_CLUSTERS:
        raise Fat12BuildError("image is not FAT12")
    fat = raw[fat_start : fat_start + fat_size]

    def read_chain(first_cluster: int, *, size: int | None = None) -> bytes:
        if first_cluster < 2:
            if size in {None, 0}:
                return b""
            raise Fat12BuildError("non-empty FAT file has no first cluster")
        content = bytearray()
        cluster = first_cluster
        seen: set[int] = set()
        while True:
            if cluster in seen or not 2 <= cluster < cluster_count + 2:
                raise Fat12BuildError("FAT12 chain is cyclic or out of bounds")
            seen.add(cluster)
            start = data_start + (cluster - 2) * cluster_size
            content.extend(raw[start : start + cluster_size])
            following = _fat12_entry_value(fat, cluster)
            if following >= 0xFF8:
                break
            if following == 0xFF7 or not 2 <= following < 0xFF0:
                raise Fat12BuildError("FAT12 chain terminates with an invalid marker")
            cluster = following
            if len(seen) > cluster_count:
                raise Fat12BuildError("FAT12 chain exceeds the data area")
        if size is not None:
            if size > len(content):
                raise Fat12BuildError("FAT file size exceeds its allocated chain")
            return bytes(content[:size])
        return bytes(content)

    if not isinstance(path, str) or not path or path.startswith(("/", "\\")):
        raise Fat12BuildError("FAT lookup path must be relative and non-empty")
    normalized = path.replace("\\", "/")
    components = normalized.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise Fat12BuildError("FAT lookup path contains an empty or relative component")

    directory = raw[root_start : root_start + root_size]
    for index, component in enumerate(components):
        entry = _parse_directory(directory).get(component.casefold())
        if entry is None:
            raise Fat12BuildError(f"FAT path was not found: {path}")
        is_directory = bool(entry[11] & 0x10)
        first_cluster = struct.unpack_from("<H", entry, 26)[0]
        if index + 1 < len(components):
            if not is_directory:
                raise Fat12BuildError(f"FAT path component is not a directory: {component}")
            directory = read_chain(first_cluster)
            continue
        if is_directory:
            raise Fat12BuildError(f"FAT path names a directory, not a file: {path}")
        size = struct.unpack_from("<I", entry, 28)[0]
        return read_chain(first_cluster, size=size)
    raise AssertionError("validated FAT path unexpectedly had no components")


def build_fat12_efi(
    source: Path | str,
    output: Path | str,
    *,
    destination: str = DEFAULT_DESTINATION,
    size_kib: int = DEFAULT_IMAGE_SIZE_KIB,
    volume_label: str = DEFAULT_VOLUME_LABEL,
    bcd: Path | str | None = None,
) -> BuildResult:
    """Build and self-verify a reproducible FAT12 UEFI boot image.

    ``destination`` must consist solely of 8.3-compatible components.  The EFI
    source is required to be a PE/COFF EFI application, and conventional UEFI
    boot filenames are checked against their required PE machine architecture.
    If ``bcd`` is supplied, the arbitrary non-empty BCD payload is stored at
    ``EFI/Microsoft/Boot/BCD`` using the collision-checked ``MICROS~1`` alias.
    """

    source_path = Path(source)
    output_path = Path(output)
    bcd_path = Path(bcd) if bcd is not None else None
    try:
        output_resolved = output_path.resolve(strict=False)
        if source_path.resolve(strict=True) == output_resolved:
            raise Fat12BuildError("EFI input and output paths must be different")
        if bcd_path is not None and bcd_path.resolve(strict=True) == output_resolved:
            raise Fat12BuildError("BCD input and output paths must be different")
    except OSError as exc:
        raise Fat12BuildError(f"cannot resolve input or output path: {exc}") from exc

    components = _validate_destination(destination)
    encoded_label = _validate_volume_label(volume_label)
    layout = _calculate_layout(size_kib)
    payload = _read_source(source_path)
    _validate_efi_payload(payload, components[-1])
    bcd_payload = (
        _read_source(bcd_path, description="BCD input") if bcd_path is not None else None
    )

    root = _DirectoryNode(name="", short_name=None, parent=None)
    _add_efi_path(root, components, payload)
    if bcd_payload is not None:
        _add_standard_bcd_path(root, bcd_payload)

    directories = _walk_directories(root)
    files = _walk_files(root)
    required_clusters = len(directories) + sum(
        _ceil_div(len(file.payload), layout.cluster_size) for file in files
    )
    if required_clusters > layout.cluster_count:
        payload_bytes = sum(len(file.payload) for file in files)
        raise Fat12BuildError(
            f"payloads are too large for this image: {payload_bytes} bytes across "
            f"{len(files)} file(s) at {size_kib} KiB"
        )

    next_cluster = 2
    for directory in directories:
        directory.cluster = next_cluster
        next_cluster += 1
    for file in files:
        count = _ceil_div(len(file.payload), layout.cluster_size)
        file.clusters = list(range(next_cluster, next_cluster + count))
        next_cluster += count

    image = bytearray(layout.image_size)
    image[0:BYTES_PER_SECTOR] = _boot_sector(layout, encoded_label)

    fat_size = layout.sectors_per_fat * BYTES_PER_SECTOR
    fat = bytearray(fat_size)
    fat[0:3] = bytes((MEDIA_DESCRIPTOR, 0xFF, 0xFF))
    for directory in directories:
        _set_fat12_entry(fat, directory.cluster, FAT12_EOC)
    for file in files:
        if file.clusters is None:
            raise AssertionError("file clusters were not initialized")
        for index, cluster in enumerate(file.clusters):
            following = file.clusters[index + 1] if index + 1 < len(file.clusters) else FAT12_EOC
            _set_fat12_entry(fat, cluster, following)

    fat_start = RESERVED_SECTORS * BYTES_PER_SECTOR
    for copy_index in range(FAT_COUNT):
        start = fat_start + copy_index * fat_size
        image[start : start + fat_size] = fat

    root_start = (RESERVED_SECTORS + FAT_COUNT * layout.sectors_per_fat) * BYTES_PER_SECTOR
    root_bytes = _directory_bytes(
        root,
        capacity=layout.root_directory_sectors * BYTES_PER_SECTOR,
        volume_label=encoded_label,
    )
    image[root_start : root_start + len(root_bytes)] = root_bytes

    data_start = layout.data_start_sector * BYTES_PER_SECTOR

    def cluster_offset(cluster: int) -> int:
        return data_start + (cluster - 2) * layout.cluster_size

    for directory in directories:
        serialized = _directory_bytes(directory, capacity=layout.cluster_size)
        offset = cluster_offset(directory.cluster)
        image[offset : offset + layout.cluster_size] = serialized
    for file in files:
        if file.clusters is None:
            raise AssertionError("file clusters were not initialized")
        for index, cluster in enumerate(file.clusters):
            payload_start = index * layout.cluster_size
            chunk = file.payload[payload_start : payload_start + layout.cluster_size]
            offset = cluster_offset(cluster)
            image[offset : offset + len(chunk)] = chunk

    image_bytes = bytes(image)
    if read_fat12_file(image_bytes, "/".join(components)) != payload:
        raise Fat12BuildError("internal verification failed for the EFI payload")
    if bcd_payload is not None and read_fat12_file(
        image_bytes, DEFAULT_BCD_DESTINATION
    ) != bcd_payload:
        raise Fat12BuildError("internal verification failed for the BCD payload")

    _write_atomic(output_path, image_bytes)
    try:
        written = output_path.read_bytes()
    except OSError as exc:
        raise Fat12BuildError(f"cannot re-read written FAT image {output_path}: {exc}") from exc
    if written != image_bytes:
        raise Fat12BuildError("written FAT image differs from the generated image")
    if read_fat12_file(written, "/".join(components)) != payload:
        raise Fat12BuildError("written FAT image failed EFI payload verification")
    if bcd_payload is not None and read_fat12_file(
        written, DEFAULT_BCD_DESTINATION
    ) != bcd_payload:
        raise Fat12BuildError("written FAT image failed BCD payload verification")

    digest = hashlib.sha256(image_bytes).hexdigest().upper()
    return BuildResult(
        output=output_path.resolve(),
        destination="/".join(components),
        image_size=len(image_bytes),
        payload_size=len(payload),
        sha256=digest,
        layout=layout,
        bcd_destination=DEFAULT_BCD_DESTINATION if bcd_payload is not None else None,
        bcd_payload_size=len(bcd_payload) if bcd_payload is not None else 0,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a deterministic FAT12 image for an El Torito UEFI "
            "no-emulation boot entry."
        )
    )
    parser.add_argument("efi_binary", type=Path, help="PE/COFF EFI application to include")
    parser.add_argument("output", type=Path, help="FAT image to create (for example efisys.bin)")
    parser.add_argument(
        "--destination",
        default=DEFAULT_DESTINATION,
        help=f"8.3 path inside the image (default: {DEFAULT_DESTINATION})",
    )
    parser.add_argument(
        "--size-kib",
        type=int,
        default=DEFAULT_IMAGE_SIZE_KIB,
        help=f"image size in KiB (default: {DEFAULT_IMAGE_SIZE_KIB})",
    )
    parser.add_argument(
        "--volume-label",
        default=DEFAULT_VOLUME_LABEL,
        help=f"FAT volume label, at most 11 characters (default: {DEFAULT_VOLUME_LABEL})",
    )
    parser.add_argument(
        "--bcd",
        type=Path,
        help=f"optional BCD store to include at {DEFAULT_BCD_DESTINATION}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = build_fat12_efi(
            args.efi_binary,
            args.output,
            destination=args.destination,
            size_kib=args.size_kib,
            volume_label=args.volume_label,
            bcd=args.bcd,
        )
    except Fat12BuildError as exc:
        parser.error(str(exc))
    print(f"Created: {result.output}")
    print(f"EFI path: {result.destination}")
    print(f"Image bytes: {result.image_size}")
    print(f"Payload bytes: {result.payload_size}")
    if result.bcd_destination is not None:
        print(f"BCD path: {result.bcd_destination}")
        print(f"BCD bytes: {result.bcd_payload_size}")
    print(f"SHA256: {result.sha256}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
