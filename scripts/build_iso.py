#!/usr/bin/env python3
"""Build a deterministic ISO-9660/Joliet image from a staging directory.

The writer intentionally has no third-party runtime dependency.  By default
it emits a plain data disc.  When ``--boot-image`` is supplied it also writes
a standards-based El Torito catalog for a no-emulation BIOS or UEFI image.
It never writes Windows autorun metadata.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import math
import os
import re
import stat
import struct
import tempfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterable


SECTOR_SIZE = 2048
SYSTEM_AREA_SECTORS = 16
DEFAULT_SOURCE_DATE_EPOCH = 946684800  # 2000-01-01T00:00:00Z
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


class IsoBuildError(RuntimeError):
    """Raised when the input cannot be represented safely in the image."""


@dataclass(eq=False)
class Node:
    path: Path
    name: str
    is_dir: bool
    parent: "Node | None" = None
    children: list["Node"] = field(default_factory=list)
    size: int = 0
    stat_signature: tuple[int, int, int, int] | None = None
    iso_identifier: bytes = b""
    joliet_identifier: bytes = b""
    iso_extent: int = 0
    joliet_extent: int = 0
    iso_dir_size: int = 0
    joliet_dir_size: int = 0
    file_extent: int = 0
    directory_number: int = 0


def _sectors(byte_count: int) -> int:
    return max(1, math.ceil(byte_count / SECTOR_SIZE))


def _both_u16(value: int) -> bytes:
    return struct.pack("<H", value) + struct.pack(">H", value)


def _both_u32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def _is_reparse(value: os.stat_result) -> bool:
    return bool(getattr(value, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_children(directory: Path) -> list[Path]:
    try:
        children = list(directory.iterdir())
    except OSError as exc:
        raise IsoBuildError(f"Cannot enumerate staging directory {directory}: {exc}") from exc
    return sorted(children, key=lambda item: (item.name.casefold(), item.name))


def _validate_component(name: str) -> None:
    if not name or name in {".", ".."}:
        raise IsoBuildError(f"Invalid empty or traversal path component: {name!r}")
    if any(character in name for character in ("/", "\\", "\x00")):
        raise IsoBuildError(f"Invalid path component: {name!r}")
    if any(ord(character) < 32 for character in name):
        raise IsoBuildError(f"Control character in path component: {name!r}")
    if any(character in name for character in ("*", ":", ";", "?")):
        raise IsoBuildError(f"Joliet-forbidden character in path component: {name!r}")
    encoded = name.encode("utf-16-be")
    if len(encoded) > 128:
        raise IsoBuildError(f"Joliet component exceeds 64 UCS-2 characters: {name!r}")
    if any(ord(character) > 0xFFFF for character in name):
        raise IsoBuildError(f"Joliet cannot represent non-BMP character in: {name!r}")


def _scan_tree(staging: Path) -> Node:
    root_stat = os.stat(staging, follow_symlinks=False)
    if not stat.S_ISDIR(root_stat.st_mode) or _is_reparse(root_stat):
        raise IsoBuildError("Staging must be a real directory, not a symlink/reparse point.")

    root = Node(path=staging, name="", is_dir=True)

    def visit(parent: Node) -> None:
        for child_path in _safe_children(parent.path):
            _validate_component(child_path.name)
            value = os.stat(child_path, follow_symlinks=False)
            if stat.S_ISLNK(value.st_mode) or _is_reparse(value):
                raise IsoBuildError(f"Symlinks/reparse points are not accepted: {child_path}")
            if stat.S_ISDIR(value.st_mode):
                child = Node(
                    path=child_path,
                    name=child_path.name,
                    is_dir=True,
                    parent=parent,
                )
                parent.children.append(child)
                visit(child)
            elif stat.S_ISREG(value.st_mode):
                child = Node(
                    path=child_path,
                    name=child_path.name,
                    is_dir=False,
                    parent=parent,
                    size=value.st_size,
                    stat_signature=_stat_signature(value),
                )
                parent.children.append(child)
            else:
                raise IsoBuildError(f"Only regular files and directories are accepted: {child_path}")

    visit(root)
    return root


_ISO_ALLOWED = re.compile(r"[^A-Z0-9_]")


def _ascii_token(value: str, fallback: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    token = _ISO_ALLOWED.sub("_", normalized.upper()).strip("_")
    return token or fallback


def _unique_iso_identifier(name: str, is_dir: bool, used: set[str]) -> bytes:
    if is_dir:
        stem = _ascii_token(name, "DIR")
        extension = ""
    else:
        raw_stem, separator, raw_extension = name.rpartition(".")
        if not separator:
            raw_stem, raw_extension = name, ""
        stem = _ascii_token(raw_stem, "FILE")
        extension = _ascii_token(raw_extension, "")[:3] if raw_extension else ""

    for index in range(10000):
        suffix = "" if index == 0 else f"~{index}"
        limit = 8 - len(suffix)
        if limit < 1:
            break
        candidate_stem = stem[:limit] + suffix
        candidate = candidate_stem if is_dir else f"{candidate_stem}.{extension}"
        key = candidate.casefold()
        if key not in used:
            used.add(key)
            if not is_dir:
                candidate += ";1"
            return candidate.encode("ascii")
    raise IsoBuildError(f"Could not allocate a unique ISO-9660 identifier for {name!r}")


def _joliet_identifier(name: str) -> bytes:
    # Joliet retains ISO-9660's Separator 1 and Separator 2.  They are UCS-2
    # FULL STOP and SEMICOLON code points rather than the 8-bit originals.
    # The final dot is required when an extensionless name has an empty File
    # Name Extension; Windows hides both separators when presenting the name.
    body = name if "." in name else f"{name}."
    return f"{body};1".encode("utf-16-be")


def _assign_identifiers(root: Node) -> None:
    def visit(directory: Node) -> None:
        used: set[str] = set()
        for child in directory.children:
            child.iso_identifier = _unique_iso_identifier(child.name, child.is_dir, used)
            child.joliet_identifier = _joliet_identifier(child.name)
            if child.is_dir:
                visit(child)

    visit(root)


def _directories(root: Node) -> list[Node]:
    result: list[Node] = []

    def visit(node: Node) -> None:
        result.append(node)
        for child in node.children:
            if child.is_dir:
                visit(child)

    visit(root)
    for number, directory in enumerate(result, start=1):
        directory.directory_number = number
    return result


def _files(root: Node) -> list[Node]:
    result: list[Node] = []

    def visit(node: Node) -> None:
        for child in node.children:
            if child.is_dir:
                visit(child)
            else:
                result.append(child)

    visit(root)
    return result


def _recording_date(timestamp: dt.datetime) -> bytes:
    return bytes(
        (
            timestamp.year - 1900,
            timestamp.month,
            timestamp.day,
            timestamp.hour,
            timestamp.minute,
            timestamp.second,
            0,
        )
    )


def _volume_date(timestamp: dt.datetime) -> bytes:
    return timestamp.strftime("%Y%m%d%H%M%S00").encode("ascii") + b"\x00"


def _directory_record(
    *,
    extent: int,
    data_length: int,
    identifier: bytes,
    is_dir: bool,
    timestamp: dt.datetime,
) -> bytes:
    padding = b"\x00" if len(identifier) % 2 == 0 else b""
    record_length = 33 + len(identifier) + len(padding)
    if record_length > 255:
        raise IsoBuildError("Directory record exceeds the ISO-9660 one-byte length field.")
    return b"".join(
        (
            bytes((record_length, 0)),
            struct.pack("<I", extent),
            struct.pack(">I", extent),
            struct.pack("<I", data_length),
            struct.pack(">I", data_length),
            _recording_date(timestamp),
            bytes((2 if is_dir else 0, 0, 0)),
            _both_u16(1),
            bytes((len(identifier),)),
            identifier,
            padding,
        )
    )


def _pack_sector_records(records: Iterable[bytes]) -> bytes:
    output = bytearray()
    for record in records:
        offset = len(output) % SECTOR_SIZE
        if offset + len(record) > SECTOR_SIZE:
            output.extend(b"\x00" * (SECTOR_SIZE - offset))
        output.extend(record)
    remainder = len(output) % SECTOR_SIZE
    if remainder:
        output.extend(b"\x00" * (SECTOR_SIZE - remainder))
    return bytes(output or b"\x00" * SECTOR_SIZE)


def _directory_size(directory: Node, joliet: bool, timestamp: dt.datetime) -> int:
    identifiers = [b"\x00", b"\x01"]
    identifiers.extend(
        child.joliet_identifier if joliet else child.iso_identifier
        for child in directory.children
    )
    records = [
        _directory_record(
            extent=0,
            data_length=0,
            identifier=identifier,
            is_dir=True,
            timestamp=timestamp,
        )
        for identifier in identifiers
    ]
    return len(_pack_sector_records(records))


def _directory_bytes(directory: Node, joliet: bool, timestamp: dt.datetime) -> bytes:
    current_extent = directory.joliet_extent if joliet else directory.iso_extent
    current_size = directory.joliet_dir_size if joliet else directory.iso_dir_size
    parent = directory.parent or directory
    parent_extent = parent.joliet_extent if joliet else parent.iso_extent
    parent_size = parent.joliet_dir_size if joliet else parent.iso_dir_size
    records = [
        _directory_record(
            extent=current_extent,
            data_length=current_size,
            identifier=b"\x00",
            is_dir=True,
            timestamp=timestamp,
        ),
        _directory_record(
            extent=parent_extent,
            data_length=parent_size,
            identifier=b"\x01",
            is_dir=True,
            timestamp=timestamp,
        ),
    ]
    children = sorted(
        directory.children,
        key=lambda child: child.joliet_identifier if joliet else child.iso_identifier,
    )
    for child in children:
        identifier = child.joliet_identifier if joliet else child.iso_identifier
        if child.is_dir:
            extent = child.joliet_extent if joliet else child.iso_extent
            length = child.joliet_dir_size if joliet else child.iso_dir_size
        else:
            extent = child.file_extent
            length = child.size
        records.append(
            _directory_record(
                extent=extent,
                data_length=length,
                identifier=identifier,
                is_dir=child.is_dir,
                timestamp=timestamp,
            )
        )
    result = _pack_sector_records(records)
    expected = directory.joliet_dir_size if joliet else directory.iso_dir_size
    if len(result) != expected:
        raise IsoBuildError("Internal directory sizing mismatch.")
    return result


def _path_table(directories: list[Node], joliet: bool, big_endian: bool) -> bytes:
    result = bytearray()
    order = ">" if big_endian else "<"
    if not directories or directories[0].parent is not None:
        raise IsoBuildError("Internal path-table root is invalid.")

    # ECMA-119 path-table directory numbers are assigned breadth-first: all
    # children of a lower-numbered parent must precede children of a later
    # parent.  The filesystem tree itself is traversed depth-first elsewhere,
    # so build a namespace-specific queue here and sort siblings by the exact
    # identifier bytes written to this path table.
    ordered = [directories[0]]
    index = 0
    while index < len(ordered):
        parent = ordered[index]
        children = [child for child in parent.children if child.is_dir]
        children.sort(key=lambda child: child.joliet_identifier if joliet else child.iso_identifier)
        ordered.extend(children)
        index += 1
    if len(ordered) != len(directories):
        raise IsoBuildError("Internal path-table directory count mismatch.")
    directory_numbers = {directory: number for number, directory in enumerate(ordered, start=1)}

    for directory in ordered:
        if directory.parent is None:
            identifier = b"\x00"
            parent_number = 1
        else:
            identifier = directory.joliet_identifier if joliet else directory.iso_identifier
            parent_number = directory_numbers[directory.parent]
        extent = directory.joliet_extent if joliet else directory.iso_extent
        result.extend(bytes((len(identifier), 0)))
        result.extend(struct.pack(f"{order}I", extent))
        result.extend(struct.pack(f"{order}H", parent_number))
        result.extend(identifier)
        if len(identifier) % 2:
            result.extend(b"\x00")
    return bytes(result)


def _ascii_field(value: str, length: int) -> bytes:
    encoded = value.encode("ascii", "strict")
    if len(encoded) > length:
        raise IsoBuildError(f"ISO descriptor field is too long: {value!r}")
    return encoded.ljust(length, b" ")


def _joliet_field(value: str, length: int) -> bytes:
    encoded = value.encode("utf-16-be")
    if len(encoded) > length:
        raise IsoBuildError(f"Joliet descriptor field is too long: {value!r}")
    return encoded.ljust(length, b"\x00")


def _volume_descriptor(
    *,
    descriptor_type: int,
    volume_label: str,
    total_sectors: int,
    path_table_size: int,
    path_table_l_extent: int,
    path_table_m_extent: int,
    root_extent: int,
    root_size: int,
    timestamp: dt.datetime,
    joliet: bool,
) -> bytes:
    data = bytearray(SECTOR_SIZE)
    data[0] = descriptor_type
    data[1:6] = b"CD001"
    data[6] = 1
    if joliet:
        data[8:40] = _joliet_field("NODETRACE IR", 32)
        data[40:72] = _joliet_field(volume_label, 32)
        data[88:91] = b"%/E"
        data[318:446] = _joliet_field("NODETRACE IR PROJECT", 128)
        data[446:574] = _joliet_field("NODETRACE IR ISO BUILDER", 128)
        data[574:702] = _joliet_field("NODETRACE IR LIVE WINDOWS MEDIA", 128)
    else:
        data[8:40] = _ascii_field("NODETRACE IR", 32)
        data[40:72] = _ascii_field(volume_label, 32)
        data[318:446] = _ascii_field("NODETRACE IR PROJECT", 128)
        data[446:574] = _ascii_field("NODETRACE IR ISO BUILDER", 128)
        data[574:702] = _ascii_field("NODETRACE IR LIVE WINDOWS MEDIA", 128)
    data[80:88] = _both_u32(total_sectors)
    data[120:124] = _both_u16(1)
    data[124:128] = _both_u16(1)
    data[128:132] = _both_u16(SECTOR_SIZE)
    data[132:140] = _both_u32(path_table_size)
    data[140:144] = struct.pack("<I", path_table_l_extent)
    data[148:152] = struct.pack(">I", path_table_m_extent)
    root_record = _directory_record(
        extent=root_extent,
        data_length=root_size,
        identifier=b"\x00",
        is_dir=True,
        timestamp=timestamp,
    )
    if len(root_record) != 34:
        raise IsoBuildError("Internal root directory record mismatch.")
    data[156:190] = root_record
    creation = _volume_date(timestamp)
    data[813:830] = creation
    data[830:847] = creation
    data[847:864] = b"0" * 16 + b"\x00"
    data[864:881] = b"0" * 16 + b"\x00"
    data[881] = 1
    return bytes(data)


def _terminator() -> bytes:
    data = bytearray(SECTOR_SIZE)
    data[0] = 255
    data[1:6] = b"CD001"
    data[6] = 1
    return bytes(data)


def _boot_record(catalog_extent: int) -> bytes:
    data = bytearray(SECTOR_SIZE)
    data[0] = 0
    data[1:6] = b"CD001"
    data[6] = 1
    # El Torito character strings are NUL-padded, unlike the space-padded
    # identifiers in the surrounding ISO-9660 volume descriptors.
    data[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b"\x00")
    struct.pack_into("<I", data, 71, catalog_extent)
    return bytes(data)


def _boot_catalog_entry(*, image_extent: int, image_size: int) -> bytes:
    if image_size <= 0:
        raise IsoBuildError("El Torito boot image must not be empty.")
    load_sectors = math.ceil(image_size / 512)
    if load_sectors > 0xFFFF:
        raise IsoBuildError("El Torito boot image exceeds the 16-bit load-sector field.")

    entry = bytearray(32)
    entry[0] = 0x88  # bootable
    entry[1] = 0x00  # no emulation
    struct.pack_into("<H", entry, 6, load_sectors)
    struct.pack_into("<I", entry, 8, image_extent)
    return bytes(entry)


def _boot_catalog(*, images: list[tuple[str, int, int]]) -> bytes:
    if not images:
        raise IsoBuildError("At least one El Torito boot image is required.")
    platforms = [platform for platform, _, _ in images]
    if any(platform not in {"bios", "efi"} for platform in platforms):
        raise IsoBuildError(f"Unsupported El Torito platform list: {platforms!r}")
    if len(platforms) != len(set(platforms)):
        raise IsoBuildError("Only one El Torito image per platform is supported.")
    if len(images) > 2:
        raise IsoBuildError("At most BIOS and UEFI El Torito images are supported.")
    for platform, _, image_size in images:
        if platform == "efi" and 0 < image_size <= 512:
            raise IsoBuildError(
                "UEFI El Torito images must exceed 512 bytes; sector counts 0 and 1 mean through end-of-disc."
            )

    platform_id = 0x00 if images[0][0] == "bios" else 0xEF
    validation = bytearray(32)
    validation[0] = 0x01
    validation[1] = platform_id
    validation[4:28] = b"NODETRACE IR".ljust(24, b"\x00")
    validation[30:32] = b"\x55\xaa"
    checksum = (-sum(struct.unpack("<16H", validation))) & 0xFFFF
    struct.pack_into("<H", validation, 28, checksum)
    if sum(struct.unpack("<16H", validation)) & 0xFFFF:
        raise IsoBuildError("Internal El Torito validation checksum failure.")

    catalog = bytearray(SECTOR_SIZE)
    catalog[0:32] = validation
    _, first_extent, first_size = images[0]
    catalog[32:64] = _boot_catalog_entry(
        image_extent=first_extent,
        image_size=first_size,
    )
    offset = 64
    for index, (platform, image_extent, image_size) in enumerate(images[1:]):
        section = bytearray(32)
        section[0] = 0x91 if index == len(images[1:]) - 1 else 0x90
        section[1] = 0x00 if platform == "bios" else 0xEF
        struct.pack_into("<H", section, 2, 1)
        section[4:32] = f"NODETRACE IR {platform.upper()}".encode("ascii").ljust(28, b"\x00")
        catalog[offset : offset + 32] = section
        offset += 32
        catalog[offset : offset + 32] = _boot_catalog_entry(
            image_extent=image_extent,
            image_size=image_size,
        )
        offset += 32
    return bytes(catalog)


def _find_file(root: Node, relative_path: str) -> Node:
    normalized = relative_path.replace("\\", "/").strip("/")
    components = normalized.split("/") if normalized else []
    if not components or any(component in {"", ".", ".."} for component in components):
        raise IsoBuildError(f"Invalid boot image path: {relative_path!r}")
    current = root
    for index, component in enumerate(components):
        matches = [child for child in current.children if child.name == component]
        if len(matches) != 1:
            raise IsoBuildError(f"Boot image was not found in staging: {relative_path}")
        current = matches[0]
        if index < len(components) - 1 and not current.is_dir:
            raise IsoBuildError(f"Boot image path crosses a regular file: {relative_path}")
    if current.is_dir:
        raise IsoBuildError(f"Boot image path names a directory: {relative_path}")
    return current


def _write_sector_data(handle: BinaryIO, extent: int, payload: bytes) -> None:
    handle.seek(extent * SECTOR_SIZE)
    handle.write(payload)


def _copy_file(handle: BinaryIO, node: Node) -> None:
    current = os.stat(node.path, follow_symlinks=False)
    if _is_reparse(current) or _stat_signature(current) != node.stat_signature:
        raise IsoBuildError(f"Input changed while the image was being planned: {node.path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        flags |= no_follow
    descriptor = os.open(node.path, flags)
    try:
        opened = os.fstat(descriptor)
        if _stat_signature(opened) != node.stat_signature:
            raise IsoBuildError(f"Input changed while it was being opened: {node.path}")
        handle.seek(node.file_extent * SECTOR_SIZE)
        remaining = node.size
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise IsoBuildError(f"Unexpected end of input file: {node.path}")
                handle.write(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise IsoBuildError(f"Input grew while it was being copied: {node.path}")
        if _stat_signature(os.fstat(descriptor)) != node.stat_signature:
            raise IsoBuildError(f"Input changed while it was being copied: {node.path}")
    finally:
        os.close(descriptor)


def _verify_image(
    path: Path,
    expected_sectors: int,
    *,
    boot_images: list[tuple[str, int, int]] | None = None,
    boot_catalog_extent: int | None = None,
) -> None:
    effective_boot_images = list(boot_images or [])
    if path.stat().st_size != expected_sectors * SECTOR_SIZE:
        raise IsoBuildError("ISO size does not match its declared volume size.")
    with path.open("rb") as handle:
        handle.seek(16 * SECTOR_SIZE)
        primary = handle.read(SECTOR_SIZE)
        second = handle.read(SECTOR_SIZE)
        third = handle.read(SECTOR_SIZE)
        fourth = handle.read(SECTOR_SIZE) if effective_boot_images else b""
        if boot_catalog_extent is not None:
            handle.seek(boot_catalog_extent * SECTOR_SIZE)
            catalog = handle.read(SECTOR_SIZE)
        else:
            catalog = b""
    if primary[:7] != b"\x01CD001\x01":
        raise IsoBuildError("Primary volume descriptor validation failed.")
    if not effective_boot_images:
        supplementary, terminator = second, third
    else:
        boot_record, supplementary, terminator = second, third, fourth
        if boot_record[:7] != b"\x00CD001\x01":
            raise IsoBuildError("El Torito boot record validation failed.")
        expected_system_id = b"EL TORITO SPECIFICATION".ljust(32, b"\x00")
        if boot_record[7:39] != expected_system_id:
            raise IsoBuildError("El Torito boot system identifier validation failed.")
        if any(boot_record[39:71]) or any(boot_record[75:]):
            raise IsoBuildError("El Torito boot record reserved bytes are not zero.")
        if boot_catalog_extent is None or struct.unpack_from("<I", boot_record, 71)[0] != boot_catalog_extent:
            raise IsoBuildError("El Torito boot catalog pointer validation failed.")
        if len(catalog) != SECTOR_SIZE or catalog[0] != 1 or catalog[30:32] != b"\x55\xaa":
            raise IsoBuildError("El Torito validation entry is malformed.")
        if catalog[2:4] != b"\x00\x00" or catalog[4:28] != b"NODETRACE IR".ljust(24, b"\x00"):
            raise IsoBuildError("El Torito validation entry reserved or identifier bytes are malformed.")
        if sum(struct.unpack("<16H", catalog[:32])) & 0xFFFF:
            raise IsoBuildError("El Torito validation checksum failed.")
        expected_platform = 0x00 if effective_boot_images[0][0] == "bios" else 0xEF
        if catalog[1] != expected_platform or catalog[32] != 0x88:
            raise IsoBuildError("El Torito platform or boot indicator validation failed.")
        expected_catalog = _boot_catalog(images=effective_boot_images)
        if catalog != expected_catalog:
            raise IsoBuildError("El Torito catalog entries or padding failed validation.")
    if supplementary[:7] != b"\x02CD001\x01" or supplementary[88:91] != b"%/E":
        raise IsoBuildError("Joliet supplementary volume descriptor validation failed.")
    if terminator[:7] != b"\xffCD001\x01":
        raise IsoBuildError("Volume descriptor terminator validation failed.")
    declared = struct.unpack_from("<I", primary, 80)[0]
    if declared != expected_sectors:
        raise IsoBuildError("Primary volume descriptor contains an invalid volume size.")


def build_iso(
    staging: Path,
    output: Path,
    *,
    volume_label: str = "NODETRACE_IR",
    source_date_epoch: int = DEFAULT_SOURCE_DATE_EPOCH,
    boot_image: str | None = None,
    boot_platform: str | None = None,
    bios_boot_image: str | None = None,
    efi_boot_image: str | None = None,
) -> str:
    """Build *output* from *staging* and return its lowercase SHA-256."""

    staging = staging.resolve(strict=True)
    output = output.resolve(strict=False)
    if _is_relative_to(output, staging):
        raise IsoBuildError("Output ISO must be outside the staging directory.")
    if not re.fullmatch(r"[A-Z0-9_]{1,16}", volume_label):
        raise IsoBuildError("Volume label must contain 1-16 uppercase ASCII letters, digits or underscores.")
    try:
        timestamp = dt.datetime.fromtimestamp(source_date_epoch, tz=dt.timezone.utc).replace(tzinfo=None)
    except (OSError, OverflowError, ValueError) as exc:
        raise IsoBuildError(f"Invalid source-date epoch: {source_date_epoch}") from exc
    if not 1900 <= timestamp.year <= 2155:
        raise IsoBuildError("ISO recording timestamps must be between 1900 and 2155.")

    root = _scan_tree(staging)
    _assign_identifiers(root)
    directories = _directories(root)
    files = _files(root)
    if not files:
        raise IsoBuildError("Staging directory is empty.")
    legacy_boot_requested = boot_image is not None or boot_platform is not None
    explicit_boot_requested = bios_boot_image is not None or efi_boot_image is not None
    if legacy_boot_requested and explicit_boot_requested:
        raise IsoBuildError(
            "Legacy boot_image/boot_platform cannot be combined with explicit BIOS/UEFI boot images."
        )
    if (boot_image is None) != (boot_platform is None):
        raise IsoBuildError("boot_image and boot_platform must be supplied together.")
    boot_nodes: list[tuple[str, Node]] = []
    if boot_image is not None:
        if boot_platform not in {"bios", "efi"}:
            raise IsoBuildError("boot_platform must be 'bios' or 'efi'.")
        boot_nodes.append((boot_platform, _find_file(root, boot_image)))
    else:
        # A hybrid image must use BIOS as its Initial/Default Entry.  UEFI is
        # represented by a final platform section as required by El Torito.
        if bios_boot_image is not None:
            boot_nodes.append(("bios", _find_file(root, bios_boot_image)))
        if efi_boot_image is not None:
            boot_nodes.append(("efi", _find_file(root, efi_boot_image)))

    for directory in directories:
        directory.iso_dir_size = _directory_size(directory, False, timestamp)
        directory.joliet_dir_size = _directory_size(directory, True, timestamp)

    # Four path tables are reserved first. Their byte lengths are independent
    # of directory extents, so zero extents are sufficient for sizing.
    iso_path_size = len(_path_table(directories, False, False))
    joliet_path_size = len(_path_table(directories, True, False))
    descriptor_count = 4 if boot_nodes else 3
    cursor = 16 + descriptor_count
    boot_catalog_extent: int | None = None
    if boot_nodes:
        boot_catalog_extent = cursor
        cursor += 1
    iso_l_extent = cursor
    cursor += _sectors(iso_path_size)
    iso_m_extent = cursor
    cursor += _sectors(iso_path_size)
    joliet_l_extent = cursor
    cursor += _sectors(joliet_path_size)
    joliet_m_extent = cursor
    cursor += _sectors(joliet_path_size)

    for directory in directories:
        directory.iso_extent = cursor
        cursor += _sectors(directory.iso_dir_size)
    for directory in directories:
        directory.joliet_extent = cursor
        cursor += _sectors(directory.joliet_dir_size)
    for file_node in files:
        file_node.file_extent = cursor
        cursor += _sectors(file_node.size)
    total_sectors = cursor

    iso_path_l = _path_table(directories, False, False)
    iso_path_m = _path_table(directories, False, True)
    joliet_path_l = _path_table(directories, True, False)
    joliet_path_m = _path_table(directories, True, True)

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.truncate(total_sectors * SECTOR_SIZE)
            primary = _volume_descriptor(
                descriptor_type=1,
                volume_label=volume_label,
                total_sectors=total_sectors,
                path_table_size=len(iso_path_l),
                path_table_l_extent=iso_l_extent,
                path_table_m_extent=iso_m_extent,
                root_extent=root.iso_extent,
                root_size=root.iso_dir_size,
                timestamp=timestamp,
                joliet=False,
            )
            supplementary = _volume_descriptor(
                descriptor_type=2,
                volume_label=volume_label,
                total_sectors=total_sectors,
                path_table_size=len(joliet_path_l),
                path_table_l_extent=joliet_l_extent,
                path_table_m_extent=joliet_m_extent,
                root_extent=root.joliet_extent,
                root_size=root.joliet_dir_size,
                timestamp=timestamp,
                joliet=True,
            )
            _write_sector_data(handle, 16, primary)
            if not boot_nodes:
                _write_sector_data(handle, 17, supplementary)
                _write_sector_data(handle, 18, _terminator())
            else:
                assert boot_catalog_extent is not None
                _write_sector_data(handle, 17, _boot_record(boot_catalog_extent))
                _write_sector_data(handle, 18, supplementary)
                _write_sector_data(handle, 19, _terminator())
                _write_sector_data(
                    handle,
                    boot_catalog_extent,
                    _boot_catalog(
                        images=[
                            (platform, node.file_extent, node.size)
                            for platform, node in boot_nodes
                        ],
                    ),
                )
            _write_sector_data(handle, iso_l_extent, iso_path_l)
            _write_sector_data(handle, iso_m_extent, iso_path_m)
            _write_sector_data(handle, joliet_l_extent, joliet_path_l)
            _write_sector_data(handle, joliet_m_extent, joliet_path_m)
            for directory in directories:
                _write_sector_data(handle, directory.iso_extent, _directory_bytes(directory, False, timestamp))
                _write_sector_data(handle, directory.joliet_extent, _directory_bytes(directory, True, timestamp))
            for file_node in files:
                _copy_file(handle, file_node)
            handle.flush()
            os.fsync(handle.fileno())

        _verify_image(
            temporary,
            total_sectors,
            boot_images=[
                (platform, node.file_extent, node.size)
                for platform, node in boot_nodes
            ],
            boot_catalog_extent=boot_catalog_extent,
        )
        digest = hashlib.sha256()
        with temporary.open("rb") as built:
            for chunk in iter(lambda: built.read(1024 * 1024), b""):
                digest.update(chunk)
        os.replace(temporary, output)
        temporary = None
        return digest.hexdigest()
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", required=True, type=Path, help="Input directory")
    parser.add_argument("--output", required=True, type=Path, help="Output .iso path")
    parser.add_argument("--volume-label", default="NODETRACE_IR")
    parser.add_argument(
        "--boot-image",
        help="Path inside staging to an El Torito no-emulation boot image",
    )
    parser.add_argument(
        "--boot-platform",
        choices=("bios", "efi"),
        help="El Torito platform for legacy --boot-image",
    )
    parser.add_argument(
        "--bios-boot-image",
        help="Path inside staging to the BIOS no-emulation image",
    )
    parser.add_argument(
        "--efi-boot-image",
        help="Path inside staging to the UEFI FAT system-partition image",
    )
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", DEFAULT_SOURCE_DATE_EPOCH)),
        help="UTC timestamp embedded in all ISO records (default: 2000-01-01)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_args(argv)
    try:
        digest = build_iso(
            arguments.staging,
            arguments.output,
            volume_label=arguments.volume_label,
            source_date_epoch=arguments.source_date_epoch,
            boot_image=arguments.boot_image,
            boot_platform=arguments.boot_platform,
            bios_boot_image=arguments.bios_boot_image,
            efi_boot_image=arguments.efi_boot_image,
        )
    except (IsoBuildError, OSError) as exc:
        raise SystemExit(f"ISO build failed: {exc}") from exc
    print(f"ISO: {arguments.output.resolve()}")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
