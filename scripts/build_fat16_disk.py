#!/usr/bin/env python3
"""Build and inspect deterministic MBR-partitioned FAT16 disk images.

The builder intentionally implements only the small, auditable FAT16 surface
needed by the disposable WinPE VM probe.  It does not invoke host formatting
tools and never opens a physical disk: ``build`` refuses non-file output paths
and creates a new regular image from supplied files/directories.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import struct
import sys
from typing import Iterable, Mapping


SECTOR_SIZE = 512
PARTITION_START_LBA = 2048
ROOT_ENTRY_COUNT = 512
FAT_COUNT = 2
RESERVED_SECTORS = 1
FAT16_MIN_CLUSTERS = 4085
FAT16_MAX_CLUSTERS = 65524
END_OF_CHAIN = 0xFFFF


class Fat16Error(ValueError):
    """Raised when an image request or FAT structure is invalid."""


@dataclass
class Node:
    name: str
    is_dir: bool
    content: bytes = b""
    children: dict[str, "Node"] = field(default_factory=dict)
    parent: "Node | None" = None
    short_name: bytes = b""
    clusters: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class Layout:
    image_sectors: int
    partition_sectors: int
    sectors_per_cluster: int
    fat_sectors: int
    root_dir_sectors: int
    data_start_sector: int
    cluster_count: int

    @property
    def cluster_size(self) -> int:
        return self.sectors_per_cluster * SECTOR_SIZE


def _normalise_image_path(value: str) -> PurePosixPath:
    value = value.replace("\\", "/")
    path = PurePosixPath(value)
    if not value or value.startswith("/") or path.is_absolute():
        raise Fat16Error(f"image path must be relative: {value!r}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise Fat16Error(f"image path contains an unsafe component: {value!r}")
    if any("\x00" in part for part in path.parts):
        raise Fat16Error("image paths cannot contain NUL characters")
    return path


def _normalise_label(label: str) -> bytes:
    cleaned = "".join(character if 32 <= ord(character) < 127 else "_" for character in label.upper())
    cleaned = re.sub(r'["*+,./:;<=>?\\\[\]|]', "_", cleaned).strip()
    if not cleaned:
        raise Fat16Error("volume label cannot be empty")
    return cleaned[:11].ljust(11).encode("ascii")


def _parse_file_spec(spec: str) -> tuple[Path, PurePosixPath]:
    if "=" not in spec:
        raise Fat16Error("--file must be SOURCE=IMAGE/PATH")
    source_text, destination_text = spec.split("=", 1)
    source = Path(source_text).expanduser().resolve()
    if not source.is_file():
        raise Fat16Error(f"source file was not found: {source}")
    return source, _normalise_image_path(destination_text)


def _build_tree(files: Mapping[PurePosixPath, bytes], directories: Iterable[PurePosixPath]) -> Node:
    root = Node(name="", is_dir=True)

    def ensure_directory(path: PurePosixPath) -> Node:
        current = root
        for part in path.parts:
            key = part.casefold()
            existing = current.children.get(key)
            if existing is None:
                existing = Node(name=part, is_dir=True, parent=current)
                current.children[key] = existing
            elif not existing.is_dir:
                raise Fat16Error(f"path collides with a file: {path}")
            current = existing
        return current

    for directory in sorted(directories, key=lambda item: item.as_posix().casefold()):
        ensure_directory(directory)
    for path, content in sorted(files.items(), key=lambda item: item[0].as_posix().casefold()):
        parent = ensure_directory(PurePosixPath(*path.parts[:-1]))
        key = path.name.casefold()
        if key in parent.children:
            raise Fat16Error(f"duplicate or colliding image path: {path}")
        parent.children[key] = Node(name=path.name, is_dir=False, content=content, parent=parent)
    return root


_SHORT_INVALID = re.compile(r'[^A-Z0-9!#$%&\'()\-@^_`{}~]')


def _split_name(name: str) -> tuple[str, str]:
    if name in (".", ".."):
        return name, ""
    if "." in name and not name.startswith("."):
        stem, extension = name.rsplit(".", 1)
    else:
        stem, extension = name, ""
    return stem, extension


def _short_component(value: str) -> str:
    ascii_value = value.upper().encode("ascii", "replace").decode("ascii")
    return _SHORT_INVALID.sub("_", ascii_value).replace(" ", "")


def _assign_short_names(directory: Node) -> None:
    used: set[bytes] = set()
    for child in sorted(directory.children.values(), key=lambda item: (item.name.casefold(), item.name)):
        stem, extension = _split_name(child.name)
        stem_clean = _short_component(stem)
        extension_clean = _short_component(extension)
        direct = (stem_clean[:8].ljust(8) + extension_clean[:3].ljust(3)).encode("ascii")
        direct_round_trip = stem_clean and len(stem_clean) <= 8 and len(extension_clean) <= 3
        if direct_round_trip and direct not in used:
            short = direct
        else:
            prefix = (stem_clean or "FILE")[:6]
            short = b""
            for number in range(1, 1_000_000):
                tail = f"~{number}"
                candidate_stem = (prefix[: 8 - len(tail)] + tail).ljust(8)
                candidate = (candidate_stem + extension_clean[:3].ljust(3)).encode("ascii")
                if candidate not in used:
                    short = candidate
                    break
            if not short:
                raise Fat16Error(f"could not assign an 8.3 alias for {child.name!r}")
        child.short_name = short
        used.add(short)
        if child.is_dir:
            _assign_short_names(child)


def _display_short_name(short: bytes) -> str:
    stem = short[:8].decode("ascii").rstrip()
    extension = short[8:11].decode("ascii").rstrip()
    return stem if not extension else f"{stem}.{extension}"


def _needs_lfn(node: Node) -> bool:
    return node.name != _display_short_name(node.short_name)


def _utf16_units(value: str) -> list[int]:
    encoded = value.encode("utf-16le")
    return list(struct.unpack(f"<{len(encoded) // 2}H", encoded))


def _lfn_entry_count(node: Node) -> int:
    if not _needs_lfn(node):
        return 0
    return math.ceil((len(_utf16_units(node.name)) + 1) / 13)


def _directory_entry_count(directory: Node) -> int:
    count = 1 if directory.parent is None else 2  # root volume label, or . and ..
    for child in directory.children.values():
        count += 1 + _lfn_entry_count(child)
    return count + 1  # explicit end marker


def _choose_layout(size_mib: int) -> Layout:
    if size_mib < 4 or size_mib > 2048:
        raise Fat16Error("FAT16 image size must be between 4 and 2048 MiB")
    image_sectors = size_mib * 1024 * 1024 // SECTOR_SIZE
    partition_sectors = image_sectors - PARTITION_START_LBA
    if partition_sectors <= 0:
        raise Fat16Error("image is too small for the aligned MBR partition")
    root_dir_sectors = math.ceil(ROOT_ENTRY_COUNT * 32 / SECTOR_SIZE)

    for sectors_per_cluster in (1, 2, 4, 8, 16, 32, 64, 128):
        fat_sectors = 1
        for _ in range(32):
            data_sectors = partition_sectors - RESERVED_SECTORS - FAT_COUNT * fat_sectors - root_dir_sectors
            cluster_count = data_sectors // sectors_per_cluster
            next_fat_sectors = math.ceil((cluster_count + 2) * 2 / SECTOR_SIZE)
            if next_fat_sectors == fat_sectors:
                break
            fat_sectors = next_fat_sectors
        data_sectors = partition_sectors - RESERVED_SECTORS - FAT_COUNT * fat_sectors - root_dir_sectors
        cluster_count = data_sectors // sectors_per_cluster
        if FAT16_MIN_CLUSTERS <= cluster_count <= FAT16_MAX_CLUSTERS:
            data_start_sector = RESERVED_SECTORS + FAT_COUNT * fat_sectors + root_dir_sectors
            return Layout(
                image_sectors=image_sectors,
                partition_sectors=partition_sectors,
                sectors_per_cluster=sectors_per_cluster,
                fat_sectors=fat_sectors,
                root_dir_sectors=root_dir_sectors,
                data_start_sector=data_start_sector,
                cluster_count=cluster_count,
            )
    raise Fat16Error("requested size cannot be represented as FAT16")


def _iter_nodes(root: Node) -> Iterable[Node]:
    for child in sorted(root.children.values(), key=lambda item: (item.name.casefold(), item.name)):
        yield child
        if child.is_dir:
            yield from _iter_nodes(child)


def _allocate_clusters(root: Node, layout: Layout) -> list[int]:
    next_cluster = 2
    fat = [0] * (layout.cluster_count + 2)
    fat[0] = 0xFFF8
    fat[1] = END_OF_CHAIN

    def allocate(node: Node, byte_count: int) -> None:
        nonlocal next_cluster
        count = math.ceil(byte_count / layout.cluster_size) if byte_count else 0
        if next_cluster + count > len(fat):
            raise Fat16Error("files do not fit in the requested FAT16 image")
        node.clusters = list(range(next_cluster, next_cluster + count))
        next_cluster += count
        for index, cluster in enumerate(node.clusters):
            fat[cluster] = node.clusters[index + 1] if index + 1 < len(node.clusters) else END_OF_CHAIN

    for node in _iter_nodes(root):
        if node.is_dir:
            allocate(node, _directory_entry_count(node) * 32)
        else:
            allocate(node, len(node.content))
    return fat


def _lfn_checksum(short_name: bytes) -> int:
    checksum = 0
    for value in short_name:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + value
        checksum &= 0xFF
    return checksum


def _pack_lfn_entries(node: Node) -> list[bytes]:
    if not _needs_lfn(node):
        return []
    units = _utf16_units(node.name) + [0x0000]
    while len(units) % 13:
        units.append(0xFFFF)
    chunks = [units[index : index + 13] for index in range(0, len(units), 13)]
    checksum = _lfn_checksum(node.short_name)
    entries: list[bytes] = []
    for ordinal in range(len(chunks), 0, -1):
        sequence = ordinal | (0x40 if ordinal == len(chunks) else 0)
        chunk = chunks[ordinal - 1]
        entry = bytearray(32)
        entry[0] = sequence
        entry[1:11] = struct.pack("<5H", *chunk[:5])
        entry[11] = 0x0F
        entry[12] = 0
        entry[13] = checksum
        entry[14:26] = struct.pack("<6H", *chunk[5:11])
        entry[26:28] = b"\x00\x00"
        entry[28:32] = struct.pack("<2H", *chunk[11:13])
        entries.append(bytes(entry))
    return entries


def _pack_short_entry(short_name: bytes, *, is_dir: bool, first_cluster: int, size: int) -> bytes:
    entry = bytearray(32)
    entry[:11] = short_name
    entry[11] = 0x10 if is_dir else 0x20
    struct.pack_into("<H", entry, 26, first_cluster)
    struct.pack_into("<I", entry, 28, size)
    return bytes(entry)


def _pack_directory(directory: Node, layout: Layout, volume_label: bytes | None = None) -> bytes:
    entries: list[bytes] = []
    if directory.parent is None:
        if volume_label is None or len(volume_label) != 11:
            raise Fat16Error("the root directory requires an 11-byte volume label")
        label_entry = bytearray(32)
        label_entry[:11] = volume_label
        label_entry[11] = 0x08
        entries.append(bytes(label_entry))
    else:
        entries.append(_pack_short_entry(b".          ", is_dir=True, first_cluster=directory.clusters[0], size=0))
        parent_cluster = 0 if directory.parent.parent is None else directory.parent.clusters[0]
        entries.append(_pack_short_entry(b"..         ", is_dir=True, first_cluster=parent_cluster, size=0))
    for child in sorted(directory.children.values(), key=lambda item: (item.name.casefold(), item.name)):
        entries.extend(_pack_lfn_entries(child))
        first_cluster = child.clusters[0] if child.clusters else 0
        entries.append(
            _pack_short_entry(
                child.short_name,
                is_dir=child.is_dir,
                first_cluster=first_cluster,
                size=0 if child.is_dir else len(child.content),
            )
        )
    entries.append(bytes(32))
    payload = b"".join(entries)
    capacity = ROOT_ENTRY_COUNT * 32 if directory.parent is None else len(directory.clusters) * layout.cluster_size
    if len(payload) > capacity:
        raise Fat16Error(f"directory is too large: {directory.name or '/'}")
    return payload.ljust(capacity, b"\x00")


def _cluster_offset(layout: Layout, cluster: int) -> int:
    partition_offset = PARTITION_START_LBA * SECTOR_SIZE
    relative_sector = layout.data_start_sector + (cluster - 2) * layout.sectors_per_cluster
    return partition_offset + relative_sector * SECTOR_SIZE


def _write_chain(image: bytearray, layout: Layout, clusters: list[int], payload: bytes) -> None:
    for index, cluster in enumerate(clusters):
        chunk = payload[index * layout.cluster_size : (index + 1) * layout.cluster_size]
        offset = _cluster_offset(layout, cluster)
        image[offset : offset + len(chunk)] = chunk


def build_image(
    output: Path,
    *,
    files: Mapping[PurePosixPath, bytes],
    directories: Iterable[PurePosixPath] = (),
    volume_label: str,
    size_mib: int = 16,
) -> dict[str, object]:
    """Create a deterministic MBR + FAT16 raw disk image."""

    output = output.resolve()
    if output.exists():
        raise Fat16Error(f"refusing to overwrite existing output: {output}")
    if not output.parent.is_dir():
        raise Fat16Error(f"output parent directory does not exist: {output.parent}")

    normalised_files = {_normalise_image_path(path.as_posix()): bytes(content) for path, content in files.items()}
    normalised_directories = [_normalise_image_path(path.as_posix()) for path in directories]
    root = _build_tree(normalised_files, normalised_directories)
    _assign_short_names(root)
    layout = _choose_layout(size_mib)
    fat = _allocate_clusters(root, layout)
    label_bytes = _normalise_label(volume_label)

    seed = hashlib.sha256()
    seed.update(label_bytes)
    seed.update(struct.pack("<I", size_mib))
    for path, content in sorted(normalised_files.items(), key=lambda item: item[0].as_posix().casefold()):
        seed.update(path.as_posix().encode("utf-8"))
        seed.update(b"\x00")
        seed.update(content)
    serial = struct.unpack("<I", seed.digest()[:4])[0]

    image = bytearray(layout.image_sectors * SECTOR_SIZE)

    # MBR with one LBA-addressed FAT16 partition. CHS fields are saturated;
    # modern firmware and VirtualBox use the exact LBA fields.
    partition_entry = bytearray(16)
    partition_entry[0] = 0x00
    partition_entry[1:4] = b"\xFE\xFF\xFF"
    partition_entry[4] = 0x0E
    partition_entry[5:8] = b"\xFE\xFF\xFF"
    struct.pack_into("<II", partition_entry, 8, PARTITION_START_LBA, layout.partition_sectors)
    image[446:462] = partition_entry
    image[510:512] = b"\x55\xAA"

    boot = bytearray(SECTOR_SIZE)
    boot[0:3] = b"\xEB\x3C\x90"
    boot[3:11] = b"NODETRCE"
    struct.pack_into("<H", boot, 11, SECTOR_SIZE)
    boot[13] = layout.sectors_per_cluster
    struct.pack_into("<H", boot, 14, RESERVED_SECTORS)
    boot[16] = FAT_COUNT
    struct.pack_into("<H", boot, 17, ROOT_ENTRY_COUNT)
    if layout.partition_sectors <= 0xFFFF:
        struct.pack_into("<H", boot, 19, layout.partition_sectors)
        struct.pack_into("<I", boot, 32, 0)
    else:
        struct.pack_into("<H", boot, 19, 0)
        struct.pack_into("<I", boot, 32, layout.partition_sectors)
    boot[21] = 0xF8
    struct.pack_into("<H", boot, 22, layout.fat_sectors)
    struct.pack_into("<H", boot, 24, 63)
    struct.pack_into("<H", boot, 26, 255)
    struct.pack_into("<I", boot, 28, PARTITION_START_LBA)
    boot[36] = 0x80
    boot[38] = 0x29
    struct.pack_into("<I", boot, 39, serial)
    boot[43:54] = label_bytes
    boot[54:62] = b"FAT16   "
    boot[510:512] = b"\x55\xAA"
    partition_offset = PARTITION_START_LBA * SECTOR_SIZE
    image[partition_offset : partition_offset + SECTOR_SIZE] = boot

    fat_payload = b"".join(struct.pack("<H", value) for value in fat)
    fat_payload = fat_payload.ljust(layout.fat_sectors * SECTOR_SIZE, b"\x00")
    fat1_offset = partition_offset + RESERVED_SECTORS * SECTOR_SIZE
    for fat_index in range(FAT_COUNT):
        start = fat1_offset + fat_index * layout.fat_sectors * SECTOR_SIZE
        image[start : start + len(fat_payload)] = fat_payload

    root_offset = fat1_offset + FAT_COUNT * layout.fat_sectors * SECTOR_SIZE
    root_payload = _pack_directory(root, layout, label_bytes)
    image[root_offset : root_offset + len(root_payload)] = root_payload

    for node in _iter_nodes(root):
        if node.is_dir:
            payload = _pack_directory(node, layout)
        else:
            payload = node.content
        _write_chain(image, layout, node.clusters, payload)

    output.write_bytes(image)
    digest = hashlib.sha256(image).hexdigest()
    return {
        "schema": "nodetrace-ir/fat16-image/v1",
        "path": str(output),
        "size": len(image),
        "sha256": digest,
        "volume_label": label_bytes.decode("ascii").rstrip(),
        "volume_serial": f"{serial:08x}",
        "partition_start_lba": PARTITION_START_LBA,
        "partition_sectors": layout.partition_sectors,
        "sectors_per_cluster": layout.sectors_per_cluster,
        "cluster_count": layout.cluster_count,
        "files": [path.as_posix() for path in sorted(normalised_files, key=lambda item: item.as_posix().casefold())],
    }


@dataclass(frozen=True)
class ParsedVolume:
    image: bytes
    partition_offset: int
    sectors_per_cluster: int
    fat_offset: int
    root_offset: int
    root_size: int
    data_offset: int
    cluster_size: int
    fat: tuple[int, ...]
    volume_label: str


def _parse_volume(image_path: Path) -> ParsedVolume:
    image = image_path.read_bytes()
    if len(image) < (PARTITION_START_LBA + 1) * SECTOR_SIZE or image[510:512] != b"\x55\xAA":
        raise Fat16Error("image does not contain a valid MBR signature")
    partition_type = image[450]
    partition_lba, partition_sectors = struct.unpack_from("<II", image, 454)
    if partition_type not in (0x04, 0x06, 0x0E) or partition_lba == 0:
        raise Fat16Error("first MBR partition is not FAT16")
    if (partition_lba + partition_sectors) * SECTOR_SIZE > len(image):
        raise Fat16Error("partition extends beyond image")
    partition_offset = partition_lba * SECTOR_SIZE
    boot = image[partition_offset : partition_offset + SECTOR_SIZE]
    if boot[510:512] != b"\x55\xAA" or boot[54:62] != b"FAT16   ":
        raise Fat16Error("partition boot sector is not FAT16")
    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    if bytes_per_sector != SECTOR_SIZE:
        raise Fat16Error("only 512-byte FAT16 sectors are supported")
    sectors_per_cluster = boot[13]
    reserved = struct.unpack_from("<H", boot, 14)[0]
    fat_count = boot[16]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    fat_sectors = struct.unpack_from("<H", boot, 22)[0]
    root_size = math.ceil(root_entries * 32 / SECTOR_SIZE) * SECTOR_SIZE
    fat_offset = partition_offset + reserved * SECTOR_SIZE
    root_offset = fat_offset + fat_count * fat_sectors * SECTOR_SIZE
    data_offset = root_offset + root_size
    fat_bytes = image[fat_offset : fat_offset + fat_sectors * SECTOR_SIZE]
    fat = struct.unpack(f"<{len(fat_bytes) // 2}H", fat_bytes)
    return ParsedVolume(
        image=image,
        partition_offset=partition_offset,
        sectors_per_cluster=sectors_per_cluster,
        fat_offset=fat_offset,
        root_offset=root_offset,
        root_size=root_size,
        data_offset=data_offset,
        cluster_size=sectors_per_cluster * SECTOR_SIZE,
        fat=fat,
        volume_label=boot[43:54].decode("ascii", "replace").rstrip(),
    )


def _read_chain(volume: ParsedVolume, first_cluster: int, size: int | None = None) -> bytes:
    if first_cluster == 0:
        return b""
    chunks: list[bytes] = []
    seen: set[int] = set()
    cluster = first_cluster
    while 2 <= cluster < 0xFFF8:
        if cluster in seen or cluster >= len(volume.fat):
            raise Fat16Error("invalid or cyclic FAT cluster chain")
        seen.add(cluster)
        offset = volume.data_offset + (cluster - 2) * volume.cluster_size
        chunks.append(volume.image[offset : offset + volume.cluster_size])
        cluster = volume.fat[cluster]
    payload = b"".join(chunks)
    return payload if size is None else payload[:size]


def _decode_short_name(entry: bytes) -> str:
    stem = entry[:8].decode("ascii", "replace").rstrip()
    extension = entry[8:11].decode("ascii", "replace").rstrip()
    return stem if not extension else f"{stem}.{extension}"


def _decode_lfn_entry(entry: bytes) -> tuple[int, list[int], int]:
    sequence = entry[0]
    units = list(struct.unpack("<5H", entry[1:11]))
    units.extend(struct.unpack("<6H", entry[14:26]))
    units.extend(struct.unpack("<2H", entry[28:32]))
    return sequence, units, entry[13]


def _directory_items(payload: bytes) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    pending: list[tuple[int, list[int], int]] = []
    for offset in range(0, len(payload), 32):
        entry = payload[offset : offset + 32]
        if len(entry) < 32 or entry[0] == 0x00:
            break
        if entry[0] == 0xE5:
            pending.clear()
            continue
        if entry[11] == 0x0F:
            pending.append(_decode_lfn_entry(entry))
            continue
        if entry[11] & 0x08:
            pending.clear()
            continue
        short_name = bytes(entry[:11])
        name = _decode_short_name(entry)
        if pending:
            checksum = _lfn_checksum(short_name)
            if all(item[2] == checksum for item in pending):
                units: list[int] = []
                for _sequence, chunk, _checksum in sorted(pending, key=lambda item: item[0] & 0x1F):
                    units.extend(chunk)
                trimmed: list[int] = []
                for unit in units:
                    if unit == 0x0000:
                        break
                    if unit != 0xFFFF:
                        trimmed.append(unit)
                if trimmed:
                    name = struct.pack(f"<{len(trimmed)}H", *trimmed).decode("utf-16le", "replace")
            pending.clear()
        result.append((name, entry))
    return result


def inspect_image(image_path: Path) -> dict[str, object]:
    """Return a recursive listing suitable for deterministic VM assertions."""

    image_path = image_path.resolve()
    if not image_path.is_file():
        raise Fat16Error(f"image was not found: {image_path}")
    volume = _parse_volume(image_path)
    entries: list[dict[str, object]] = []
    visited: set[int] = set()

    def walk(payload: bytes, parent_path: str) -> None:
        for name, entry in _directory_items(payload):
            if name in (".", ".."):
                continue
            attributes = entry[11]
            is_dir = bool(attributes & 0x10)
            first_cluster = struct.unpack_from("<H", entry, 26)[0]
            size = struct.unpack_from("<I", entry, 28)[0]
            path = name if not parent_path else f"{parent_path}/{name}"
            item: dict[str, object] = {
                "path": path,
                "type": "directory" if is_dir else "file",
                "first_cluster": first_cluster,
                "size": 0 if is_dir else size,
            }
            if is_dir:
                entries.append(item)
                if first_cluster:
                    if first_cluster in visited:
                        raise Fat16Error("directory cluster was referenced more than once")
                    visited.add(first_cluster)
                    walk(_read_chain(volume, first_cluster), path)
            else:
                content = _read_chain(volume, first_cluster, size)
                item["sha256"] = hashlib.sha256(content).hexdigest()
                entries.append(item)

    root_payload = volume.image[volume.root_offset : volume.root_offset + volume.root_size]
    walk(root_payload, "")
    return {
        "schema": "nodetrace-ir/fat16-inspection/v1",
        "image": str(image_path),
        "size": image_path.stat().st_size,
        "sha256": hashlib.sha256(volume.image).hexdigest(),
        "volume_label": volume.volume_label,
        "entries": entries,
    }


def _write_json(path: Path | None, payload: object) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(rendered)
        return
    if path.exists():
        raise Fat16Error(f"refusing to overwrite JSON output: {path}")
    path.write_text(rendered, encoding="utf-8")


def _build_command(args: argparse.Namespace) -> int:
    files: dict[PurePosixPath, bytes] = {}
    for spec in args.file:
        source, destination = _parse_file_spec(spec)
        if destination in files:
            raise Fat16Error(f"duplicate destination: {destination}")
        files[destination] = source.read_bytes()
    directories = [_normalise_image_path(value) for value in args.directory]
    result = build_image(
        Path(args.output),
        files=files,
        directories=directories,
        volume_label=args.label,
        size_mib=args.size_mib,
    )
    _write_json(Path(args.json_output).resolve() if args.json_output else None, result)
    return 0


def _inspect_command(args: argparse.Namespace) -> int:
    result = inspect_image(Path(args.image))
    _write_json(Path(args.json_output).resolve() if args.json_output else None, result)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="create a new deterministic raw image")
    build.add_argument("--output", required=True)
    build.add_argument("--label", required=True)
    build.add_argument("--size-mib", type=int, default=16)
    build.add_argument("--file", action="append", default=[], metavar="SOURCE=IMAGE/PATH")
    build.add_argument("--directory", action="append", default=[], metavar="IMAGE/PATH")
    build.add_argument("--json-output")
    build.set_defaults(func=_build_command)

    inspect = commands.add_parser("inspect", help="recursively list an MBR/FAT16 image")
    inspect.add_argument("--image", required=True)
    inspect.add_argument("--json-output")
    inspect.set_defaults(func=_inspect_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return int(args.func(args))
    except (Fat16Error, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
