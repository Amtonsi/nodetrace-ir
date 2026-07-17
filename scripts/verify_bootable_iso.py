#!/usr/bin/env python3
"""Verify ISO-9660 and El Torito boot metadata without mounting the image.

The verifier is deliberately read-only and uses only the Python standard
library.  A successful result means that the image contains a structurally
valid El Torito catalog with at least one usable x86 BIOS or UEFI boot entry;
it does not claim that the referenced operating system will finish booting on
particular hardware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable


SECTOR_SIZE = 2048
VOLUME_DESCRIPTOR_START = 16
MAX_VOLUME_DESCRIPTORS = 256
MAX_CATALOG_ENTRIES = 4096
MAX_EXTENSION_ENTRIES = 32
MAX_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_RECORDS = 200_000
MAX_DIRECTORY_DEPTH = 64
EL_TORITO_SYSTEM_ID = b"EL TORITO SPECIFICATION"
UDF_NSR02_VRS_IDENTIFIERS = (b"BEA01", b"NSR02", b"TEA01")

PLATFORMS = {
    0x00: "BIOS",
    0x01: "PowerPC",
    0x02: "Mac",
    0xEF: "UEFI",
}
MEDIA_TYPES = {
    0: "no-emulation",
    1: "1.2M-floppy",
    2: "1.44M-floppy",
    3: "2.88M-floppy",
    4: "hard-disk",
}


class IsoVerificationError(RuntimeError):
    """Raised for malformed or unsafe-to-parse ISO structures."""


@dataclass(frozen=True)
class VolumeDescriptors:
    primary: bytes
    joliet: bytes | None
    boot_record: bytes
    terminator_sector: int


class ImageReader:
    """Small bounded random-access reader for an already opened image."""

    def __init__(self, handle: BinaryIO, size: int) -> None:
        self.handle = handle
        self.size = size

    def read_at(self, offset: int, length: int, *, what: str) -> bytes:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise IsoVerificationError(
                f"{what} is outside the image (offset={offset}, length={length}, size={self.size})"
            )
        self.handle.seek(offset)
        data = self.handle.read(length)
        if len(data) != length:
            raise IsoVerificationError(f"Could not read the complete {what}")
        return data

    def sector(self, lba: int, *, what: str) -> bytes:
        if lba < 0:
            raise IsoVerificationError(f"{what} uses a negative sector number")
        return self.read_at(lba * SECTOR_SIZE, SECTOR_SIZE, what=what)


def _sha256(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _both_endian_u16(data: bytes, offset: int, field: str) -> int:
    little = struct.unpack_from("<H", data, offset)[0]
    big = struct.unpack_from(">H", data, offset + 2)[0]
    if little != big:
        raise IsoVerificationError(f"ISO descriptor has mismatched endian values for {field}")
    return little


def _both_endian_u32(data: bytes, offset: int, field: str) -> int:
    little = struct.unpack_from("<I", data, offset)[0]
    big = struct.unpack_from(">I", data, offset + 4)[0]
    if little != big:
        raise IsoVerificationError(f"ISO descriptor has mismatched endian values for {field}")
    return little


def _read_volume_descriptors(reader: ImageReader) -> VolumeDescriptors:
    primary: bytes | None = None
    joliet: bytes | None = None
    boot_records: list[bytes] = []
    terminator_sector: int | None = None

    for index in range(MAX_VOLUME_DESCRIPTORS):
        sector_number = VOLUME_DESCRIPTOR_START + index
        descriptor = reader.sector(sector_number, what=f"volume descriptor at sector {sector_number}")
        if descriptor[1:6] != b"CD001" or descriptor[6] != 1:
            raise IsoVerificationError(
                f"Invalid ISO-9660 volume descriptor signature at sector {sector_number}"
            )
        descriptor_type = descriptor[0]
        if descriptor_type == 1 and primary is None:
            primary = descriptor
        elif descriptor_type == 2 and descriptor[88:91] in {b"%/@", b"%/C", b"%/E"}:
            if joliet is None:
                joliet = descriptor
        elif descriptor_type == 0:
            system_id = descriptor[7:39].rstrip(b" \x00")
            if system_id == EL_TORITO_SYSTEM_ID:
                boot_records.append(descriptor)
        elif descriptor_type == 255:
            terminator_sector = sector_number
            break

    if terminator_sector is None:
        raise IsoVerificationError("ISO volume descriptor terminator was not found")
    if primary is None:
        raise IsoVerificationError("ISO primary volume descriptor was not found")
    if not boot_records:
        raise IsoVerificationError("El Torito boot record was not found; this is not a bootable ISO")
    if len(boot_records) != 1:
        raise IsoVerificationError("Multiple El Torito boot records make the boot catalog ambiguous")
    return VolumeDescriptors(primary, joliet, boot_records[0], terminator_sector)


def _read_udf_nsr02_vrs(
    reader: ImageReader, terminator_sector: int
) -> dict[str, object]:
    start_sector = terminator_sector + 1
    descriptors: list[dict[str, object]] = []
    for offset, expected_identifier in enumerate(UDF_NSR02_VRS_IDENTIFIERS):
        sector_number = start_sector + offset
        descriptor = reader.sector(
            sector_number,
            what=(
                "UDF Volume Recognition Sequence descriptor "
                f"{expected_identifier.decode('ascii')} at sector {sector_number}"
            ),
        )
        actual_identifier = descriptor[1:6].decode("ascii", "replace")
        if (
            descriptor[0] != 0
            or descriptor[1:6] != expected_identifier
            or descriptor[6] != 1
        ):
            raise IsoVerificationError(
                "UDF Volume Recognition Sequence requires "
                f"{expected_identifier.decode('ascii')} at sector {sector_number}; "
                f"found type 0x{descriptor[0]:02X}, "
                f"identifier {actual_identifier!r}, version {descriptor[6]}"
            )
        descriptors.append(
            {
                "identifier": expected_identifier.decode("ascii"),
                "sector": sector_number,
            }
        )
    return {"start_sector": start_sector, "descriptors": descriptors}

def _validation_entry(raw: bytes) -> dict[str, object]:
    if len(raw) != 32:
        raise IsoVerificationError("El Torito validation entry is truncated")
    if raw[0] != 0x01:
        raise IsoVerificationError("El Torito catalog has an invalid validation header ID")
    if raw[30:32] != b"\x55\xaa":
        raise IsoVerificationError("El Torito validation entry has an invalid 0x55AA signature")
    checksum = sum(struct.unpack("<16H", raw)) & 0xFFFF
    if checksum:
        raise IsoVerificationError("El Torito validation entry checksum is invalid")
    platform_id = raw[1]
    return {
        "header_id": raw[0],
        "platform_id": platform_id,
        "platform": PLATFORMS.get(platform_id, f"unknown-0x{platform_id:02X}"),
        "identifier": raw[4:28].rstrip(b" \x00").decode("ascii", "replace"),
        "checksum_valid": True,
        "signature": "55AA",
    }


def _boot_entry(
    raw: bytes,
    *,
    index: int,
    platform_id: int,
    source: str,
    image_size: int,
    declared_sectors: int,
) -> dict[str, object]:
    if len(raw) != 32:
        raise IsoVerificationError("El Torito boot entry is truncated")

    indicator = raw[0]
    bootable = indicator == 0x88
    media_code = raw[1] & 0x0F
    has_extensions = bool(raw[1] & 0x20)
    sector_count = struct.unpack_from("<H", raw, 6)[0]
    load_rba = struct.unpack_from("<I", raw, 8)[0]
    platform = PLATFORMS.get(platform_id, f"unknown-0x{platform_id:02X}")
    errors: list[str] = []

    if indicator not in {0x00, 0x88}:
        errors.append(f"invalid boot indicator 0x{indicator:02X}")
    if media_code not in MEDIA_TYPES:
        errors.append(f"invalid boot media type {media_code}")
    if bootable:
        if sector_count == 0:
            errors.append("boot sector count is zero")
        if load_rba == 0:
            errors.append("boot image LBA is zero")
        elif load_rba >= declared_sectors:
            errors.append("boot image LBA is outside the declared ISO volume")
        load_size = sector_count * 512
        image_offset = load_rba * SECTOR_SIZE
        if load_size and (image_offset > image_size or load_size > image_size - image_offset):
            errors.append("loaded boot image range is outside the ISO file")
        declared_size = declared_sectors * SECTOR_SIZE
        if load_size and (
            image_offset > declared_size or load_size > declared_size - image_offset
        ):
            errors.append("loaded boot image range is outside the declared ISO volume")
        if platform_id == 0xEF and media_code != 0:
            errors.append("UEFI boot entries must use no-emulation media")

    recognized = platform_id in {0x00, 0xEF}
    return {
        "index": index,
        "source": source,
        "platform_id": platform_id,
        "platform": platform,
        "boot_indicator": f"0x{indicator:02X}",
        "bootable": bootable,
        "recognized": recognized,
        "media_type": media_code,
        "media": MEDIA_TYPES.get(media_code, "invalid"),
        "load_segment": struct.unpack_from("<H", raw, 2)[0],
        "system_type": raw[4],
        "sector_count_512": sector_count,
        "load_size_bytes": sector_count * 512,
        "load_rba": load_rba,
        "image_offset": load_rba * SECTOR_SIZE,
        "has_extensions": has_extensions,
        "valid": bootable and recognized and not errors,
        "errors": errors,
    }


def _catalog_record(reader: ImageReader, catalog_offset: int, entry_number: int) -> bytes:
    if entry_number < 0 or entry_number >= MAX_CATALOG_ENTRIES:
        raise IsoVerificationError("El Torito catalog exceeds the safe entry limit")
    return reader.read_at(
        catalog_offset + entry_number * 32,
        32,
        what=f"El Torito catalog entry {entry_number}",
    )


def _consume_extensions(
    reader: ImageReader,
    catalog_offset: int,
    cursor: int,
    entry: dict[str, object],
) -> tuple[int, list[dict[str, object]]]:
    extensions: list[dict[str, object]] = []
    if not entry["has_extensions"]:
        return cursor, extensions
    for _ in range(MAX_EXTENSION_ENTRIES):
        raw = _catalog_record(reader, catalog_offset, cursor)
        if raw[0] != 0x44:
            raise IsoVerificationError(
                f"El Torito entry {entry['index']} declares an extension but none follows"
            )
        extensions.append(
            {
                "entry": cursor,
                "final": not bool(raw[1] & 0x20),
                "vendor_data_hex": raw[2:].hex(),
            }
        )
        cursor += 1
        if not raw[1] & 0x20:
            entry["extensions"] = extensions
            return cursor, extensions
    raise IsoVerificationError("El Torito extension chain exceeds the safe entry limit")


def _read_boot_catalog(
    reader: ImageReader,
    *,
    catalog_lba: int,
    declared_sectors: int,
) -> tuple[dict[str, object], list[dict[str, object]], int]:
    if catalog_lba == 0 or catalog_lba >= declared_sectors:
        raise IsoVerificationError("El Torito boot catalog LBA is outside the declared ISO volume")
    catalog_offset = catalog_lba * SECTOR_SIZE
    declared_size = declared_sectors * SECTOR_SIZE
    if catalog_offset > declared_size - 64:
        raise IsoVerificationError("El Torito boot catalog header crosses the declared ISO volume")
    catalog_reader = ImageReader(reader.handle, declared_size)
    validation_raw = _catalog_record(catalog_reader, catalog_offset, 0)
    validation = _validation_entry(validation_raw)
    default_raw = _catalog_record(catalog_reader, catalog_offset, 1)
    entries: list[dict[str, object]] = []
    default_entry = _boot_entry(
        default_raw,
        index=1,
        platform_id=int(validation["platform_id"]),
        source="default",
        image_size=reader.size,
        declared_sectors=declared_sectors,
    )
    entries.append(default_entry)
    cursor = 2
    cursor, _ = _consume_extensions(catalog_reader, catalog_offset, cursor, default_entry)

    saw_final_header = False
    while cursor < MAX_CATALOG_ENTRIES:
        raw = _catalog_record(catalog_reader, catalog_offset, cursor)
        if raw[0] == 0x00:
            break
        if raw[0] not in {0x90, 0x91}:
            raise IsoVerificationError(
                f"Unexpected El Torito catalog record 0x{raw[0]:02X} at entry {cursor}"
            )
        final_header = raw[0] == 0x91
        platform_id = raw[1]
        section_count = struct.unpack_from("<H", raw, 2)[0]
        if section_count == 0:
            raise IsoVerificationError(f"El Torito section at entry {cursor} is empty")
        section_name = raw[4:32].rstrip(b" \x00").decode("ascii", "replace")
        header_entry = cursor
        cursor += 1
        for section_index in range(section_count):
            entry_raw = _catalog_record(catalog_reader, catalog_offset, cursor)
            if entry_raw[0] not in {0x00, 0x88}:
                raise IsoVerificationError(
                    f"Invalid El Torito section boot entry at catalog entry {cursor}"
                )
            entry = _boot_entry(
                entry_raw,
                index=cursor,
                platform_id=platform_id,
                source=f"section:{header_entry}:{section_index}",
                image_size=reader.size,
                declared_sectors=declared_sectors,
            )
            entry["section_identifier"] = section_name
            entries.append(entry)
            cursor += 1
            cursor, _ = _consume_extensions(catalog_reader, catalog_offset, cursor, entry)
        if final_header:
            saw_final_header = True
            break

    # A final header is only mandatory when the catalog actually uses sections.
    if any(str(entry["source"]).startswith("section:") for entry in entries) and not saw_final_header:
        raise IsoVerificationError("El Torito section catalog has no final section header")
    return validation, entries, cursor * 32


def _directory_record(raw: bytes, *, namespace: str) -> dict[str, object]:
    if len(raw) < 34:
        raise IsoVerificationError(f"{namespace} directory record is too short")
    identifier_length = raw[32]
    if 33 + identifier_length > len(raw):
        raise IsoVerificationError(f"{namespace} directory identifier is truncated")
    identifier_raw = raw[33 : 33 + identifier_length]
    if identifier_raw in {b"\x00", b"\x01"}:
        name = "." if identifier_raw == b"\x00" else ".."
    elif namespace == "joliet":
        if len(identifier_raw) % 2:
            raise IsoVerificationError("Joliet directory identifier has an odd byte length")
        try:
            name = identifier_raw.decode("utf-16-be")
        except UnicodeDecodeError as exc:
            raise IsoVerificationError("Joliet directory identifier is not valid UCS-2") from exc
    else:
        try:
            name = identifier_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise IsoVerificationError("ISO-9660 directory identifier is not ASCII") from exc
    if ";" in name:
        stem, separator, version = name.rpartition(";")
        if separator and version.isdigit():
            name = stem[:-1] if stem.endswith(".") else stem
    return {
        "name": name,
        "extent": _both_endian_u32(raw, 2, f"{namespace} directory extent"),
        "extended_attribute_sectors": raw[1],
        "size": _both_endian_u32(raw, 10, f"{namespace} directory size"),
        "is_directory": bool(raw[25] & 0x02),
    }


def _root_record(descriptor: bytes, *, namespace: str) -> dict[str, object]:
    length = descriptor[156]
    if length < 34 or 156 + length > len(descriptor):
        raise IsoVerificationError(f"{namespace} root directory record is invalid")
    record = _directory_record(descriptor[156 : 156 + length], namespace=namespace)
    if not record["is_directory"]:
        raise IsoVerificationError(f"{namespace} root directory record is not a directory")
    return record


def _enumerate_paths(
    reader: ImageReader,
    descriptor: bytes,
    *,
    namespace: str,
    block_size: int,
    volume_size: int,
) -> dict[str, str]:
    paths: dict[str, str] = {}
    root = _root_record(descriptor, namespace=namespace)
    stack: list[tuple[dict[str, object], str, int]] = [(root, "", 0)]
    visited: set[tuple[int, int]] = set()
    directory_bytes = 0
    record_count = 0

    while stack:
        directory, prefix, depth = stack.pop()
        if depth > MAX_DIRECTORY_DEPTH:
            raise IsoVerificationError(f"{namespace} directory tree exceeds the safe depth limit")
        extent = int(directory["extent"]) + int(directory["extended_attribute_sectors"])
        length = int(directory["size"])
        key = (extent, length)
        if key in visited:
            continue
        visited.add(key)
        directory_bytes += length
        if directory_bytes > MAX_DIRECTORY_BYTES:
            raise IsoVerificationError(f"{namespace} directories exceed the safe byte limit")
        offset = extent * block_size
        if offset > volume_size or length > volume_size - offset:
            raise IsoVerificationError(f"{namespace} directory extent is outside the ISO volume")
        data = reader.read_at(offset, length, what=f"{namespace} directory extent")

        cursor = 0
        while cursor < len(data):
            record_length = data[cursor]
            if record_length == 0:
                cursor = ((cursor // block_size) + 1) * block_size
                continue
            if record_length < 34 or cursor + record_length > len(data):
                raise IsoVerificationError(f"{namespace} directory record is truncated")
            if cursor % block_size + record_length > block_size:
                raise IsoVerificationError(f"{namespace} directory record crosses a logical block")
            record_count += 1
            if record_count > MAX_DIRECTORY_RECORDS:
                raise IsoVerificationError(f"{namespace} directories exceed the safe record limit")
            record = _directory_record(
                data[cursor : cursor + record_length], namespace=namespace
            )
            cursor += record_length
            name = str(record["name"])
            if name in {".", ".."}:
                continue
            if not name or "/" in name or "\\" in name or "\x00" in name:
                raise IsoVerificationError(f"{namespace} contains an unsafe path component")
            path = f"{prefix}/{name}" if prefix else name
            paths.setdefault(path.casefold(), path)

            child_extent = int(record["extent"]) + int(record["extended_attribute_sectors"])
            child_size = int(record["size"])
            child_offset = child_extent * block_size
            if child_offset > volume_size or child_size > volume_size - child_offset:
                raise IsoVerificationError(f"{namespace} path {path!r} points outside the ISO volume")
            if record["is_directory"]:
                stack.append((record, path, depth + 1))
    return paths


def _normalize_expected_path(value: str) -> str:
    normalized = value.replace("\\", "/").strip("/")
    components = normalized.split("/") if normalized else []
    if not components or any(component in {"", ".", ".."} for component in components):
        raise IsoVerificationError(f"Invalid expected ISO path: {value!r}")
    if any("\x00" in component for component in components):
        raise IsoVerificationError(f"Invalid expected ISO path: {value!r}")
    return "/".join(components)


def _expected_path_results(
    reader: ImageReader,
    descriptors: VolumeDescriptors,
    expected_paths: Iterable[str],
    *,
    block_size: int,
    volume_size: int,
) -> tuple[list[dict[str, object]], list[str]]:
    requested = list(expected_paths)
    if not requested:
        return [], []
    namespaces = {
        "iso9660": _enumerate_paths(
            reader,
            descriptors.primary,
            namespace="iso9660",
            block_size=block_size,
            volume_size=volume_size,
        )
    }
    if descriptors.joliet is not None:
        namespaces["joliet"] = _enumerate_paths(
            reader,
            descriptors.joliet,
            namespace="joliet",
            block_size=block_size,
            volume_size=volume_size,
        )

    results: list[dict[str, object]] = []
    errors: list[str] = []
    for value in requested:
        try:
            normalized = _normalize_expected_path(value)
        except IsoVerificationError as exc:
            results.append(
                {"requested": value, "normalized": None, "found": False, "namespaces": []}
            )
            errors.append(str(exc))
            continue
        matches = [name for name, paths in namespaces.items() if normalized.casefold() in paths]
        results.append(
            {
                "requested": value,
                "normalized": normalized,
                "found": bool(matches),
                "namespaces": matches,
            }
        )
        if not matches:
            errors.append(f"Expected ISO path not found: {normalized}")
    return results, errors


def verify_iso(
    image: Path | str,
    expected_paths: Iterable[str] = (),
    require_udf_nsr02: bool = False,
) -> dict[str, object]:
    """Return a JSON-serializable verification report for *image*."""

    source = Path(image)
    report: dict[str, object] = {
        "schema_version": 1,
        "image": {
            "path": str(source.resolve(strict=False)),
            "size": None,
            "sha256": None,
        },
        "iso9660": None,
        "udf_nsr02": None,
        "el_torito": None,
        "boot_modes": [],
        "expected_paths": [],
        "valid": False,
        "errors": [],
    }
    errors = report["errors"]
    assert isinstance(errors, list)

    try:
        resolved = source.resolve(strict=True)
        if not resolved.is_file():
            raise IsoVerificationError("Image path is not a regular file")
        with resolved.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            digest = _sha256(handle)
            image_info = report["image"]
            assert isinstance(image_info, dict)
            image_info.update(path=str(resolved), size=size, sha256=digest)
            if size < (VOLUME_DESCRIPTOR_START + 1) * SECTOR_SIZE:
                raise IsoVerificationError("File is too small to be an ISO-9660 image")
            if size % SECTOR_SIZE:
                raise IsoVerificationError("ISO file size is not a multiple of 2048 bytes")
            reader = ImageReader(handle, size)
            descriptors = _read_volume_descriptors(reader)
            block_size = _both_endian_u16(
                descriptors.primary, 128, "logical block size"
            )
            if block_size != SECTOR_SIZE:
                raise IsoVerificationError(
                    f"Unsupported ISO logical block size {block_size}; expected {SECTOR_SIZE}"
                )
            declared_sectors = _both_endian_u32(
                descriptors.primary, 80, "volume space size"
            )
            if declared_sectors == 0:
                raise IsoVerificationError("ISO declares an empty volume")
            volume_size = declared_sectors * block_size
            if volume_size > size:
                raise IsoVerificationError("ISO declared volume size exceeds the image file")
            volume_id = descriptors.primary[40:72].decode("ascii", "replace").rstrip(" \x00")
            report["iso9660"] = {
                "volume_id": volume_id,
                "logical_block_size": block_size,
                "declared_sectors": declared_sectors,
                "declared_size": volume_size,
                "has_joliet": descriptors.joliet is not None,
                "descriptor_terminator_sector": descriptors.terminator_sector,
            }

            catalog_lba = struct.unpack_from("<I", descriptors.boot_record, 71)[0]
            validation, entries, inspected_bytes = _read_boot_catalog(
                reader,
                catalog_lba=catalog_lba,
                declared_sectors=declared_sectors,
            )
            modes: list[str] = []
            for mode in ("BIOS", "UEFI"):
                if any(entry["valid"] and entry["platform"] == mode for entry in entries):
                    modes.append(mode)
            for entry in entries:
                entry_errors = entry["errors"]
                if entry["bootable"] and entry_errors:
                    errors.extend(
                        f"El Torito entry {entry['index']}: {message}"
                        for message in entry_errors
                    )
            if not modes:
                errors.append("No valid bootable BIOS or UEFI entry was found")
            report["boot_modes"] = modes
            report["el_torito"] = {
                "boot_system_identifier": EL_TORITO_SYSTEM_ID.decode("ascii"),
                "catalog_lba": catalog_lba,
                "catalog_offset": catalog_lba * SECTOR_SIZE,
                "catalog_bytes_inspected": inspected_bytes,
                "validation": validation,
                "entries": entries,
            }

            path_results, path_errors = _expected_path_results(
                reader,
                descriptors,
                expected_paths,
                block_size=block_size,
                volume_size=volume_size,
            )
            report["expected_paths"] = path_results
            errors.extend(path_errors)
            if require_udf_nsr02:
                report["udf_nsr02"] = _read_udf_nsr02_vrs(
                    reader, descriptors.terminator_sector
                )
    except (IsoVerificationError, OSError) as exc:
        errors.append(str(exc))

    report["valid"] = not errors
    return report


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="ISO image to inspect")
    parser.add_argument(
        "--expect-path",
        action="append",
        default=[],
        metavar="PATH",
        help="Require a case-insensitive ISO-9660 or Joliet path (repeatable)",
    )
    parser.add_argument(
        "--require-udf-nsr02",
        action="store_true",
        help=(
            "Require consecutive BEA01, NSR02, and TEA01 descriptors immediately "
            "after the ISO descriptor terminator"
        ),
    )
    parser.add_argument(
        "--compact", action="store_true", help="Emit compact JSON instead of indented JSON"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_args(argv)
    report = verify_iso(
        arguments.image,
        arguments.expect_path,
        require_udf_nsr02=arguments.require_udf_nsr02,
    )
    print(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=None if arguments.compact else 2,
            sort_keys=True,
        )
    )
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
