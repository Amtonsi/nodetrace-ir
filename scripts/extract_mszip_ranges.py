#!/usr/bin/env python3
"""Extract selected files from downloaded MSZIP CAB folder ranges.

The helper is intentionally narrow: it supports the unspanned, reserve-aware
MSZIP CAB layout used by the pinned Windows PE 10.1.19041 payloads.  A small
CAB header range supplies the signed MSI member directory, while each
``--folder-range`` file begins exactly at the corresponding CFFOLDER data
offset.  No synthetic CAB and no third-party extraction library are needed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import zlib
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from inspect_cab import inspect_cab


MSZIP = 0x0001


def _cab_checksum(data: bytes) -> int:
    """Return the CFDATA XOR checksum described by MS-CAB."""

    value = 0
    whole = len(data) & ~3
    for offset in range(0, whole, 4):
        value ^= struct.unpack_from("<I", data, offset)[0]
    remainder = data[whole:]
    if remainder:
        tail = 0
        # MS-CAB packs the 1-3 trailing bytes in network-style order even
        # though complete DWORDs above are little-endian.
        for byte in remainder:
            tail = (tail << 8) | byte
        value ^= tail
    return value & 0xFFFFFFFF


def _read_exact(stream: BinaryIO, size: int, label: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ValueError(f"truncated {label}: got {len(data)} bytes, expected {size}")
    return data


def _parse_assignment(value: str, label: str) -> tuple[str, str]:
    key, separator, target = value.partition("=")
    if not separator or not key or not target:
        raise argparse.ArgumentTypeError(f"{label} must use KEY=VALUE syntax")
    return key, target


def _safe_output_path(root: Path, relative: str) -> Path:
    posix = PurePosixPath(relative.replace("\\", "/"))
    if posix.is_absolute() or not posix.parts or any(part in {"", ".", ".."} for part in posix.parts):
        raise ValueError(f"unsafe output path: {relative!r}")
    root_resolved = root.resolve()
    candidate = root_resolved.joinpath(*posix.parts).resolve()
    if os.path.commonpath((str(root_resolved), str(candidate))) != str(root_resolved):
        raise ValueError(f"output path escapes root: {relative!r}")
    return candidate


class _FolderSource:
    def __init__(self, path: Path, start: int, expected_size: int) -> None:
        self.path = path
        self.start = start
        self.expected_size = expected_size
        self.stream: BinaryIO | None = None

    def __enter__(self) -> BinaryIO:
        size = self.path.stat().st_size
        if self.start < 0 or self.start + self.expected_size > size:
            raise ValueError(
                f"folder source {self.path} cannot provide offset {self.start} "
                f"plus {self.expected_size} bytes (file size {size})"
            )
        self.stream = self.path.open("rb")
        self.stream.seek(self.start)
        return self.stream

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.stream is not None:
            self.stream.close()


def _extract_folder(
    *,
    source: _FolderSource,
    folder: dict[str, int],
    entries: list[dict[str, object]],
    outputs: dict[str, Path],
    data_reserve: int,
) -> list[dict[str, object]]:
    compression = int(folder["compression"])
    if compression & 0x000F != MSZIP or compression & 0xFFF0:
        raise ValueError(f"folder {folder['index']} uses unsupported compression 0x{compression:04x}")

    records: list[dict[str, object]] = []
    partials: dict[str, Path] = {}
    written = {str(entry["name"]): 0 for entry in entries}
    hashes = {str(entry["name"]): hashlib.sha256() for entry in entries}

    with ExitStack() as stack:
        stream = stack.enter_context(source)
        handles: dict[str, BinaryIO] = {}
        for entry in entries:
            name = str(entry["name"])
            destination = outputs[name]
            destination.parent.mkdir(parents=True, exist_ok=True)
            partial = destination.with_name(destination.name + ".partial")
            if partial.exists():
                partial.unlink()
            partials[name] = partial
            handles[name] = stack.enter_context(partial.open("xb"))

        dictionary = b""
        uncompressed_position = 0
        source_start = stream.tell()
        for block_index in range(int(folder["block_count"])):
            block_header = _read_exact(stream, 8, f"CFDATA header {block_index}")
            checksum, compressed_size, uncompressed_size = struct.unpack("<IHH", block_header)
            reserve = _read_exact(stream, data_reserve, f"CFDATA reserve {block_index}")
            compressed = _read_exact(stream, compressed_size, f"CFDATA payload {block_index}")
            if checksum:
                calculated = _cab_checksum(block_header[4:] + reserve + compressed)
                if calculated != checksum:
                    raise ValueError(
                        f"CFDATA checksum mismatch in folder {folder['index']} block {block_index}: "
                        f"0x{calculated:08x}, expected 0x{checksum:08x}"
                    )
            if not compressed.startswith(b"CK"):
                raise ValueError(f"folder {folder['index']} block {block_index} lacks the MSZIP CK marker")

            if dictionary:
                inflater = zlib.decompressobj(wbits=-zlib.MAX_WBITS, zdict=dictionary)
            else:
                inflater = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
            uncompressed = inflater.decompress(compressed[2:]) + inflater.flush()
            if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
                raise ValueError(f"invalid deflate stream in folder {folder['index']} block {block_index}")
            if len(uncompressed) != uncompressed_size:
                raise ValueError(
                    f"folder {folder['index']} block {block_index} expanded to {len(uncompressed)} bytes, "
                    f"expected {uncompressed_size}"
                )

            block_start = uncompressed_position
            block_end = block_start + len(uncompressed)
            for entry in entries:
                name = str(entry["name"])
                file_start = int(entry["uncompressed_offset"])
                file_end = file_start + int(entry["size"])
                overlap_start = max(block_start, file_start)
                overlap_end = min(block_end, file_end)
                if overlap_start < overlap_end:
                    chunk = uncompressed[overlap_start - block_start : overlap_end - block_start]
                    handles[name].write(chunk)
                    hashes[name].update(chunk)
                    written[name] += len(chunk)

            dictionary = (dictionary + uncompressed)[-32768:]
            uncompressed_position = block_end

        consumed = stream.tell() - source_start
        if consumed != int(folder["compressed_size"]):
            raise ValueError(
                f"folder {folder['index']} consumed {consumed} compressed bytes, "
                f"expected {folder['compressed_size']}"
            )

    for entry in entries:
        name = str(entry["name"])
        expected = int(entry["size"])
        if written[name] != expected:
            raise ValueError(f"member {name} extracted {written[name]} bytes, expected {expected}")
        destination = outputs[name]
        partial = partials[name]
        if destination.exists():
            raise FileExistsError(f"refusing to overwrite existing output: {destination}")
        partial.replace(destination)
        records.append(
            {
                "cab_member": name,
                "path": destination.as_posix(),
                "size": expected,
                "sha256": hashes[name].hexdigest(),
                "folder_index": int(folder["index"]),
            }
        )
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("header", type=Path, help="CAB header range containing all CFFOLDER/CFFILE records")
    parser.add_argument("--full-cab", type=Path, help="read folder data from a complete CAB")
    parser.add_argument(
        "--folder-range",
        action="append",
        default=[],
        metavar="INDEX=PATH",
        help="file beginning exactly at the selected folder compressed_start offset",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--extract", action="append", default=[], metavar="CAB_MEMBER")
    parser.add_argument(
        "--map",
        action="append",
        default=[],
        metavar="CAB_MEMBER=RELATIVE_PATH",
        help="extract and rename a member below --output-dir",
    )
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()

    metadata = inspect_cab(args.header)
    folders = {int(folder["index"]): folder for folder in metadata["folders"]}
    file_entries = {str(entry["name"]): entry for entry in metadata["files"]}

    range_paths: dict[int, Path] = {}
    for assignment in args.folder_range:
        index_text, path_text = _parse_assignment(assignment, "--folder-range")
        try:
            index = int(index_text, 10)
        except ValueError as error:
            raise SystemExit(f"invalid folder index: {index_text!r}") from error
        if index in range_paths:
            raise SystemExit(f"duplicate folder range {index}")
        range_paths[index] = Path(path_text)

    output_root = args.output_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, Path] = {}
    for name in args.extract:
        outputs[name] = _safe_output_path(output_root, name)
    for assignment in args.map:
        name, relative = _parse_assignment(assignment, "--map")
        if name in outputs:
            raise SystemExit(f"duplicate output mapping for {name}")
        outputs[name] = _safe_output_path(output_root, relative)
    if not outputs:
        raise SystemExit("at least one --extract or --map is required")
    if len({str(path).casefold() for path in outputs.values()}) != len(outputs):
        raise SystemExit("two CAB members map to the same output path")

    selected_by_folder: dict[int, list[dict[str, object]]] = {}
    for name in outputs:
        if name not in file_entries:
            raise SystemExit(f"CAB member is absent from the header: {name}")
        entry = file_entries[name]
        folder_index = int(entry["folder_index"])
        if folder_index not in folders:
            raise SystemExit(f"CAB member {name} references unsupported folder index {folder_index}")
        selected_by_folder.setdefault(folder_index, []).append(entry)

    records: list[dict[str, object]] = []
    for folder_index, entries in sorted(selected_by_folder.items()):
        folder = folders[folder_index]
        expected_size = int(folder["compressed_size"])
        if folder_index in range_paths:
            range_path = range_paths[folder_index]
            if range_path.stat().st_size != expected_size:
                raise SystemExit(
                    f"folder range {folder_index} has {range_path.stat().st_size} bytes, expected {expected_size}"
                )
            source = _FolderSource(range_path, 0, expected_size)
        elif args.full_cab:
            source = _FolderSource(args.full_cab, int(folder["compressed_start"]), expected_size)
        else:
            raise SystemExit(f"no --folder-range {folder_index}=PATH and no --full-cab were supplied")
        records.extend(
            _extract_folder(
                source=source,
                folder=folder,
                entries=entries,
                outputs=outputs,
                data_reserve=int(metadata["data_reserve"]),
            )
        )

    manifest = {
        "schema": "nodetrace-mszip-range-extraction/v1",
        "cabinet_size": int(metadata["cabinet_size"]),
        "files": records,
    }
    manifest_path = args.manifest or output_root / "mszip-extraction-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
