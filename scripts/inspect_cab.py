#!/usr/bin/env python3
"""Inspect a Microsoft CAB directory without extracting payload data.

This deliberately supports only the unspanned CAB subset used by the pinned
Windows PE 10.1.19041 payloads.  It is a build-time diagnostic helper, not a
general CAB implementation.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


FLAG_PREV_CABINET = 0x0001
FLAG_NEXT_CABINET = 0x0002
FLAG_RESERVE_PRESENT = 0x0004


def _cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated CAB string")
    return data[offset:end].decode("utf-8", errors="strict"), end + 1


def inspect_cab(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) < 40 or data[:4] != b"MSCF":
        raise ValueError("not a CAB file")

    cabinet_size, file_table_offset = struct.unpack_from("<II", data, 8)[0], struct.unpack_from("<I", data, 16)[0]
    minor, major, folder_count, file_count, flags = struct.unpack_from("<BBHHH", data, 24)
    if flags & (FLAG_PREV_CABINET | FLAG_NEXT_CABINET):
        raise ValueError("spanned CAB sets are not supported")

    cursor = 36
    folder_reserve = data_reserve = 0
    if flags & FLAG_RESERVE_PRESENT:
        header_reserve, folder_reserve, data_reserve = struct.unpack_from("<HBB", data, cursor)
        cursor += 4 + header_reserve

    folders: list[dict[str, int]] = []
    for index in range(folder_count):
        start, block_count, compression = struct.unpack_from("<IHH", data, cursor)
        cursor += 8 + folder_reserve
        folders.append(
            {
                "index": index,
                "compressed_start": start,
                "block_count": block_count,
                "compression": compression,
            }
        )

    files: list[dict[str, object]] = []
    cursor = file_table_offset
    for _ in range(file_count):
        size, uncompressed_offset, folder_index, date, time, attributes = struct.unpack_from(
            "<IIHHHH", data, cursor
        )
        cursor += 16
        name, cursor = _cstring(data, cursor)
        files.append(
            {
                "name": name,
                "size": size,
                "uncompressed_offset": uncompressed_offset,
                "folder_index": folder_index,
                "date": date,
                "time": time,
                "attributes": attributes,
            }
        )

    for index, folder in enumerate(folders):
        next_start = folders[index + 1]["compressed_start"] if index + 1 < len(folders) else cabinet_size
        folder["compressed_end"] = next_start
        folder["compressed_size"] = next_start - folder["compressed_start"]

    return {
        "path": str(path),
        "header_bytes_available": len(data),
        "cabinet_size": cabinet_size,
        "version": f"{major}.{minor}",
        "flags": flags,
        "folder_reserve": folder_reserve,
        "data_reserve": data_reserve,
        "folders": folders,
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cab")
    parser.add_argument("--names-from", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = inspect_cab(Path(args.cab))
    if args.names_from:
        wanted = {
            line.strip().casefold()
            for line in args.names_from.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()
        }
        selected = [entry for entry in result["files"] if str(entry["name"]).casefold() in wanted]
        result["selected_files"] = selected
        result["selected_folders"] = sorted({int(entry["folder_index"]) for entry in selected})
        missing = sorted(wanted - {str(entry["name"]).casefold() for entry in selected})
        result["missing_names"] = missing

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"CAB {result['version']} size={result['cabinet_size']} folders={len(result['folders'])} files={len(result['files'])}")
        if args.names_from:
            print(f"selected files={len(result['selected_files'])} folders={result['selected_folders']}")
            for index in result["selected_folders"]:
                folder = result["folders"][index]
                print(
                    f"folder {index}: {folder['compressed_start']}..{folder['compressed_end'] - 1} "
                    f"({folder['compressed_size']} bytes, compression=0x{folder['compression']:04x})"
                )
            if result["missing_names"]:
                print("missing: " + ", ".join(result["missing_names"]))
                return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
