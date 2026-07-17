#!/usr/bin/env python3
"""Safely extract one file from a FAT12 image without third-party tools."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys

from build_fat12_efi import Fat12BuildError, read_fat12_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("path")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    content = read_fat12_file(args.image, args.path)
    output = args.output.resolve()
    if output.exists():
        raise Fat12BuildError(f"refusing to overwrite existing output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(output.name + ".partial")
    if partial.exists():
        raise Fat12BuildError(f"refusing to overwrite retained partial output: {partial}")
    with partial.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    partial.replace(output)
    print(
        f"{output} size={len(content)} "
        f"sha256={hashlib.sha256(content).hexdigest().upper()}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Fat12BuildError, OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
