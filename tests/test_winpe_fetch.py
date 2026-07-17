from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
from types import SimpleNamespace
import zlib

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT_ROOT / "scripts"
INSPECTOR_PATH = SCRIPTS / "inspect_cab.py"
EXTRACTOR_PATH = SCRIPTS / "extract_mszip_ranges.py"
RESUMER_PATH = SCRIPTS / "resume_http_ranges.py"
PREPARER_PATH = SCRIPTS / "prepare_winpe_2004_x86_portable.ps1"


def _load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


inspect_cab_module = _load_script("inspect_cab", INSPECTOR_PATH)
extract_mszip = _load_script("nodetrace_extract_mszip", EXTRACTOR_PATH)
resume_ranges = _load_script("nodetrace_resume_ranges", RESUMER_PATH)


def _cab_checksum_reference(data: bytes) -> int:
    result = 0
    while len(data) >= 4:
        result ^= int.from_bytes(data[:4], "little")
        data = data[4:]
    if data:
        result ^= int.from_bytes(data, "big")
    return result & 0xFFFFFFFF


def _build_mszip_cab(files: list[tuple[str, bytes]]) -> tuple[bytes, int]:
    payload = b"".join(content for _, content in files)
    blocks: list[bytes] = []
    dictionary = b""
    for offset in range(0, len(payload), 32768):
        raw = payload[offset : offset + 32768]
        if dictionary:
            compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS, zdict=dictionary)
        else:
            compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
        compressed = b"CK" + compressor.compress(raw) + compressor.flush()
        reserve = b"\xA5\x5A"
        sizes = struct.pack("<HH", len(compressed), len(raw))
        checksum = _cab_checksum_reference(sizes + reserve + compressed)
        blocks.append(struct.pack("<I", checksum) + sizes + reserve + compressed)
        dictionary = (dictionary + raw)[-32768:]

    file_table = bytearray()
    uncompressed_offset = 0
    for name, content in files:
        encoded = name.encode("utf-8") + b"\0"
        file_table += struct.pack(
            "<IIHHHH",
            len(content),
            uncompressed_offset,
            0,
            0,
            0,
            0x20,
        )
        file_table += encoded
        uncompressed_offset += len(content)

    # CFHEADER + reserve sizes + two header-reserve bytes + one CFFOLDER
    # with one folder-reserve byte, followed by the CFFILE table.
    file_table_offset = 36 + 4 + 2 + 8 + 1
    data_start = file_table_offset + len(file_table)
    data = b"".join(blocks)
    cabinet_size = data_start + len(data)
    header = bytearray()
    header += b"MSCF"
    header += struct.pack("<I", 0)
    header += struct.pack("<I", cabinet_size)
    header += struct.pack("<I", 0)
    header += struct.pack("<I", file_table_offset)
    header += struct.pack("<I", 0)
    header += struct.pack("<BBHHHHH", 3, 1, 1, len(files), 0x0004, 0, 0)
    header += struct.pack("<HBB", 2, 1, 2)
    header += b"HR"
    header += struct.pack("<IHH", data_start, len(blocks), 0x0001)
    header += b"F"
    assert len(header) == file_table_offset
    cabinet = bytes(header) + bytes(file_table) + data
    assert len(cabinet) == cabinet_size
    return cabinet, data_start


@pytest.fixture()
def synthetic_cab(tmp_path: Path) -> dict[str, object]:
    files = [
        ("alpha.bin", (b"alpha-dictionary-pattern-" * 2100)[:48731]),
        ("beta.bin", (b"alpha-dictionary-pattern-beta-" * 1700)[:42117]),
        ("gamma.txt", ("NodeTrace IR UTF-8 test\n" * 900).encode("utf-8")),
    ]
    cabinet, data_start = _build_mszip_cab(files)
    full = tmp_path / "synthetic.cab"
    header = tmp_path / "header.bin"
    folder_range = tmp_path / "folder-0.range"
    full.write_bytes(cabinet)
    header.write_bytes(cabinet[:data_start])
    folder_range.write_bytes(cabinet[data_start:])
    return {
        "files": dict(files),
        "full": full,
        "header": header,
        "range": folder_range,
        "data_start": data_start,
    }


def test_inspector_and_range_extractor_verify_real_mszip_blocks(
    synthetic_cab: dict[str, object], tmp_path: Path
) -> None:
    full = synthetic_cab["full"]
    header = synthetic_cab["header"]
    folder_range = synthetic_cab["range"]
    expected = synthetic_cab["files"]
    metadata = inspect_cab_module.inspect_cab(full)
    assert metadata["cabinet_size"] == full.stat().st_size
    assert metadata["folder_reserve"] == 1
    assert metadata["data_reserve"] == 2
    assert metadata["folders"] == [
        {
            "index": 0,
            "compressed_start": synthetic_cab["data_start"],
            "block_count": 4,
            "compression": 1,
            "compressed_end": full.stat().st_size,
            "compressed_size": folder_range.stat().st_size,
        }
    ]

    output = tmp_path / "range-output"
    manifest = tmp_path / "range-manifest.json"
    result = subprocess.run(
        [
            sys.executable,
            str(EXTRACTOR_PATH),
            str(header),
            "--folder-range",
            f"0={folder_range}",
            "--output-dir",
            str(output),
            "--map",
            "alpha.bin=Media/alpha.bin",
            "--map",
            "beta.bin=Media/nested/beta.bin",
            "--manifest",
            str(manifest),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (output / "Media" / "alpha.bin").read_bytes() == expected["alpha.bin"]
    assert (output / "Media" / "nested" / "beta.bin").read_bytes() == expected["beta.bin"]
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["schema"] == "nodetrace-mszip-range-extraction/v1"
    by_member = {record["cab_member"]: record for record in payload["files"]}
    assert by_member["alpha.bin"]["sha256"] == hashlib.sha256(expected["alpha.bin"]).hexdigest()
    assert by_member["beta.bin"]["sha256"] == hashlib.sha256(expected["beta.bin"]).hexdigest()

    full_output = tmp_path / "full-output"
    result = subprocess.run(
        [
            sys.executable,
            str(EXTRACTOR_PATH),
            str(header),
            "--full-cab",
            str(full),
            "--output-dir",
            str(full_output),
            "--extract",
            "gamma.txt",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (full_output / "gamma.txt").read_bytes() == expected["gamma.txt"]


def test_range_extractor_rejects_checksum_corruption_and_path_escape(
    synthetic_cab: dict[str, object], tmp_path: Path
) -> None:
    corrupted = tmp_path / "corrupted.range"
    body = bytearray(synthetic_cab["range"].read_bytes())
    body[-7] ^= 0x40
    corrupted.write_bytes(body)
    output = tmp_path / "corrupt-output"
    result = subprocess.run(
        [
            sys.executable,
            str(EXTRACTOR_PATH),
            str(synthetic_cab["header"]),
            "--folder-range",
            f"0={corrupted}",
            "--output-dir",
            str(output),
            "--extract",
            "gamma.txt",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr

    safe_root = tmp_path / "safe-root"
    result = subprocess.run(
        [
            sys.executable,
            str(EXTRACTOR_PATH),
            str(synthetic_cab["header"]),
            "--folder-range",
            f"0={synthetic_cab['range']}",
            "--output-dir",
            str(safe_root),
            "--map",
            "alpha.bin=../escaped.bin",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "unsafe output path" in result.stderr
    assert not (tmp_path / "escaped.bin").exists()


def test_resume_one_appends_only_after_exact_206_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = bytes(range(251)) * 19
    total = len(remote)
    part = tmp_path / "part-00"
    existing = 731
    part.write_bytes(remote[:existing])

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        range_text = command[command.index("--range") + 1]
        request_start, request_end = (int(value) for value in range_text.split("-"))
        output = Path(command[command.index("--output") + 1])
        headers = Path(command[command.index("--dump-header") + 1])
        output.write_bytes(remote[request_start : request_end + 1])
        headers.write_bytes(
            b"HTTP/1.1 200 Connection established\r\n\r\n"
            + b"HTTP/1.1 206 Partial Content\r\n"
            + f"Content-Range: bytes {request_start}-{request_end}/{total}\r\n\r\n".encode()
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(resume_ranges.subprocess, "run", fake_run)
    result = resume_ranges.resume_one(
        index=0,
        part_path=part,
        range_start=0,
        range_end=total - 1,
        total_size=total,
        url="https://download.microsoft.com/payload.bin",
        curl="curl.exe",
        retry=20,
        connect_timeout=30,
    )
    assert result["bytes"] == total
    assert part.read_bytes() == remote
    assert list(tmp_path.glob("part-00.resume-*.download.applied"))

    captured: list[str] = []

    def capture_run(command: list[str], **_: object) -> SimpleNamespace:
        captured.extend(command)
        request_start, request_end = (
            int(value) for value in command[command.index("--range") + 1].split("-")
        )
        Path(command[command.index("--output") + 1]).write_bytes(
            remote[request_start : request_end + 1]
        )
        Path(command[command.index("--dump-header") + 1]).write_text(
            f"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {request_start}-{request_end}/{total}\r\n\r\n",
            encoding="ascii",
        )
        return SimpleNamespace(returncode=0)

    second = tmp_path / "part-01"
    second.write_bytes(remote[:100])
    monkeypatch.setattr(resume_ranges.subprocess, "run", capture_run)
    resume_ranges.resume_one(
        index=1,
        part_path=second,
        range_start=0,
        range_end=total - 1,
        total_size=total,
        url="https://download.microsoft.com/payload.bin",
        curl="curl.exe",
        retry=20,
        connect_timeout=30,
    )
    assert "--retry-all-errors" in captured
    assert captured[captured.index("--retry") + 1] == "20"
    assert captured[captured.index("--connect-timeout") + 1] == "30"


def test_resume_one_commits_independently_verified_small_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = bytes(range(251)) * 17
    part = tmp_path / "part-00"
    ranges: list[tuple[int, int]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        request_start, request_end = (
            int(value) for value in command[command.index("--range") + 1].split("-")
        )
        ranges.append((request_start, request_end))
        Path(command[command.index("--output") + 1]).write_bytes(
            remote[request_start : request_end + 1]
        )
        Path(command[command.index("--dump-header") + 1]).write_text(
            f"HTTP/1.1 206 Partial Content\r\n"
            f"Content-Range: bytes {request_start}-{request_end}/{len(remote)}\r\n\r\n",
            encoding="ascii",
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(resume_ranges.subprocess, "run", fake_run)
    result = resume_ranges.resume_one(
        index=0,
        part_path=part,
        range_start=0,
        range_end=len(remote) - 1,
        total_size=len(remote),
        url="https://download.microsoft.com/payload.bin",
        curl="curl.exe",
        retry=20,
        connect_timeout=30,
        chunk_size=512,
    )
    assert part.read_bytes() == remote
    assert result["bytes"] == len(remote)
    assert ranges[0] == (0, 511)
    assert ranges[-1] == (4096, len(remote) - 1)
    assert len(ranges) == 9
    assert len(result["verified_chunks"]) == 9


def test_resume_header_and_final_digest_fail_closed(tmp_path: Path) -> None:
    bad_headers = tmp_path / "bad.headers"
    bad_headers.write_text(
        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-4/5\r\n\r\n",
        encoding="ascii",
    )
    with pytest.raises(resume_ranges.DownloadError, match="unexpected Content-Range"):
        resume_ranges.validate_headers(bad_headers, 0, 4, 5)

    part_a = tmp_path / "part-a"
    part_b = tmp_path / "part-b"
    part_a.write_bytes(b"abc")
    part_b.write_bytes(b"def")
    output = tmp_path / "payload.bin"
    expected = hashlib.sha1(b"abcdef").hexdigest()
    result = resume_ranges.assemble([part_a, part_b], output, 6, expected)
    assert output.read_bytes() == b"abcdef"
    assert result["sha1"] == expected.upper()

    wrong_output = tmp_path / "wrong.bin"
    with pytest.raises(resume_ranges.DownloadError, match="failed identity"):
        resume_ranges.assemble([part_a, part_b], wrong_output, 6, "0" * 40)
    assert not wrong_output.exists()
    assert (tmp_path / "wrong.bin.assembling").read_bytes() == b"abcdef"


def test_exact_part_partition_matches_pinned_wim_payload() -> None:
    ranges = resume_ranges.part_ranges(199_404_031, 16)
    assert ranges[0] == (0, 12_462_751)
    assert ranges[-1] == (186_941_280, 199_404_030)
    assert sum(end - start + 1 for start, end in ranges) == 199_404_031
    assert resume_ranges.parse_indices("0-3,12-15", 16) == [0, 1, 2, 3, 12, 13, 14, 15]


def test_portable_preparer_pins_wim_cab_with_exact_dual_hashes() -> None:
    script = PREPARER_PATH.read_text(encoding="utf-8")
    sha1 = "10FA653EF230E3CEA8E9C8E8A9DF9CCD412AB7ED"
    sha256 = "BFBEF5062372192C42D3833BE0AB99A9C197B4271D7B47D76F299C57DD6FA071"
    sha1_assertion = (
        'Assert-FileIdentity $wimCab 199404031 "SHA1" $PinnedWimCabSha1'
    )
    sha256_assertion = (
        'Assert-FileIdentity $wimCab 199404031 "SHA256" $PinnedWimCabSha256'
    )
    extraction = script.index(
        'Invoke-PythonChecked "Extracting the pinned x86 boot WIM"'
    )
    manifest = script.index("$manifest = [ordered]@{")

    assert f'$PinnedWimCabSha1 = "{sha1}"' in script
    assert f'$PinnedWimCabSha256 = "{sha256}"' in script
    assert '"690b8ac88bc08254d351654d56805aea.cab" 199404031 "SHA256" `' in script
    assert script.index(sha1_assertion) < extraction
    assert extraction < script.rindex(sha1_assertion) < manifest
    assert extraction < script.index(sha256_assertion) < manifest
    assert "sha1 = $PinnedWimCabSha1" in script
    assert "sha256 = $PinnedWimCabSha256" in script
    assert "$wimCabSha256 = (Get-FileHash" not in script

def test_portable_preparer_pins_embedded_signed_ia32_loader() -> None:
    script = PREPARER_PATH.read_text(encoding="utf-8")
    assert 'source_image_path = "Media/fwfiles/efisys.bin"' in script
    assert 'source_member_path = "EFI/BOOT/BOOTIA32.EFI"' in script
    assert 'path = "Media/EFI/Boot/bootia32.efi"' in script
    assert 'origin_role = "ia32-efi-el-torito-loader"' in script
    assert "size = 1010080L" in script
    assert "BB5B85E5CF1F582CC2A9F269E48EB6BA1B6AC0445006DA911DA981AB87D14F97" in script
    assert 'authenticode = "Valid"' in script
