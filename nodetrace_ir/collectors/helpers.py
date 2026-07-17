from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import hashlib
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import stat as stat_module
import subprocess
from typing import Any, BinaryIO, Iterator, Mapping
import uuid


@dataclass(frozen=True, slots=True)
class PowerShellResult:
    """Result of a non-interactive, read-only PowerShell query."""

    ok: bool
    data: Any = None
    error: str = ""
    returncode: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""


class UnsafeEvidencePathError(OSError):
    """Raised before a suspect path can escape the local regular-file boundary."""


class EvidenceFileChangedError(OSError):
    """Raised when the opened evidence file changes during acquisition."""


@dataclass(slots=True)
class VerifiedEvidenceFile:
    """One open handle used for metadata, hashing, and the final stability check."""

    path: Path
    stream: BinaryIO
    initial_stat: os.stat_result

    def hashes(self, chunk_size: int = 1024 * 1024) -> dict[str, str]:
        _validate_chunk_size(chunk_size)
        self.stream.seek(0)
        result = _hash_stream(self.stream, chunk_size)
        self.verify_unchanged()
        return result

    def verify_unchanged(self) -> os.stat_result:
        current = os.fstat(self.stream.fileno())
        if _stable_file_state(current) != _stable_file_state(self.initial_stat):
            raise EvidenceFileChangedError(
                "Suspect file identity, size, or timestamps changed while it was being read"
            )
        return current


def is_windows() -> bool:
    return os.name == "nt"


def _windows_directory() -> Path | None:
    if not is_windows():
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
        if 0 < length < len(buffer):
            return Path(buffer.value)
    except (AttributeError, OSError, ValueError):
        pass
    system_root = os.environ.get("SystemRoot")
    return Path(system_root) if system_root else None


def _trusted_powershell_path() -> Path | None:
    """Resolve only the inbox Windows PowerShell host under the Windows tree.

    Searching PATH on an investigated host would let an attacker-controlled
    directory substitute powershell.exe before an elevated collection.
    """
    windows = _windows_directory()
    if windows is None:
        return None
    candidates = [
        windows / "Sysnative" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        windows / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
    ]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve(strict=True)
        except OSError:
            continue
    return None


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def parse(cls, value: str) -> "_GUID":
        parsed = uuid.UUID(value)
        clock = parsed.fields
        data4 = bytes((clock[3], clock[4])) + clock[5].to_bytes(6, "big")
        return cls(clock[0], clock[1], clock[2], (ctypes.c_ubyte * 8)(*data4))


_KNOWN_FOLDER_IDS = {
    "startup": "B97D20BB-F46A-4C97-BA10-5E3608430854",
    "common_startup": "82A5EA35-D9CD-47C5-9629-E15D2F714E6E",
}


def known_folder_path(name: str) -> str:
    """Resolve a Windows Known Folder without trusting inherited shell paths."""
    identifier = _KNOWN_FOLDER_IDS.get(name)
    if not identifier or not is_windows():
        return ""
    pointer = ctypes.c_wchar_p()
    try:
        guid = _GUID.parse(identifier)
        result = ctypes.windll.shell32.SHGetKnownFolderPath(
            ctypes.byref(guid), 0, None, ctypes.byref(pointer)
        )
        if result == 0 and pointer.value:
            return pointer.value
    except (AttributeError, OSError, ValueError):
        pass
    finally:
        try:
            if pointer:
                ctypes.windll.ole32.CoTaskMemFree(pointer)
        except (AttributeError, OSError):
            pass
    if name == "startup" and os.environ.get("APPDATA"):
        return str(Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    if name == "common_startup" and os.environ.get("ProgramData"):
        return str(Path(os.environ["ProgramData"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
    return ""


_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def _safe_evidence_path(path: str | os.PathLike[str]) -> Path:
    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise UnsafeEvidencePathError("Suspect path is empty or contains a NUL character")

    candidate = Path(raw).expanduser()
    if not is_windows():
        absolute = Path(os.path.abspath(candidate))
        _reject_reparse_components(absolute)
        return absolute

    windows_path = str(candidate).replace("/", "\\")
    if windows_path.startswith("\\"):
        raise UnsafeEvidencePathError("UNC, root-relative, and Win32 device paths are not allowed")

    drive, tail = ntpath.splitdrive(windows_path)
    if len(drive) != 2 or drive[1] != ":" or not tail.startswith("\\"):
        raise UnsafeEvidencePathError("Suspect path must be an absolute local drive path")
    if ":" in tail:
        raise UnsafeEvidencePathError("NTFS alternate-data-stream paths are not allowed as case seeds")

    for component in PureWindowsPath(windows_path).parts[1:]:
        device_name = component.rstrip(" .").split(".", 1)[0].upper()
        if device_name in _WINDOWS_RESERVED_NAMES:
            raise UnsafeEvidencePathError(f"Windows device name is not allowed: {component}")

    absolute = Path(ntpath.abspath(windows_path))
    try:
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        drive_type = int(get_drive_type(f"{absolute.drive}\\"))
    except (AttributeError, OSError, ValueError) as exc:
        raise UnsafeEvidencePathError(f"Local volume type could not be verified: {exc}") from exc
    if drive_type in {0, 1, 4}:  # unknown, invalid root, or remote/network volume
        raise UnsafeEvidencePathError("Suspect file must be on a directly attached local volume")

    _reject_reparse_components(absolute)
    return absolute


def _reject_reparse_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            item_stat = current.lstat()
        except OSError:
            raise
        attributes = int(getattr(item_stat, "st_file_attributes", 0))
        if stat_module.S_ISLNK(item_stat.st_mode) or (
            attributes & getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise UnsafeEvidencePathError(f"Reparse points are not allowed in suspect paths: {current}")


def _open_windows_evidence_file(path: Path) -> BinaryIO:
    import msvcrt

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE; deny rename/delete
        None,
        3,  # OPEN_EXISTING
        0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, invalid_handle}:
        raise ctypes.WinError()
    try:
        descriptor = msvcrt.open_osfhandle(
            int(handle), os.O_RDONLY | os.O_BINARY | getattr(os, "O_NOINHERIT", 0)
        )
    except Exception:
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise
    return os.fdopen(descriptor, "rb", closefd=True)


def _opened_windows_path(stream: BinaryIO) -> Path:
    import msvcrt

    handle = msvcrt.get_osfhandle(stream.fileno())
    get_final_path = ctypes.windll.kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    get_final_path.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(get_final_path(ctypes.c_void_p(handle), buffer, len(buffer), 0))
    if length <= 0 or length >= len(buffer):
        raise UnsafeEvidencePathError("The opened suspect file's final path could not be verified")
    value = buffer.value
    if value.casefold().startswith("\\\\?\\unc\\"):
        raise UnsafeEvidencePathError("The opened suspect file resolved to a network path")
    if value.startswith("\\\\?\\"):
        value = value[4:]
    if value.startswith("\\"):
        raise UnsafeEvidencePathError("The opened suspect file resolved outside a local drive")
    return Path(ntpath.normpath(value))


@contextmanager
def open_verified_evidence_file(
    path: str | os.PathLike[str],
) -> Iterator[VerifiedEvidenceFile]:
    """Open one local, non-reparse regular file and fail closed on mutation.

    On Windows the handle is opened without delete sharing and with
    ``FILE_FLAG_OPEN_REPARSE_POINT``. This keeps the path bound while
    path-based read-only metadata is collected, without blocking ordinary
    readers or in-place writers. ``fstat`` detects in-place changes.
    """

    safe_path = _safe_evidence_path(path)
    if is_windows():
        stream = _open_windows_evidence_file(safe_path)
    else:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        stream = os.fdopen(os.open(safe_path, flags), "rb", closefd=True)

    with stream:
        initial_stat = os.fstat(stream.fileno())
        attributes = int(getattr(initial_stat, "st_file_attributes", 0))
        if attributes & getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise UnsafeEvidencePathError("The opened suspect file is a reparse point")
        if not stat_module.S_ISREG(initial_stat.st_mode):
            raise UnsafeEvidencePathError("The suspect path is not a regular file")

        if is_windows():
            opened_path = _opened_windows_path(stream)
            if ntpath.normcase(str(opened_path)) != ntpath.normcase(str(safe_path)):
                raise UnsafeEvidencePathError(
                    f"Suspect path resolved to a different object: {opened_path}"
                )

        verified = VerifiedEvidenceFile(safe_path, stream, initial_stat)
        yield verified
        verified.verify_unchanged()


def _validate_chunk_size(chunk_size: int) -> None:
    if chunk_size < 4096:
        raise ValueError("chunk_size must be at least 4096 bytes")


def _hash_stream(stream: BinaryIO, chunk_size: int) -> dict[str, str]:
    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5(usedforsecurity=False)
    while True:
        block = stream.read(chunk_size)
        if not block:
            break
        sha256_hash.update(block)
        sha1_hash.update(block)
        md5_hash.update(block)
    return {
        "sha256": sha256_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "md5": md5_hash.hexdigest(),
    }


def _stable_file_state(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    modified_ns = getattr(value, "st_mtime_ns", None)
    changed_ns = getattr(value, "st_ctime_ns", None)
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(modified_ns if modified_ns is not None else value.st_mtime * 1_000_000_000),
        int(changed_ns if changed_ns is not None else value.st_ctime * 1_000_000_000),
    )


def hash_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> dict[str, str]:
    """Hash a regular file with one bounded-memory, read-only pass.

    This function never asks the OS to execute the target and never loads it as a
    library.  Opening the file for binary reads is the minimum access required to
    calculate forensic hashes.
    """

    _validate_chunk_size(chunk_size)
    with Path(path).open("rb") as stream:
        return _hash_stream(stream, chunk_size)


def run_powershell_json(
    script: str,
    *,
    timeout: float = 30.0,
    env: Mapping[str, str] | None = None,
) -> PowerShellResult:
    """Run a fixed PowerShell inventory script and parse its UTF-8 JSON output.

    Callers pass untrusted paths through ``env`` and read them with ``$env:...``;
    they are never interpolated into PowerShell source.  ``shell=False``, a
    non-interactive profile-free host and a finite timeout keep collection
    deterministic.  The function captures errors instead of raising them into a
    collector.
    """

    if not is_windows():
        return PowerShellResult(ok=False, error="PowerShell Windows collection is unavailable on this OS")
    if timeout <= 0:
        return PowerShellResult(ok=False, error="PowerShell timeout must be positive")

    executable = _trusted_powershell_path()
    if not executable:
        return PowerShellResult(ok=False, error="Trusted inbox Windows PowerShell executable was not found")

    prelude = """
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
""".strip()
    # Windows PowerShell 5.1 can still encode redirected text with a legacy
    # code page despite OutputEncoding.  Put UTF-8 JSON in an ASCII base64
    # envelope so localized event-log errors survive byte-for-byte.
    wrapped_script = f"""
{prelude}
$__NodeTraceOutput = & {{
{script}
}}
$__NodeTraceText = ($__NodeTraceOutput | Out-String).Trim()
$__NodeTraceBytes = [System.Text.Encoding]::UTF8.GetBytes($__NodeTraceText)
[Convert]::ToBase64String($__NodeTraceBytes)
""".strip()
    windows = _windows_directory()
    if windows is None:
        return PowerShellResult(ok=False, error="Windows directory could not be resolved")
    system32 = windows / "System32"
    module_paths = [
        system32 / "WindowsPowerShell" / "v1.0" / "Modules",
        executable.parent / "Modules",
    ]
    process_env = {
        "SystemRoot": str(windows),
        "WINDIR": str(windows),
        "COMSPEC": str(system32 / "cmd.exe"),
        "PATH": os.pathsep.join((str(system32), str(executable.parent))),
        "PSModulePath": os.pathsep.join(str(path) for path in module_paths),
        "TEMP": os.environ.get("TEMP", str(windows / "Temp")),
        "TMP": os.environ.get("TMP", str(windows / "Temp")),
        "POWERSHELL_TELEMETRY_OPTOUT": "1",
    }
    if env:
        for key, value in env.items():
            normalized_key = str(key).upper()
            if not normalized_key.startswith("NODETRACE_") or not normalized_key.replace("_", "").isalnum():
                return PowerShellResult(ok=False, error=f"Refusing non-NodeTrace environment key: {key}")
            process_env[normalized_key] = str(value)

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            [
                str(executable),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                wrapped_script,
            ],
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=process_env,
            cwd=str(system32),
            stdin=subprocess.DEVNULL,
            creationflags=creationflags,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _coerce_stream(exc.stdout)
        stderr = _coerce_stream(exc.stderr)
        return PowerShellResult(
            ok=False,
            error=f"PowerShell collection timed out after {timeout:g} seconds",
            timed_out=True,
            stdout=stdout,
            stderr=stderr,
        )
    except OSError as exc:
        return PowerShellResult(ok=False, error=f"Unable to start PowerShell: {exc}")

    stdout = completed.stdout.strip().lstrip("\ufeff")
    stderr = completed.stderr.strip()
    if completed.returncode != 0:
        detail = stderr or stdout or f"exit code {completed.returncode}"
        return PowerShellResult(
            ok=False,
            error=f"PowerShell collection failed: {detail}",
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )
    if not stdout:
        return PowerShellResult(
            ok=False,
            error="PowerShell returned no JSON",
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    try:
        # Direct JSON remains accepted for compatibility with pwsh wrappers and
        # makes the helper straightforward to mock in unit tests.
        if stdout[:1] in {"{", "[", '"'}:
            json_text = stdout
        else:
            json_text = base64.b64decode(stdout, validate=True).decode("utf-8")
        data = json.loads(json_text)
    except (binascii.Error, UnicodeDecodeError) as exc:
        return PowerShellResult(
            ok=False,
            error=f"PowerShell returned an invalid UTF-8 JSON envelope: {exc}",
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )
    except json.JSONDecodeError as exc:
        return PowerShellResult(
            ok=False,
            error=f"PowerShell returned invalid JSON: {exc.msg}",
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )
    return PowerShellResult(
        ok=True,
        data=data,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _coerce_stream(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
