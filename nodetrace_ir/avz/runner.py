from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from typing import Mapping

from .policy import (
    DEFAULT_READ_ONLY_POLICY,
    ReadOnlyAVZPolicy,
    validate_read_only_script,
)


class AVZRunnerError(RuntimeError):
    """Raised before AVZ starts when its executable or output path is unsafe."""


@dataclass(frozen=True, slots=True)
class AVZRunArtifacts:
    status: str
    command: tuple[str, ...]
    script_path: Path
    output_directory: Path
    log_path: Path
    html_path: Path
    xml_path: Path
    returncode: int | None
    started_at: str
    finished_at: str
    elapsed_seconds: float
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""

    @property
    def report_paths(self) -> tuple[Path, ...]:
        return tuple(
            path for path in (self.xml_path, self.html_path, self.log_path) if path.is_file()
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _validate_local_path(path: Path, *, name: str, must_be_file: bool) -> Path:
    if not path.is_absolute():
        raise AVZRunnerError(f"{name} must be an absolute path")
    raw = str(path)
    if any(character in raw for character in ("\x00", "\r", "\n", "'")):
        raise AVZRunnerError(f"{name} contains a character unsafe for an AVZ script")
    if raw.startswith("\\\\") or raw.startswith("//"):
        raise AVZRunnerError(f"{name} must not be a UNC/network path")
    try:
        item_stat = path.lstat()
    except OSError as exc:
        raise AVZRunnerError(f"{name} is unavailable: {exc}") from exc
    attributes = int(getattr(item_stat, "st_file_attributes", 0))
    if stat.S_ISLNK(item_stat.st_mode) or attributes & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    ):
        raise AVZRunnerError(f"{name} must not be a symlink or reparse point")
    if must_be_file and not stat.S_ISREG(item_stat.st_mode):
        raise AVZRunnerError(f"{name} is not a regular file")
    if not must_be_file and not stat.S_ISDIR(item_stat.st_mode):
        raise AVZRunnerError(f"{name} is not a directory")
    return path.resolve(strict=True)


def _avz_literal(path: Path) -> str:
    value = str(path)
    if any(character in value for character in ("\x00", "\r", "\n", "'")):
        raise AVZRunnerError("AVZ output path cannot be represented safely")
    return value


def build_read_only_script(
    output_directory: str | Path,
    *,
    scan_file: str | Path | None = None,
    scan_directory: str | Path | None = None,
    include_system_report: bool = True,
    policy: ReadOnlyAVZPolicy = DEFAULT_READ_ONLY_POLICY,
) -> str:
    """Render the only AVZ script shape that NodeTrace IR is allowed to run."""

    output = Path(output_directory)
    if not output.is_absolute():
        raise AVZRunnerError("AVZ output directory must be an absolute path")
    output_text = _avz_literal(output)
    log_path = _avz_literal(output / "avz_scan.log")
    html_path = _avz_literal(output / "avz_system.htm")
    watchdog_seconds = max(1, int(policy.timeout_seconds))
    if scan_file is not None and scan_directory is not None:
        raise AVZRunnerError("AVZ accepts either a scan file or a scan directory, not both")
    lines = ["begin"]
    lines.extend(f"  {line}" for line in policy.setup_lines())
    lines.extend(
        (
            f"  SetupAVZ('TempFolder={output_text}');",
            f"  SetupAVZ('QuarantineBaseFolder={output_text}');",
            f"  ActivateWatchDog({watchdog_seconds});",
        )
    )
    scan_target = scan_file if scan_file is not None else scan_directory
    if scan_target is not None:
        target = Path(scan_target)
        if not target.is_absolute():
            raise AVZRunnerError("AVZ scan target must be an absolute path")
        _avz_literal(target)
        lines.append("  RunScan;")
    lines.append(f"  SaveLog('{log_path}');")
    if include_system_report:
        lines.extend(
            (
            # $FFFBFFFF excludes DNS/Ping network diagnostics. ARepParams also
            # filters trusted files (1), includes structured details (2),
            # suppresses an extra ZIP (32), and includes every process (64).
            f"  ExecuteSysCheckEX('{html_path}', $FFFBFFFF, true, 1+2+32+64);",
            )
        )
    lines.extend(("  ExitAVZ;", "end."))
    script = "\r\n".join(lines) + "\r\n"
    validate_read_only_script(script)
    return script


def _minimal_environment(output_directory: Path) -> dict[str, str]:
    environment: dict[str, str] = {
        "TEMP": str(output_directory),
        "TMP": str(output_directory),
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if system_root:
            system32 = Path(system_root) / "System32"
            environment.update(
                {
                    "SystemRoot": system_root,
                    "WINDIR": system_root,
                    "COMSPEC": str(system32 / "cmd.exe"),
                    "PATH": str(system32),
                }
            )
        # AVZ is a legacy GUI application and expects the standard Windows
        # profile/program-directory variables to exist.  Copy only this
        # explicit allowlist: proxy variables, credentials and unrelated
        # application state are intentionally not inherited.
        for key in (
            "ALLUSERSPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "ProgramData",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS",
            "PATHEXT",
        ):
            value = os.environ.get(key)
            if value:
                environment[key] = value
    return environment


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    for encoding in ("utf-8", "cp1251"):
        try:
            return value.decode(encoding)
        except UnicodeDecodeError:
            continue
    return value.decode("utf-8", errors="replace")


class AVZRunner:
    """Execute an explicitly supplied AVZ binary under a read-only policy.

    This class never downloads AVZ and never searches ``PATH``.  The caller is
    responsible for supplying and independently verifying the approved binary.
    """

    def __init__(
        self,
        executable: str | Path,
        *,
        policy: ReadOnlyAVZPolicy = DEFAULT_READ_ONLY_POLICY,
    ) -> None:
        self.executable = Path(executable)
        self.policy = policy

    def run(
        self,
        output_directory: str | Path,
        *,
        scan_file: str | Path | None = None,
        scan_directory: str | Path | None = None,
        extra_environment: Mapping[str, str] | None = None,
    ) -> AVZRunArtifacts:
        if scan_file is not None and scan_directory is not None:
            raise AVZRunnerError("AVZ accepts either a scan file or a scan directory, not both")
        executable = _validate_local_path(
            self.executable, name="AVZ executable", must_be_file=True
        )
        output = _validate_local_path(
            Path(output_directory), name="AVZ output directory", must_be_file=False
        )
        target = (
            _validate_local_path(
                Path(scan_file), name="AVZ scan file", must_be_file=True
            )
            if scan_file is not None
            else None
        )
        directory = (
            _validate_local_path(
                Path(scan_directory), name="AVZ scan directory", must_be_file=False
            )
            if scan_directory is not None
            else None
        )
        # A mounted Windows installation is a file tree, not the running
        # system.  In that mode AVZ must never inventory WinPE processes,
        # services or vulnerabilities: only RunScan over the explicit tree is
        # permitted and only the resulting scan log is imported.
        effective_policy = (
            replace(
                self.policy,
                scan_processes=False,
                scan_system=False,
                scan_vulnerabilities=False,
            )
            if directory is not None
            else self.policy
        )
        script = build_read_only_script(
            output,
            scan_file=target,
            scan_directory=directory,
            include_system_report=directory is None,
            policy=effective_policy,
        )
        validate_read_only_script(script)

        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8-sig",
            newline="",
            prefix="nodetrace_avz_",
            suffix=".avz",
            dir=output,
            delete=False,
        )
        script_path = Path(handle.name)
        try:
            handle.write(script)
        finally:
            handle.close()

        command_parts = [
            str(executable),
            "HiddenMode=3",
            f"Lang={self.policy.language.upper()}",
            f"TempFolder={output}",
            f"QuarantineBaseFolder={output}",
            "DelVir=N",
            "ModeVirus=0",
            "ModeAdvWare=0",
            "ModeSpy=0",
            "ModePornWare=0",
            "ModeRiskWare=0",
            "ModeHackTools=0",
            "ExtFileDelete=N",
            "UseInfected=N",
            "UseQuarantine=N",
            "AutoRepairLSP=N",
            "AutoFixSysProblems=N",
            "RootKitDetect=N",
            "AntiRootKitSystem=N",
            "AntiRootKitSystemUser=N",
            "AntiRootKitSystemKernel=N",
            f"EvLevel={effective_policy.heuristic_level}",
            f"ExtEvCheck={'Y' if effective_policy.extended_heuristics else 'N'}",
            f"ScanProcess={'Y' if effective_policy.scan_processes else 'N'}",
            f"ScanSystem={'Y' if effective_policy.scan_system else 'N'}",
            f"ScanSystemIPU={'Y' if effective_policy.scan_vulnerabilities else 'N'}",
            "RepGoodFiles=N",
            "ScanAVZFolders=N",
            "AG=N",
        ]
        if target is not None:
            # SCANFILE makes RunScan deterministic and prevents AVZ from
            # inheriting an arbitrary search scope from a bundled profile.
            command_parts.append(f"SCANFILE={target}")
        elif directory is not None:
            # SCAN is AVZ's documented directory scope.  Passing a single,
            # validated mounted root avoids inheriting drive selections from
            # any local AVZ profile.
            command_parts.append(f"SCAN={directory}")
        command_parts.extend(
            [
            # AVZ documents Script as the last-processed command-line option.
            # Keeping it last also makes the intended order obvious to an
            # analyst reviewing the recorded argv.
            f"Script={script_path}",
            ]
        )
        command = tuple(command_parts)
        environment = _minimal_environment(output)
        if extra_environment:
            for key, value in extra_environment.items():
                normalized = str(key).upper()
                if not normalized.startswith("NODETRACE_"):
                    raise AVZRunnerError(
                        f"Only NODETRACE_* extra environment keys are accepted: {key}"
                    )
                environment[normalized] = str(value)

        started_at = _utc_now()
        started = time.monotonic()
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
        try:
            completed = subprocess.run(
                list(command),
                shell=False,
                cwd=str(executable.parent),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            timeout=effective_policy.timeout_seconds,
                check=False,
                creationflags=creationflags,
            )
            returncode = int(completed.returncode)
            timed_out = False
            status = "completed" if returncode == 0 else "failed"
            stdout = _decode_output(completed.stdout)
            stderr = _decode_output(completed.stderr)
        except subprocess.TimeoutExpired as exc:
            returncode = None
            timed_out = True
            status = "timed_out"
            stdout = _decode_output(exc.stdout)
            stderr = _decode_output(exc.stderr)
        except OSError as exc:
            returncode = None
            timed_out = False
            status = "failed"
            stdout = ""
            stderr = f"Unable to start AVZ: {exc}"

        return AVZRunArtifacts(
            status=status,
            command=command,
            script_path=script_path,
            output_directory=output,
            log_path=output / "avz_scan.log",
            html_path=output / "avz_system.htm",
            xml_path=output / "avz_system.xml",
            returncode=returncode,
            started_at=started_at,
            finished_at=_utc_now(),
            elapsed_seconds=round(time.monotonic() - started, 6),
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
        )


__all__ = [
    "AVZRunArtifacts",
    "AVZRunner",
    "AVZRunnerError",
    "build_read_only_script",
]
