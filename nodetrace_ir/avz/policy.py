from __future__ import annotations

from dataclasses import dataclass
import re


class AVZPolicyViolation(ValueError):
    """Raised when an AVZ script can modify the host or use the network."""


_REQUIRED_SAFE_SETTINGS = (
    ("DelVir", "N"),
    ("ModeVirus", "0"),
    ("ModeAdvWare", "0"),
    ("ModeSpy", "0"),
    ("ModePornWare", "0"),
    ("ModeRiskWare", "0"),
    ("ModeHackTools", "0"),
    ("ExtFileDelete", "N"),
    ("UseInfected", "N"),
    ("UseQuarantine", "N"),
    ("AutoRepairLSP", "N"),
    ("AutoFixSysProblems", "N"),
    ("RootKitDetect", "N"),
    ("AntiRootKitSystem", "N"),
    ("AntiRootKitSystemUser", "N"),
    ("AntiRootKitSystemKernel", "N"),
)

_SENSITIVE_SAFE_SETTINGS = {
    key.casefold(): value.casefold() for key, value in _REQUIRED_SAFE_SETTINGS
}

_VARIABLE_SAFE_SETTINGS = {
    "evlevel": {"0", "1", "2", "3"},
    "extevcheck": {"n", "y"},
    "scanprocess": {"n", "y"},
    "scansystem": {"n", "y"},
    "scansystemipu": {"n", "y"},
    "repgoodfiles": {"n"},
    "hiddenmode": {"3"},
}
_LOCAL_PATH_SETTINGS = {"tempfolder", "quarantinebasefolder"}

_SETUP_CALL = re.compile(
    r"\bSetupAVZ\s*\(\s*'(?P<setting>[^']*)'\s*\)", flags=re.IGNORECASE
)

_FORBIDDEN_CALLS = re.compile(
    r"\b(?:"
    r"DeleteFile(?:Mask)?|DeleteService|DelBHO|"
    r"QuarantineFileF?|ExecuteAutoQuarantine|ClearQuarantine(?:Ex)?|"
    r"CreateQurantineArchive|ExecuteSysClean|SysClean\w*|"
    r"BC_\w+|RebootWindows|ExecuteRepair|ExecuteStdScr|"
    r"DownloadFile|FTPSendFile|SendSysLogMessage|"
    r"RegKeyParamWrite|RegKeyDel|RegKeyParamDel"
    r")\b",
    flags=re.IGNORECASE,
)

_FORBIDDEN_NETWORK_TEXT = re.compile(
    r"(?:https?://|ftp://|\\\\[^\\\s]+\\)", flags=re.IGNORECASE
)

_FUNCTION_CALL = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\(")
_ALLOWED_FUNCTIONS = {
    "setupavz",
    "activatewatchdog",
    "savelog",
    "executesyscheckex",
}
_SAFE_SYSTEM_CHECK = re.compile(
    r"\bExecuteSysCheckEX\s*\(\s*'[^']+'\s*,\s*\$FFFBFFFF\s*,\s*true\s*,"
    r"\s*1\s*\+\s*2\s*\+\s*32\s*\+\s*64\s*\)",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ReadOnlyAVZPolicy:
    """Immutable policy for a non-remediating, non-networked AVZ run.

    The initial detector intentionally leaves the AVZ rootkit driver disabled.
    Loading a kernel component before volatile evidence is captured would alter
    the investigated host and is outside this isolated integration layer.
    """

    timeout_seconds: float = 30 * 60
    heuristic_level: int = 3
    scan_processes: bool = True
    scan_system: bool = True
    scan_vulnerabilities: bool = True
    extended_heuristics: bool = True
    language: str = "RU"
    allow_remediation: bool = False
    allow_quarantine: bool = False
    allow_network: bool = False
    allow_rootkit_driver: bool = False

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("AVZ timeout must be positive")
        if self.heuristic_level not in {0, 1, 2, 3}:
            raise ValueError("AVZ heuristic_level must be between 0 and 3")
        if self.language.upper() not in {"RU", "EN"}:
            raise ValueError("AVZ language must be RU or EN")
        if self.allow_remediation:
            raise AVZPolicyViolation("NodeTrace IR never permits AVZ remediation")
        if self.allow_quarantine:
            raise AVZPolicyViolation("NodeTrace IR never permits automatic AVZ quarantine")
        if self.allow_network:
            raise AVZPolicyViolation("NodeTrace IR never permits AVZ network access")
        if self.allow_rootkit_driver:
            raise AVZPolicyViolation(
                "The isolated detector never loads AVZ kernel/rootkit components"
            )

    def setup_lines(self) -> tuple[str, ...]:
        yes_no = lambda value: "Y" if value else "N"
        return (
            "SetupAVZ('DelVir=N');",
            "SetupAVZ('ModeVirus=0');",
            "SetupAVZ('ModeAdvWare=0');",
            "SetupAVZ('ModeSpy=0');",
            "SetupAVZ('ModePornWare=0');",
            "SetupAVZ('ModeRiskWare=0');",
            "SetupAVZ('ModeHackTools=0');",
            "SetupAVZ('ExtFileDelete=N');",
            "SetupAVZ('UseInfected=N');",
            "SetupAVZ('UseQuarantine=N');",
            "SetupAVZ('AutoRepairLSP=N');",
            "SetupAVZ('AutoFixSysProblems=N');",
            "SetupAVZ('RootKitDetect=N');",
            "SetupAVZ('AntiRootKitSystem=N');",
            "SetupAVZ('AntiRootKitSystemUser=N');",
            "SetupAVZ('AntiRootKitSystemKernel=N');",
            f"SetupAVZ('EvLevel={self.heuristic_level}');",
            f"SetupAVZ('ExtEvCheck={yes_no(self.extended_heuristics)}');",
            f"SetupAVZ('ScanProcess={yes_no(self.scan_processes)}');",
            f"SetupAVZ('ScanSystem={yes_no(self.scan_system)}');",
            f"SetupAVZ('ScanSystemIPU={yes_no(self.scan_vulnerabilities)}');",
            "SetupAVZ('RepGoodFiles=N');",
            "SetupAVZ('HiddenMode=3');",
        )


DEFAULT_READ_ONLY_POLICY = ReadOnlyAVZPolicy()


def validate_read_only_script(script: str) -> None:
    """Fail closed if generated or supplied AVZ source violates policy."""

    if not isinstance(script, str) or not script.strip():
        raise AVZPolicyViolation("AVZ script is empty")
    if "\x00" in script:
        raise AVZPolicyViolation("AVZ script contains a NUL character")
    if _FORBIDDEN_NETWORK_TEXT.search(script):
        raise AVZPolicyViolation("AVZ script contains a network path or URL")
    setup_mentions = len(re.findall(r"\bSetupAVZ\s*\(", script, flags=re.IGNORECASE))
    setup_matches = list(_SETUP_CALL.finditer(script))
    if setup_mentions != len(setup_matches):
        raise AVZPolicyViolation("AVZ script contains an unparseable SetupAVZ call")
    settings: dict[str, list[str]] = {}
    for match in setup_matches:
        setting = match.group("setting")
        if "=" not in setting:
            raise AVZPolicyViolation(f"Malformed AVZ setting: {setting}")
        key, value = (part.strip() for part in setting.split("=", 1))
        settings.setdefault(key.casefold(), []).append(value.casefold())
        normalized_key = key.casefold()
        normalized_value = value.casefold()
        required_value = _SENSITIVE_SAFE_SETTINGS.get(normalized_key)
        if required_value is not None and value.casefold() != required_value:
            raise AVZPolicyViolation(f"Unsafe AVZ setting is present: {key}={value}")
        if required_value is not None:
            continue
        allowed_values = _VARIABLE_SAFE_SETTINGS.get(normalized_key)
        if allowed_values is not None:
            if normalized_value not in allowed_values:
                raise AVZPolicyViolation(f"Unsafe AVZ setting is present: {key}={value}")
            continue
        if normalized_key in _LOCAL_PATH_SETTINGS:
            if not value or value.startswith(("\\\\", "//")):
                raise AVZPolicyViolation(f"Unsafe AVZ output path setting: {key}={value}")
            continue
        raise AVZPolicyViolation(f"Unapproved AVZ setting is present: {key}")
    for key, value in _REQUIRED_SAFE_SETTINGS:
        if value.casefold() not in settings.get(key.casefold(), []):
            raise AVZPolicyViolation(
                f"Required read-only setting is missing: SetupAVZ('{key}={value}');"
            )

    without_literals = re.sub(r"'[^']*'", "''", script)
    match = _FORBIDDEN_CALLS.search(without_literals)
    if match:
        raise AVZPolicyViolation(f"Unsafe AVZ call is present: {match.group(0).strip()}")
    for call in _FUNCTION_CALL.finditer(without_literals):
        if call.group("name").casefold() not in _ALLOWED_FUNCTIONS:
            raise AVZPolicyViolation(f"Unapproved AVZ call is present: {call.group('name')}")
    system_check_mentions = len(
        re.findall(r"\bExecuteSysCheckEX\s*\(", script, flags=re.IGNORECASE)
    )
    if system_check_mentions and len(_SAFE_SYSTEM_CHECK.findall(script)) != system_check_mentions:
        raise AVZPolicyViolation(
            "ExecuteSysCheckEX must use the offline-safe mask and structured-report flags"
        )
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.casefold() in {"begin", "end.", "runscan;", "exitavz;"}:
            continue
        if re.fullmatch(r"SetupAVZ\s*\(\s*'[^']*'\s*\)\s*;", line, re.IGNORECASE):
            continue
        if re.fullmatch(r"ActivateWatchDog\s*\(\s*\d+\s*\)\s*;", line, re.IGNORECASE):
            continue
        if re.fullmatch(r"SaveLog\s*\(\s*'[^']+'\s*\)\s*;", line, re.IGNORECASE):
            continue
        if line.endswith(";") and _SAFE_SYSTEM_CHECK.fullmatch(line[:-1].strip()):
            continue
        raise AVZPolicyViolation(f"Unapproved AVZ statement is present: {line[:80]}")


__all__ = [
    "AVZPolicyViolation",
    "DEFAULT_READ_ONLY_POLICY",
    "ReadOnlyAVZPolicy",
    "validate_read_only_script",
]
