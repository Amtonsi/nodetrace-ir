from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from nodetrace_ir.avz import (
    AVZImportError,
    AVZImportLimits,
    AVZImporter,
    AVZPolicyViolation,
    AVZRunner,
    AVZRunnerError,
    ReadOnlyAVZPolicy,
    build_read_only_script,
    decode_avz_text,
    import_avz_report,
    validate_read_only_script,
)
import nodetrace_ir.avz.runner as runner_module


FIXTURES = Path(__file__).parent / "fixtures" / "avz"


def test_read_only_policy_is_fail_closed() -> None:
    for option in (
        "allow_remediation",
        "allow_quarantine",
        "allow_network",
        "allow_rootkit_driver",
    ):
        with pytest.raises(AVZPolicyViolation):
            ReadOnlyAVZPolicy(**{option: True})

    safe = "\n".join(ReadOnlyAVZPolicy().setup_lines())
    validate_read_only_script(safe)
    with pytest.raises(AVZPolicyViolation, match="Unsafe AVZ call"):
        validate_read_only_script(safe + "\nDeleteFile('C:\\Temp\\sample.exe');")
    with pytest.raises(AVZPolicyViolation, match="network path or URL"):
        validate_read_only_script(safe + "\n// https://example.invalid/report")
    with pytest.raises(AVZPolicyViolation, match="Unsafe AVZ setting"):
        validate_read_only_script(safe.replace("DelVir=N", "DelVir=Y"))
    with pytest.raises(AVZPolicyViolation, match="Unapproved AVZ call"):
        validate_read_only_script(safe + "\nExecuteFile('C:\\Temp\\sample.exe');")


def test_generated_script_contains_only_detection_and_report_actions(tmp_path: Path) -> None:
    script = build_read_only_script(tmp_path, scan_file=tmp_path / "suspect.exe")
    lowered = script.casefold()

    assert "setupavz('delvir=n');" in lowered
    assert "setupavz('useinfected=n');" in lowered
    assert "setupavz('usequarantine=n');" in lowered
    assert "setupavz('rootkitdetect=n');" in lowered
    assert "setupavz('autorepairlsp=n');" in lowered
    assert "setupavz('autofixsysproblems=n');" in lowered
    assert "setupavz('antirootkitsystemkernel=n');" in lowered
    assert "runscan;" in lowered
    assert "executesyscheckex" in lowered
    assert "$fffbffff" in lowered
    assert "1+2+32+64" in lowered
    assert "$ffffffff" not in lowered
    assert "deletefile" not in lowered
    assert "quarantinefile" not in lowered
    assert "downloadfile" not in lowered
    validate_read_only_script(script)


def test_system_only_script_collects_report_without_unbounded_runscan(tmp_path: Path) -> None:
    script = build_read_only_script(tmp_path)

    assert "RunScan;" not in script
    assert "ExecuteSysCheckEX" in script
    validate_read_only_script(script)


def test_offline_directory_script_scans_files_without_live_system_report(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mounted-windows"
    target.mkdir()
    policy = ReadOnlyAVZPolicy(
        scan_processes=False,
        scan_system=False,
        scan_vulnerabilities=False,
    )
    script = build_read_only_script(
        tmp_path,
        scan_directory=target,
        include_system_report=False,
        policy=policy,
    )

    assert "RunScan;" in script
    assert "ExecuteSysCheckEX" not in script
    assert "ScanProcess=N" in script
    assert "ScanSystem=N" in script
    assert "ScanSystemIPU=N" in script
    validate_read_only_script(script)


def test_runner_uses_absolute_argv_shell_false_and_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "avz5.exe"
    executable.write_bytes(b"test fixture, not a real executable")
    output = tmp_path / "output"
    output.mkdir()
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    target = tmp_path / "suspect file.exe"
    target.write_bytes(b"benign fixture")
    result = AVZRunner(executable, policy=ReadOnlyAVZPolicy(timeout_seconds=12)).run(
        output,
        scan_file=target,
        extra_environment={"NODETRACE_CASE": "case-1"},
    )

    assert result.status == "completed"
    assert result.returncode == 0
    assert Path(result.command[0]).is_absolute()
    assert result.command[0] == str(executable.resolve())
    script_argument = next(item for item in result.command if item.startswith("Script="))
    assert Path(script_argument.removeprefix("Script=")).is_absolute()
    assert f"SCANFILE={target.resolve()}" in result.command
    assert result.command[-1] == script_argument
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 12
    assert kwargs["check"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    environment = kwargs["env"]
    assert isinstance(environment, dict)
    assert environment["NODETRACE_CASE"] == "case-1"
    assert environment["NO_PROXY"] == "*"
    assert "HTTP_PROXY" not in environment
    assert "HTTPS_PROXY" not in environment
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        assert environment["LOCALAPPDATA"] == os.environ["LOCALAPPDATA"]
    script = result.script_path.read_text(encoding="utf-8-sig")
    validate_read_only_script(script)
    assert "DelVir=N" in result.command
    assert "UseQuarantine=N" in result.command


def test_runner_timeout_is_reported_without_invoking_real_avz(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "avz.exe"
    executable.write_bytes(b"fixture")
    output = tmp_path / "out"
    output.mkdir()

    def time_out(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"partial")

    monkeypatch.setattr(runner_module.subprocess, "run", time_out)
    target = tmp_path / "suspect.exe"
    target.write_bytes(b"benign fixture")
    result = AVZRunner(executable, policy=ReadOnlyAVZPolicy(timeout_seconds=1)).run(
        output, scan_file=target
    )

    assert result.status == "timed_out"
    assert result.timed_out is True
    assert result.returncode is None
    assert result.stdout == "partial"


def test_runner_offline_directory_scope_disables_live_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "avz.exe"
    executable.write_bytes(b"fixture")
    output = tmp_path / "out"
    output.mkdir()
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    result = AVZRunner(executable).run(output, scan_directory=mounted)

    assert f"SCAN={mounted.resolve()}" in result.command
    assert "ScanProcess=N" in result.command
    assert "ScanSystem=N" in result.command
    assert "ScanSystemIPU=N" in result.command
    assert not any(item.startswith("SCANFILE=") for item in result.command)
    script = result.script_path.read_text(encoding="utf-8-sig")
    assert "RunScan;" in script
    assert "ExecuteSysCheckEX" not in script
    validate_read_only_script(script)


def test_runner_rejects_unsafe_paths_and_environment(tmp_path: Path) -> None:
    executable = tmp_path / "avz.exe"
    executable.write_bytes(b"fixture")
    output = tmp_path / "out"
    output.mkdir()

    with pytest.raises(AVZRunnerError, match="absolute path"):
        AVZRunner("avz.exe").run(output, scan_file=executable)
    with pytest.raises(AVZRunnerError, match="Only NODETRACE"):
        AVZRunner(executable).run(
            output, scan_file=executable, extra_environment={"PATH": "C:\\Tools"}
        )
    with pytest.raises(AVZRunnerError, match="scan file must be an absolute path"):
        AVZRunner(executable).run(output, scan_file="relative.exe")
    with pytest.raises(AVZRunnerError, match="either a scan file or a scan directory"):
        AVZRunner(executable).run(
            output,
            scan_file=executable,
            scan_directory=tmp_path,
        )
    with pytest.raises(AVZRunnerError, match="absolute path"):
        build_read_only_script("relative-output")


def test_xml_import_creates_typed_evidence_and_direct_relations() -> None:
    result = import_avz_report(
        FIXTURES / "avz5_sample.xml", collected_at="2026-07-15T00:30:00+00:00"
    )

    assert result.status == "completed"
    assert result.collector == "avz_import"
    assert result.raw_payload["format"] == "xml"
    assert result.raw_payload["metadata"]["version"] == "5.0.2"
    assert {item.entity_type for item in result.evidence} >= {
        "malware_detection",
        "file",
        "process",
        "service",
        "autorun",
        "network_connection",
        "network_endpoint",
    }
    detections = [item for item in result.evidence if item.entity_type == "malware_detection"]
    assert len(detections) == 2
    assert {item.properties["confirmed_malware"] for item in detections} == {True, False}
    suspicious = next(item for item in detections if not item.properties["confirmed_malware"])
    assert suspicious.properties["verdict"] == "suspicious"
    assert suspicious.confidence == "medium"
    assert "requires analyst validation" in suspicious.properties["interpretation"]
    relation_types = {item.relation_type for item in result.relations}
    assert relation_types >= {
        "detected_as",
        "executed_as",
        "configured_as_service",
        "possible_persistence_reference",
        "owns_connection",
        "remote_endpoint",
    }
    assert relation_types.isdisjoint({"caused", "infected_process", "entry_vector"})


def test_cp1251_text_import_is_partial_and_never_promotes_suspicion() -> None:
    text = (FIXTURES / "avz_scan_ru.txt").read_text(encoding="utf-8")
    result = AVZImporter().import_report(
        text.encode("cp1251"),
        filename="avz_scan.log",
        collected_at="2026-07-15T00:30:00+00:00",
    )

    assert result.status == "partial"
    assert result.raw_payload["format"] == "text"
    assert result.raw_payload["encoding"] == "cp1251"
    assert result.gaps
    assert {item.entity_type for item in result.evidence} >= {
        "malware_detection",
        "process",
        "service",
        "autorun",
        "network_connection",
    }
    detections = [item for item in result.evidence if item.entity_type == "malware_detection"]
    assert len(detections) == 2
    suspicious = next(item for item in detections if item.properties["verdict"] == "suspicious")
    assert suspicious.properties["confirmed_malware"] is False
    relation = next(
        item
        for item in result.relations
        if item.target_key == suspicious.stable_key and item.relation_type == "detected_as"
    )
    assert relation.confidence == "medium"
    assert "not proof" in relation.rationale


@pytest.mark.parametrize(
    ("codec", "expected"),
    (("utf-8-sig", "utf-8-sig"), ("utf-16", "utf-16")),
)
def test_decoder_accepts_bom_encodings(codec: str, expected: str) -> None:
    text, encoding = decode_avz_text("AVZ отчёт".encode(codec))
    assert text == "AVZ отчёт"
    assert encoding == expected


def test_utf16_xml_report_is_supported() -> None:
    xml = (FIXTURES / "avz5_sample.xml").read_text(encoding="utf-8")
    result = import_avz_report(xml.encode("utf-16"), filename="avz_report.xml")
    assert result.status == "completed"
    assert result.raw_payload["encoding"] == "utf-16"
    assert any(item.entity_type == "malware_detection" for item in result.evidence)


@pytest.mark.parametrize("codec", ["utf-8", "utf-16"])
def test_xml_dtd_and_entities_are_rejected(codec: str) -> None:
    malicious = (
        '<?xml version="1.0"?><!DOCTYPE report ['
        '<!ENTITY local SYSTEM "file:///C:/Windows/win.ini">]>'
        "<report><item>&local;</item></report>"
    ).encode(codec)
    with pytest.raises(AVZImportError, match="DTD and ENTITY"):
        import_avz_report(malicious, filename="untrusted.xml")


def test_malformed_xml_is_rejected_cleanly() -> None:
    with pytest.raises(AVZImportError, match="Malformed AVZ XML"):
        import_avz_report(b"<AVZReport><Processes>", filename="broken.xml")


def test_import_limits_reject_oversize_deep_and_long_reports() -> None:
    with pytest.raises(AVZImportError, match="byte import limit"):
        import_avz_report(
            b"AVZ report is too long",
            limits=AVZImportLimits(max_bytes=8),
        )

    deep = b"<r><a><b><c /></b></a></r>"
    with pytest.raises(AVZImportError, match="nesting-depth"):
        import_avz_report(deep, limits=AVZImportLimits(max_depth=3))

    long_text = b"<r><a>0123456789</a></r>"
    with pytest.raises(AVZImportError, match="per-element"):
        import_avz_report(
            long_text,
            limits=AVZImportLimits(max_text_per_element=5),
        )

    with pytest.raises(AVZImportError, match="total-text"):
        import_avz_report(
            b"plain AVZ text",
            limits=AVZImportLimits(max_total_text=5),
        )


def test_imported_paths_are_evidence_only_and_never_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    referenced = tmp_path / "must-not-be-opened.exe"
    xml = (
        '<AVZReport removalMode="disabled"><Detections>'
        f'<SuspiciousFile path="{referenced}" threat="heuristic suspicion" />'
        "</Detections></AVZReport>"
    ).encode("utf-8")

    original_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object):
        if path == referenced:
            raise AssertionError("report-referenced host path was opened")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    result = import_avz_report(xml, filename="evidence.xml")
    assert result.status == "completed"
    assert any(item.properties.get("path") == str(referenced) for item in result.evidence)
    assert referenced.exists() is False
