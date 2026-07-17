from __future__ import annotations

import csv
from hashlib import sha256
from html import unescape
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest

from nodetrace_ir.database import Database
from nodetrace_ir.contracts import CollectorResult, EvidenceDraft, RelationDraft
from nodetrace_ir.demo import create_demo_case
from nodetrace_ir.report import CaseExporter, _csv_safe, file_sha256


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = PROJECT_ROOT / "run_nodetrace_ir.py"
BUNDLE_ROOT = "NodeTraceIR_Case/"


def _bundle_bytes(archive: ZipFile, relative_path: str) -> bytes:
    return archive.read(f"{BUNDLE_ROOT}{relative_path}")


def _parse_sha256sums(raw: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        digest, path = line.split("  ", 1)
        result[path] = digest
    return result


def test_demo_database_report_manifest_zip_round_trip(tmp_path: Path) -> None:
    """Pin the complete GUI-independent evidence export path."""

    database_path = tmp_path / "state" / "nodetrace_ir.sqlite3"
    database = Database(database_path)
    case = create_demo_case(database)
    summary_before_export = database.case_summary(case.id)

    assert database_path.is_file()
    assert case.properties["synthetic"] is True
    assert summary_before_export["counts"]["evidence"] >= 10
    assert summary_before_export["counts"]["relations"] >= 10
    assert summary_before_export["counts"]["coverage_gaps"] >= 1

    output = tmp_path / "exports" / "demo-case.zip"
    result = CaseExporter(database).export(case.id, output)

    assert result.zip_path == output
    assert output.is_file() and output.stat().st_size > 0
    assert result.sha256 == file_sha256(output)
    assert len(result.sha256) == 64
    assert len(result.manifest_sha256) == 64

    required_files = {
        "README.txt",
        "SHA256SUMS.txt",
        "case.json",
        "evidence.csv",
        "timeline.csv",
        "graph.json",
        "graph.svg",
        "impact.json",
        "manifest.json",
        "report.html",
    }
    with ZipFile(output) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        relative_names = {name.removeprefix(BUNDLE_ROOT) for name in names}
        assert required_files <= relative_names
        assert result.file_count == len(names)

        # The case bundle must not smuggle runtime state, the seed executable,
        # or path traversal entries into an analyst-facing export.
        for name in names:
            path = PurePosixPath(name)
            assert name.startswith(BUNDLE_ROOT)
            assert not path.is_absolute()
            assert ".." not in path.parts
            assert "\\" not in name
            assert not name.casefold().endswith((".sqlite", ".sqlite3", ".db", ".exe", ".dll"))

        manifest_raw = _bundle_bytes(archive, "manifest.json")
        manifest = json.loads(manifest_raw)
        assert manifest["schema"] == "nodetrace-ir/manifest/v1"
        assert manifest["case_id"] == case.id
        assert manifest["hash_algorithm"] == "SHA-256"
        assert result.manifest_sha256 == sha256(manifest_raw).hexdigest()

        manifest_files = {entry["path"]: entry for entry in manifest["files"]}
        expected_manifest_files = relative_names - {"manifest.json", "SHA256SUMS.txt"}
        assert set(manifest_files) == expected_manifest_files
        for relative_path, entry in manifest_files.items():
            payload = _bundle_bytes(archive, relative_path)
            assert entry["size"] == len(payload)
            assert entry["sha256"] == sha256(payload).hexdigest()

        checksums = _parse_sha256sums(_bundle_bytes(archive, "SHA256SUMS.txt"))
        assert set(checksums) == expected_manifest_files | {"manifest.json"}
        for relative_path, digest in checksums.items():
            assert digest == sha256(_bundle_bytes(archive, relative_path)).hexdigest()

        case_payload = json.loads(_bundle_bytes(archive, "case.json"))
        assert case_payload["schema"] == "nodetrace-ir/case-export/v1"
        assert case_payload["case"]["id"] == case.id
        assert case_payload["case"]["properties"]["synthetic"] is True
        assert len(case_payload["evidence"]) == summary_before_export["counts"]["evidence"]
        assert len(case_payload["timeline"]) == summary_before_export["observation_count"]
        assert len(case_payload["relations"]) == summary_before_export["counts"]["relations"]
        assert len(case_payload["coverage_gaps"]) == summary_before_export["counts"]["coverage_gaps"]
        assert case_payload["artifacts"] == []
        assert case_payload["impact_assessment"]["case_id"] == case.id
        assert set(case_payload["impact_assessment"]["basis_counts"]) == {
            "observed",
            "correlated",
            "hypothesis",
        }

        impact_payload = json.loads(_bundle_bytes(archive, "impact.json"))
        assert impact_payload["schema"] == "nodetrace-ir/impact-assessment/v1"
        assert impact_payload["findings"] == case_payload["impact_assessment"]["findings"]

        graph_payload = json.loads(_bundle_bytes(archive, "graph.json"))
        assert len(graph_payload["nodes"]) == len(case_payload["evidence"])
        assert len(graph_payload["edges"]) == len(case_payload["relations"])

        graph_svg = _bundle_bytes(archive, "graph.svg").decode("utf-8")
        svg_root = ElementTree.fromstring(graph_svg)
        assert svg_root.tag == "{http://www.w3.org/2000/svg}svg"
        assert svg_root.attrib["viewBox"]
        assert svg_root.attrib["preserveAspectRatio"] == "xMidYMid meet"
        assert "width:100%" in svg_root.attrib["style"]
        assert "height:auto" in svg_root.attrib["style"]
        assert "<script" not in graph_svg.casefold()

        csv_text = _bundle_bytes(archive, "evidence.csv").decode("utf-8-sig")
        csv_rows = list(csv.DictReader(io.StringIO(csv_text)))
        assert len(csv_rows) == len(case_payload["evidence"])
        assert {row["entity_type"] for row in csv_rows} >= {"file", "process"}
        timeline_text = _bundle_bytes(archive, "timeline.csv").decode("utf-8-sig")
        timeline_rows = list(csv.DictReader(io.StringIO(timeline_text)))
        assert len(timeline_rows) == len(case_payload["timeline"])

        html = _bundle_bytes(archive, "report.html").decode("utf-8")
        assert "NodeTrace IR" in html
        assert graph_svg in html
        assert 'href="graph.svg"' in html
        assert all(
            f'id="{section}"' in html
            for section in (
                "summary",
                "avz-detection",
                "entry",
                "processes",
                "impact",
                "graph",
                "timeline",
                "relations",
                "evidence",
                "gaps",
            )
        )
        assert all(
            heading in html
            for heading in (
                "Детектирование AVZ",
                "Как попало",
                "Затронутые процессы",
                "Что затронуто",
            )
        )
        assert all(basis in html for basis in ("observed", "correlated", "hypothesis"))
        html_folded = html.casefold()
        assert "<script" not in html_folded
        assert '<script src="http' not in html_folded
        assert "<script src='http" not in html_folded
        assert '<link href="http' not in html_folded
        assert "<link href='http" not in html_folded


def test_cli_smoke_runs_without_opening_the_gui() -> None:
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [sys.executable, str(ENTRYPOINT), "--smoke-test"],
        cwd=PROJECT_ROOT,
        env=environment,
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout.strip())
    assert payload["status"] == "ok"
    assert payload["case_id"] > 0
    assert payload["evidence"] >= 10
    assert payload["observations"] >= payload["evidence"]
    assert payload["relations"] >= 10
    assert len(payload["export_sha256"]) == 64


def test_html_preserves_exact_web_and_usb_source_identifiers_without_claiming_delivery(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "source-provenance.sqlite3")
    suspect_path = r"C:\Users\analyst\Downloads\payload.exe"
    case = database.create_case("Source provenance", suspect_path=suspect_path)
    run = database.start_collection_run(case.id, collector_count=1)
    observed = "2026-07-15T01:02:03+00:00"
    exact_url = "https://downloads.example.test/payload.exe?case=42&token=abc"
    pnp_device_id = r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001230101117392&0"
    device_serial = "4C530001230101117392"
    volume_serial = "A1B2-C3D4"
    volume_guid = "\\\\?\\Volume{12345678-1234-5678-9abc-def012345678}\\"
    result = CollectorResult(
        collector="source_provenance_fixture",
        started_at=observed,
        finished_at=observed,
        status="success",
        evidence=[
            EvidenceDraft(
                entity_type="file",
                label="payload.exe",
                observed_at=observed,
                source="fixture",
                stable_key="file:seed:source-test",
                source_ref=suspect_path,
                confidence="high",
                severity="critical",
                properties={"is_seed": True, "path": suspect_path},
            ),
            EvidenceDraft(
                entity_type="download_origin",
                label=exact_url,
                observed_at=observed,
                source="NTFS Zone.Identifier",
                stable_key="origin:web:source-test",
                confidence="medium",
                properties={
                    "url": exact_url,
                    "origin_role": "HostUrl",
                    "reported_by": "Zone.Identifier",
                    "mutable_metadata": True,
                    "untrusted_note": "<script>alert('must be escaped')</script>",
                },
            ),
            EvidenceDraft(
                entity_type="removable_media",
                label="SanDisk Ultra (E:)",
                observed_at=observed,
                source="Windows storage inventory",
                stable_key="removable:usb:source-test",
                confidence="medium",
                properties={
                    "drive_letter": "E:",
                    "drive_type_name": "Removable",
                    "disk_model": "SanDisk Ultra USB Device",
                    "disk_interface_type": "USB",
                    "disk_media_type": "Removable Media",
                    "disk_device_id": r"\\.\PHYSICALDRIVE2",
                    "bus_type": "USB",
                    "volume": {
                        "volume_serial_number": volume_serial,
                        "volume_guid": volume_guid,
                        "volume_label": "IR_DROP",
                    },
                    "device": {
                        "pnp_device_id": pnp_device_id,
                        "serial_number": device_serial,
                        "vid": "0781",
                        "pid": "5581",
                        "model": "Ultra",
                    },
                },
            ),
        ],
        relations=[
            RelationDraft(
                "origin:web:source-test",
                "file:seed:source-test",
                "reported_download_source",
                "medium",
                "Zone.Identifier reports the URL; it remains mutable metadata.",
                observed,
            ),
            RelationDraft(
                "removable:usb:source-test",
                "file:seed:source-test",
                "present_on_removable_media",
                "medium",
                "The file was observed on this mounted volume; historical delivery is unknown.",
                observed,
            ),
        ],
    )
    database.ingest_collector_result(case.id, run.id, result)
    database.finish_collection_run(run.id, "completed", successful_count=1)

    output = tmp_path / "source-provenance.zip"
    CaseExporter(database).export(case.id, output)

    with ZipFile(output) as archive:
        html = _bundle_bytes(archive, "report.html").decode("utf-8")
        visible_html = unescape(html)
        assert exact_url in visible_html
        assert pnp_device_id in visible_html
        assert device_serial in visible_html
        assert volume_serial in visible_html
        assert volume_guid in visible_html
        assert "USB VID" in html and "0781" in html
        assert "USB PID" in html and "5581" in html
        assert "SanDisk Ultra USB Device" in html
        assert "PHYSICALDRIVE2" in html
        assert "сами по себе не доказывают факт загрузки" in html
        assert "не доказывает историческую доставку" in html
        assert "<script" not in html.casefold()

        graph_svg = _bundle_bytes(archive, "graph.svg").decode("utf-8")
        assert graph_svg in html
        assert "<script" not in graph_svg.casefold()


def test_csv_values_are_neutralized_for_spreadsheet_formula_injection() -> None:
    assert _csv_safe("=HYPERLINK(\"https://invalid\")").startswith("'=")
    assert _csv_safe("  +cmd|calc").startswith("'  +")
    assert _csv_safe("normal evidence label") == "normal evidence label"


def test_export_does_not_delete_deterministic_neighboring_tmp_file(tmp_path: Path) -> None:
    database = Database(tmp_path / "state.sqlite3")
    case = create_demo_case(database)
    destination = tmp_path / "case.zip"
    unrelated = tmp_path / "case.zip.tmp"
    unrelated.write_text("analyst-owned", encoding="utf-8")

    CaseExporter(database).export(case.id, destination)

    assert destination.is_file()
    assert unrelated.read_text(encoding="utf-8") == "analyst-owned"


def test_export_includes_verified_raw_avz_report_but_not_preserved_binary(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "state.sqlite3")
    case = create_demo_case(database)
    avz_report = (tmp_path / "collector" / "avz-system.htm").absolute()
    avz_report.parent.mkdir()
    avz_payload = b"<html><body>original AVZ report</body></html>"
    avz_report.write_bytes(avz_payload)
    preserved = (tmp_path / "evidence-store" / "suspect.exe").absolute()
    preserved.parent.mkdir()
    preserved.write_bytes(b"preserved malware-like test bytes")

    database.add_artifact(
        case.id,
        avz_report.name,
        avz_report,
        kind="avz_report",
        sha256=sha256(avz_payload).hexdigest(),
        size_bytes=len(avz_payload),
        properties={"read_only_scan": True},
    )
    database.add_artifact(
        case.id,
        preserved.name,
        preserved,
        kind="preserved_evidence",
        sha256=sha256(preserved.read_bytes()).hexdigest(),
        size_bytes=preserved.stat().st_size,
    )

    output = tmp_path / "case.zip"
    CaseExporter(database).export(case.id, output)

    with ZipFile(output) as archive:
        names = set(archive.namelist())
        raw_path = f"{BUNDLE_ROOT}raw/avz/avz-system.htm"
        assert raw_path in names
        assert archive.read(raw_path) == avz_payload
        assert all("suspect.exe" not in name.casefold() for name in names)
        assert all("preserved" not in name.casefold() for name in names)

        case_payload = json.loads(_bundle_bytes(archive, "case.json"))
        artifacts = {item["kind"]: item for item in case_payload["artifacts"]}
        assert artifacts["avz_report"]["included_in_bundle"] is True
        assert artifacts["avz_report"]["exported_path"] == "raw/avz/avz-system.htm"
        assert artifacts["preserved_evidence"]["included_in_bundle"] is False

        manifest = json.loads(_bundle_bytes(archive, "manifest.json"))
        manifest_paths = {entry["path"] for entry in manifest["files"]}
        assert "raw/avz/avz-system.htm" in manifest_paths
        checksums = _parse_sha256sums(_bundle_bytes(archive, "SHA256SUMS.txt"))
        assert checksums["raw/avz/avz-system.htm"] == sha256(avz_payload).hexdigest()


def test_export_refuses_avz_report_when_stored_hash_does_not_match(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "state.sqlite3")
    case = create_demo_case(database)
    avz_report = (tmp_path / "avz-scan.txt").absolute()
    avz_payload = b"AVZ report that changed after registration"
    avz_report.write_bytes(avz_payload)
    database.add_artifact(
        case.id,
        avz_report.name,
        avz_report,
        kind="avz_report",
        sha256="0" * 64,
        size_bytes=len(avz_payload),
    )
    destination = tmp_path / "must-not-exist.zip"

    with pytest.raises(ValueError, match="SHA-256"):
        CaseExporter(database).export(case.id, destination)

    assert not destination.exists()
