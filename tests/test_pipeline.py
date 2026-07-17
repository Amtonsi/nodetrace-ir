from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from nodetrace_ir.contracts import (
    CollectorResult,
    EvidenceDraft,
    RelationDraft,
    utc_now,
)
from nodetrace_ir.database import Database
from nodetrace_ir.pipeline import IncidentPipeline, STAGES


class FixtureCollector:
    name = "fixture_investigation"
    display_name = "Fixture investigation"

    def collect(self, context):
        now = utc_now()
        seed = "file:seed"
        process = "process:seed"
        changed_file = "file:changed"
        persistence = "registry:persistence"
        endpoint = "ip:203.0.113.20:443"
        origin = "origin:fixture"
        unrelated = "process:unrelated"
        return CollectorResult(
            collector=self.name,
            started_at=now,
            finished_at=now,
            status="completed",
            evidence=[
                EvidenceDraft(
                    "download_origin", "https://mail.example.test/item/7", now, "fixture", origin,
                    properties={"url": "https://mail.example.test/item/7"},
                ),
                EvidenceDraft(
                    "file",
                    Path(context.suspect_path).name,
                    now,
                    "fixture",
                    seed,
                    context.suspect_path,
                    "high",
                    "high",
                    {"path": context.suspect_path, "is_seed": True},
                ),
                EvidenceDraft(
                    "process", "suspect.exe", now, "fixture", process,
                    properties={"pid": 101, "image": context.suspect_path},
                ),
                EvidenceDraft(
                    "file", "created.dat", now, "fixture", changed_file,
                    properties={"path": r"C:\Temp\created.dat", "event_action": "created"},
                ),
                EvidenceDraft(
                    "registry", "Run value", now, "fixture", persistence,
                    properties={"target": r"HKCU\Software\...\Run"},
                ),
                EvidenceDraft(
                    "ip", "203.0.113.20:443", now, "fixture", endpoint,
                    properties={"ip": "203.0.113.20", "port": 443},
                ),
                EvidenceDraft(
                    "process", "unrelated.exe", now, "fixture", unrelated,
                    properties={"pid": 202},
                ),
            ],
            relations=[
                RelationDraft(
                    origin,
                    seed,
                    "reported_download_source",
                    "medium",
                    "Zone.Identifier reports the source; mutable metadata",
                ),
                RelationDraft(seed, process, "executed_as", "high", "direct event"),
                RelationDraft(process, changed_file, "created", "high", "direct event"),
                RelationDraft(
                    process,
                    persistence,
                    "possible_persistence_reference",
                    "medium",
                    "string/path correlation only",
                ),
                RelationDraft(process, endpoint, "connected_to", "high", "direct event"),
                # Another process sharing an endpoint must not be pulled into
                # the entry artifact's forward impact chain.
                RelationDraft(unrelated, endpoint, "connected_to", "high", "direct event"),
            ],
        )


@dataclass
class FakeAVZRunner:
    scanned: Path | None = None
    scanned_directory: Path | None = None
    calls: int = 0

    def run(
        self,
        output_directory: str | Path,
        *,
        scan_file: str | Path | None = None,
        scan_directory: str | Path | None = None,
    ):
        self.calls += 1
        self.scanned = Path(scan_file) if scan_file is not None else None
        self.scanned_directory = (
            Path(scan_directory) if scan_directory is not None else None
        )
        output = Path(output_directory)
        report = output / "avz_scan.log"
        report.write_text("fixture AVZ report", encoding="utf-8")
        return SimpleNamespace(
            status="completed",
            report_paths=(report,),
            returncode=0,
            timed_out=False,
            stderr="",
        )


class FakeAVZImporter:
    def import_report(self, source, *, filename=None, collected_at=None):
        now = utc_now()
        return CollectorResult(
            collector="avz_import",
            started_at=now,
            finished_at=now,
            status="completed",
            evidence=[
                EvidenceDraft(
                    "malware_detection",
                    "AVZ: Test.Malware",
                    now,
                    "AVZ",
                    "detection:avz:test",
                    confidence="high",
                    severity="high",
                    properties={
                        "confirmed_malware": True,
                        "verdict": "malware",
                        "path": "",
                    },
                )
            ],
        )


def test_detector_first_pipeline_runs_all_stages_and_preserves_evidence(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "cases.sqlite3")
    suspect = tmp_path / "suspect.exe"
    suspect.write_bytes(b"not executable test evidence")
    case = database.create_case("Pipeline", suspect_path=str(suspect))
    runner = FakeAVZRunner()
    events: list[dict[str, object]] = []

    result = IncidentPipeline(
        database,
        artifact_root=tmp_path / "artifacts",
        collectors=[FixtureCollector()],
        avz_runner=runner,
        avz_importer=FakeAVZImporter(),
    ).run(case.id, progress_callback=events.append)

    assert [item.stage for item in result.stages] == list(STAGES)
    assert result.status == "completed"
    assert runner.scanned == suspect
    assert result.preserved is not None
    assert result.preserved.stored_path.is_file()
    assert result.preserved.stored_path.parent.name == "sha256"
    assert result.investigation is not None
    assert result.investigation.status == "completed"
    assert result.impact is not None
    assert {item.label for item in result.impact.findings if item.category == "source"} == {
        "https://mail.example.test/item/7"
    }
    assert {item.label for item in result.impact.affected_processes} == {"suspect.exe"}
    assert {item.label for item in result.impact.affected_files} == {"created.dat"}
    assert result.impact.persistence[0].basis == "hypothesis"
    assert len(result.impact.network_activity) == 1
    assert all(
        "unrelated.exe" != item.label for item in result.impact.findings
    )
    assert [event["stage"] for event in events if event["phase"] == "stage_started"] == list(
        STAGES
    )
    assert {item.kind for item in database.list_artifacts(case.id)} >= {
        "avz_report",
        "preserved_evidence",
    }
    assert database.list_analyst_log(case.id)[-1].action == "incident_pipeline_finished"


def test_pipeline_records_explicit_avz_gap_and_continues_collectors(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "cases.sqlite3")
    suspect = tmp_path / "suspect.exe"
    suspect.write_bytes(b"evidence")
    case = database.create_case("No AVZ", suspect_path=str(suspect))

    result = IncidentPipeline(
        database,
        artifact_root=tmp_path / "artifacts",
        collectors=[FixtureCollector()],
    ).run(case.id)

    assert result.detection.status == "partial"
    assert "not configured" in result.detection.message
    assert result.investigation is not None
    assert result.investigation.status == "completed"
    assert result.preserved is not None
    avz_gaps = [item for item in database.list_gaps(case.id) if item.collector == "avz_detection"]
    assert len(avz_gaps) == 1
    assert "not configured" in avz_gaps[0].reason
    assert result.status == "partial"


def test_pipeline_can_start_system_triage_without_a_selected_file(tmp_path: Path) -> None:
    database = Database(tmp_path / "cases.sqlite3")
    case = database.create_case("Automatic host triage")
    runner = FakeAVZRunner()

    result = IncidentPipeline(
        database,
        artifact_root=tmp_path / "artifacts",
        collectors=[],
        avz_runner=runner,
        avz_importer=FakeAVZImporter(),
    ).run(case.id)

    assert runner.calls == 1
    assert runner.scanned is None
    assert result.detection.status == "completed"
    assert result.preserved is None
    assert result.impact is not None


def test_offline_pipeline_runs_avz_file_tree_scan_before_investigation(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "cases.sqlite3")
    mounted = tmp_path / "mounted"
    (mounted / "Windows").mkdir(parents=True)
    case = database.create_case(
        "Offline AVZ",
        properties={"target_mode": "offline", "offline_root": str(mounted)},
    )
    runner = FakeAVZRunner()

    result = IncidentPipeline(
        database,
        artifact_root=tmp_path / "artifacts",
        collectors=[],
        avz_runner=runner,
        avz_importer=FakeAVZImporter(),
    ).run(
        case.id,
        options={"target_mode": "offline", "offline_root": str(mounted)},
    )

    assert runner.calls == 1
    assert runner.scanned is None
    assert runner.scanned_directory == mounted.absolute()
    assert result.detection.details["avz_started"] is True
    assert result.detection.details["offline_root_scanned"] is True
    assert result.detection.details["suspect_file_scanned"] is False


def test_unattended_offline_pipeline_selects_first_in_target_detection(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "cases.sqlite3")
    mounted = tmp_path / "mounted"
    (mounted / "Windows").mkdir(parents=True)
    first = mounted / "Users" / "alice" / "Downloads" / "first.exe"
    second = mounted / "Temp" / "second.exe"
    outside = tmp_path / "outside.exe"
    for path in (first, second, outside):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(path.name.encode("ascii"))
    case = database.create_case("Automatic offline primary detection")

    class MultipleDetectionImporter:
        def import_report(self, source, *, filename=None, collected_at=None):
            now = utc_now()
            paths = (str(outside), str(first), str(second))
            return CollectorResult(
                collector="avz_import",
                started_at=now,
                finished_at=now,
                status="completed",
                evidence=[
                    EvidenceDraft(
                        "malware_detection",
                        f"AVZ: Test.Malware.{index}",
                        now,
                        "AVZ",
                        f"detection:avz:{index}",
                        confidence="high",
                        severity="high",
                        properties={
                            "confirmed_malware": True,
                            "verdict": "malware",
                            "path": path,
                        },
                    )
                    for index, path in enumerate(paths)
                ],
            )

    result = IncidentPipeline(
        database,
        artifact_root=tmp_path / "artifacts",
        collectors=[],
        avz_runner=FakeAVZRunner(),
        avz_importer=MultipleDetectionImporter(),
    ).run(
        case.id,
        options={"target_mode": "offline", "offline_root": str(mounted)},
    )

    assert result.effective_suspect_path == str(first)
    assert result.preserved is not None
    selection = next(
        item
        for item in database.list_analyst_log(case.id)
        if item.action == "primary_detection_selected"
    )
    assert selection.details["path"] == str(first)
    assert selection.details["confirmed_detection_count"] == 2


def test_pipeline_does_not_call_avz_for_an_unavailable_suspect_path(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "cases.sqlite3")
    missing = tmp_path / "missing.exe"
    case = database.create_case("Missing sample", suspect_path=str(missing))
    runner = FakeAVZRunner()

    result = IncidentPipeline(
        database,
        artifact_root=tmp_path / "artifacts",
        collectors=[],
        avz_runner=runner,
        avz_importer=FakeAVZImporter(),
    ).run(case.id)

    assert runner.scanned is None
    assert result.detection.status == "partial"
    assert "unavailable or unsafe" in result.detection.message
    assert result.preserved is None
    assert database.list_gaps(case.id)


def test_impact_output_separates_evidence_basis_and_disclaims_overclaiming(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "cases.sqlite3")
    suspect = tmp_path / "suspect.exe"
    suspect.write_bytes(b"evidence")
    case = database.create_case("Conservative impact", suspect_path=str(suspect))
    pipeline = IncidentPipeline(
        database,
        artifact_root=tmp_path / "artifacts",
        collectors=[FixtureCollector()],
    )

    result = pipeline.run(case.id)

    assert result.impact is not None
    bases = {item.basis for item in result.impact.findings}
    assert bases >= {"observed", "hypothesis"}
    assert any("not proof" in value.casefold() for value in result.impact.limitations)
    assert all("exfiltrat" not in item.rationale.casefold() for item in result.impact.findings)
    assert all("quantify harm" in item.rationale.casefold() for item in result.impact.findings if item.depth)
