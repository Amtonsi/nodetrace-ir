from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import os
from pathlib import Path
import stat
from threading import Event
from typing import Any, Callable, Iterable, Mapping, Protocol

from .collectors import (
    OfflineCoverageCollector,
    default_collectors,
    default_offline_collectors,
)
from .collectors.helpers import open_verified_evidence_file
from .contracts import Collector, CollectorResult, GapDraft, utc_now
from .database import Database
from .engine import CollectionEngine
from .impact import ImpactAnalyzer, ImpactAssessment
from .models import EngineRunSummary
from .preservation import EvidencePreserver, PreservedEvidence


STAGES = ("DETECT", "PRESERVE", "INVESTIGATE", "IMPACT")
PipelineProgressCallback = Callable[[dict[str, Any]], None]


class _AVZRunResult(Protocol):
    status: str
    report_paths: tuple[Path, ...]
    returncode: int | None
    timed_out: bool
    stderr: str


class _AVZRunner(Protocol):
    def run(
        self,
        output_directory: str | Path,
        *,
        scan_file: str | Path | None = None,
        scan_directory: str | Path | None = None,
    ) -> _AVZRunResult: ...


class _AVZImporter(Protocol):
    def import_report(
        self,
        source: str | Path | bytes | bytearray,
        *,
        filename: str | None = None,
        collected_at: str | None = None,
    ) -> CollectorResult: ...


class _Preserver(Protocol):
    def preserve(self, source: str | os.PathLike[str]) -> PreservedEvidence: ...


@dataclass(frozen=True, slots=True)
class PipelineStageResult:
    stage: str
    status: str
    message: str
    started_at: str
    finished_at: str
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PipelineResult:
    case_id: int
    status: str
    stages: tuple[PipelineStageResult, ...]
    triage_run_id: int | None
    investigation: EngineRunSummary | None
    preserved: PreservedEvidence | None
    impact: ImpactAssessment | None
    effective_suspect_path: str
    started_at: str
    finished_at: str

    @property
    def detection(self) -> PipelineStageResult:
        return next(item for item in self.stages if item.stage == "DETECT")

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "status": self.status,
            "stages": [item.as_dict() for item in self.stages],
            "triage_run_id": self.triage_run_id,
            "investigation_run_id": (
                self.investigation.run_id if self.investigation is not None else None
            ),
            "preserved": (
                {
                    **asdict(self.preserved),
                    "source_path": str(self.preserved.source_path),
                    "stored_path": str(self.preserved.stored_path),
                }
                if self.preserved is not None
                else None
            ),
            "impact": self.impact.as_dict() if self.impact is not None else None,
            "effective_suspect_path": self.effective_suspect_path,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


def _sha256_regular_file(path: Path) -> tuple[str, int]:
    if not path.is_absolute():
        raise OSError("generated artifact path is not absolute")
    item = path.lstat()
    attributes = int(getattr(item, "st_file_attributes", 0))
    if (
        not stat.S_ISREG(item.st_mode)
        or stat.S_ISLNK(item.st_mode)
        or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise OSError("generated artifact is not a regular non-reparse file")
    digest = sha256()
    size = 0
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
        after = os.fstat(stream.fileno())
    if (
        int(before.st_size) != size
        or int(after.st_size) != size
        or getattr(before, "st_mtime_ns", 0) != getattr(after, "st_mtime_ns", 0)
        or getattr(before, "st_ctime_ns", 0) != getattr(after, "st_ctime_ns", 0)
    ):
        raise OSError("generated artifact changed while it was hashed")
    return digest.hexdigest(), size


class IncidentPipeline:
    """Detector-first, read-only incident investigation orchestration.

    AVZ is optional but never silently skipped.  If its approved executable or
    a concrete suspect file is unavailable, an explicit coverage gap is stored
    and the built-in collectors still run.  Preservation precedes host
    investigation, and impact assessment only walks evidence already recorded.
    """

    def __init__(
        self,
        database: Database,
        *,
        artifact_root: str | Path | None = None,
        collectors: Iterable[Collector] | None = None,
        avz_executable: str | Path | None = None,
        avz_runner: _AVZRunner | None = None,
        avz_importer: _AVZImporter | None = None,
        impact_analyzer: ImpactAnalyzer | None = None,
        preserver: _Preserver | None = None,
    ) -> None:
        self.database = database
        self.artifact_root = Path(
            artifact_root if artifact_root is not None else database.path.parent / "artifacts"
        ).expanduser().absolute()
        self.collectors = list(collectors) if collectors is not None else None
        self.avz_executable = Path(avz_executable) if avz_executable else None
        self._avz_runner = avz_runner
        self._avz_importer = avz_importer
        self._impact_analyzer = impact_analyzer or ImpactAnalyzer(database)
        self._preserver = preserver

    def run(
        self,
        case_id: int,
        suspect_path: str = "",
        *,
        lookback_days: int = 30,
        options: Mapping[str, Any] | None = None,
        cancel_event: Event | None = None,
        progress_callback: PipelineProgressCallback | None = None,
        progress: PipelineProgressCallback | None = None,
    ) -> PipelineResult:
        started_at = utc_now()
        cancellation = cancel_event or Event()
        callback = progress_callback or progress
        case = self.database.get_case(case_id)
        if case is None:
            raise KeyError(f"case {case_id} does not exist")
        effective_path = str(suspect_path or case.suspect_path or "")
        pipeline_options = dict(options or {})
        target_mode = str(pipeline_options.get("target_mode") or "live").strip().casefold()
        if target_mode not in {"live", "offline"}:
            raise ValueError("target_mode must be 'live' or 'offline'")
        offline_root = str(pipeline_options.get("offline_root") or "").strip()
        if target_mode == "offline":
            if not offline_root:
                raise ValueError("offline_root is required when target_mode is offline")
            offline_root = str(Path(offline_root).expanduser().absolute())
        else:
            offline_root = ""
        pipeline_options.update(
            {
                "pipeline": "detector-first",
                "pipeline_stages": list(STAGES),
                "suspect_path": effective_path,
                "target_mode": target_mode,
                "offline_root": offline_root,
            }
        )
        triage_run = self.database.start_collection_run(
            case_id,
            collector_count=2,
            options=pipeline_options,
            started_at=started_at,
        )
        self.database.log_action(
            case_id,
            "incident_pipeline_started",
            {
                "triage_run_id": triage_run.id,
                "stages": list(STAGES),
                "suspect_path": effective_path,
                "target_mode": target_mode,
                "offline_root": offline_root,
            },
            actor="system",
        )

        stages: list[PipelineStageResult] = []
        errors: list[str] = []
        preserved: PreservedEvidence | None = None
        investigation: EngineRunSummary | None = None
        impact: ImpactAssessment | None = None

        _, detection_stage, detected_paths = self._detect(
            case_id,
            triage_run.id,
            effective_path,
            cancellation,
            callback,
            pipeline_options,
        )
        stages.append(detection_stage)
        if detection_stage.status in {"failed", "partial"}:
            errors.append(f"DETECT: {detection_stage.message}")
        if not effective_path:
            confirmed = list(dict.fromkeys(detected_paths))
            if target_mode == "offline":
                target_root = Path(offline_root).absolute()
                confirmed = [
                    value
                    for value in confirmed
                    if self._path_is_inside_target(value, target_root)
                ]
            pipeline_options["confirmed_detection_paths"] = confirmed
            if confirmed:
                # Unattended WinPE cannot stop for a file picker. AVZ report
                # order therefore selects the primary entry artifact while all
                # other confirmed detections remain in the case evidence.
                effective_path = confirmed[0]
                pipeline_options["primary_detection_path"] = effective_path
                self.database.log_action(
                    case_id,
                    "primary_detection_selected",
                    {
                        "path": effective_path,
                        "selection": "first_confirmed_avz_report_order",
                        "confirmed_detection_count": len(confirmed),
                        "target_mode": target_mode,
                    },
                    actor="system",
                )

        preserved, preservation_stage = self._preserve(
            case_id,
            triage_run.id,
            effective_path,
            cancellation,
            callback,
        )
        stages.append(preservation_stage)
        if preservation_stage.status in {"failed", "partial"}:
            errors.append(f"PRESERVE: {preservation_stage.message}")

        triage_status = self._combined_status(stages)
        successful = sum(
            item.status in {"completed", "partial"} for item in stages
        )
        failed = sum(item.status == "failed" for item in stages)
        cancelled_count = sum(item.status == "cancelled" for item in stages)
        self.database.finish_collection_run(
            triage_run.id,
            triage_status,
            successful_count=successful,
            failed_count=failed,
            cancelled_count=cancelled_count,
            error_text="\n".join(errors),
        )

        investigation, investigation_stage = self._investigate(
            case_id,
            effective_path,
            lookback_days,
            pipeline_options,
            cancellation,
            callback,
        )
        stages.append(investigation_stage)
        if investigation_stage.status in {"failed", "partial"}:
            errors.append(f"INVESTIGATE: {investigation_stage.message}")

        impact, impact_stage = self._assess_impact(
            case_id, effective_path, cancellation, callback
        )
        stages.append(impact_stage)
        if impact_stage.status in {"failed", "partial"}:
            errors.append(f"IMPACT: {impact_stage.message}")

        final_status = self._combined_status(stages)
        finished_at = utc_now()
        result = PipelineResult(
            case_id=case_id,
            status=final_status,
            stages=tuple(stages),
            triage_run_id=triage_run.id,
            investigation=investigation,
            preserved=preserved,
            impact=impact,
            effective_suspect_path=effective_path,
            started_at=started_at,
            finished_at=finished_at,
        )
        self.database.log_action(
            case_id,
            "incident_pipeline_finished",
            {
                "status": final_status,
                "triage_run_id": triage_run.id,
                "investigation_run_id": (
                    investigation.run_id if investigation is not None else None
                ),
                "stages": [item.as_dict() for item in stages],
                "preserved_sha256": preserved.sha256 if preserved is not None else "",
                "impact_counts": (
                    impact.as_dict()["counts"] if impact is not None else {}
                ),
                "errors": errors,
            },
            actor="system",
        )
        return result

    @staticmethod
    def _path_is_inside_target(value: str, target_root: Path) -> bool:
        """Reject report-supplied paths outside the mounted Windows target."""

        if not str(value or "").strip():
            return False
        try:
            candidate = Path(value).expanduser().absolute()
            candidate.relative_to(target_root)
            return candidate.is_file()
        except (OSError, ValueError):
            return False

    collect = run
    investigate = run

    def _detect(
        self,
        case_id: int,
        run_id: int,
        suspect_path: str,
        cancellation: Event,
        callback: PipelineProgressCallback | None,
        options: Mapping[str, Any],
    ) -> tuple[CollectorResult, PipelineStageResult, list[str]]:
        stage = "DETECT"
        started = utc_now()
        self._emit(callback, stage, "stage_started", "running", "AVZ detection started")
        if cancellation.is_set():
            result = self._gap_result(
                "avz_detection",
                "Pipeline cancellation was requested before detection",
                "AVZ detection evidence is unavailable",
            )
            result.status = "cancelled"
            self.database.ingest_collector_result(case_id, run_id, result)
            finished = utc_now()
            item = PipelineStageResult(stage, "cancelled", "Detection cancelled", started, finished)
            self._emit(callback, stage, "stage_finished", item.status, item.message)
            return result, item, []

        offline_mode = str(options.get("target_mode") or "live").casefold() == "offline"
        scan_directory: Path | None = None
        missing_reason = ""
        if offline_mode:
            raw_root = str(options.get("offline_root") or "").strip()
            if not raw_root:
                missing_reason = "The mounted Windows root was not supplied for AVZ file scanning"
            else:
                scan_directory = Path(raw_root).expanduser().absolute()
                try:
                    if not scan_directory.is_dir() or not (
                        scan_directory / "Windows"
                    ).is_dir():
                        missing_reason = (
                            "The configured offline root is unavailable or is not a mounted Windows volume"
                        )
                except OSError as exc:
                    missing_reason = f"The configured offline root cannot be checked: {exc}"
        elif suspect_path:
            try:
                # Availability and local-file safety are checked without
                # reading content or changing the artifact.  AVZ performs its
                # own independent validation before the scan starts.
                with open_verified_evidence_file(suspect_path):
                    pass
            except OSError as exc:
                missing_reason = f"The suspect file is unavailable or unsafe: {exc}"
        if not missing_reason and self._avz_runner is None and self.avz_executable is None:
            missing_reason = "An approved AVZ executable was not configured"
        elif not missing_reason and self._avz_runner is None and self.avz_executable is not None:
            try:
                if not self.avz_executable.is_file():
                    missing_reason = "The configured AVZ executable is unavailable"
            except OSError as exc:
                missing_reason = f"The configured AVZ executable cannot be checked: {exc}"

        if missing_reason:
            impact = (
                "The mounted Windows file tree did not receive an AVZ malware scan; "
                "offline artifact investigation will continue without an AVZ verdict"
                if offline_mode
                else "AVZ malware verdict and AVZ system evidence were not collected"
            )
            result = self._gap_result(
                "avz_detection",
                missing_reason,
                impact,
            )
            if offline_mode:
                result.gaps[0].recommendation = (
                    "Boot the matching x86 NodeTrace IR WinPE media with its verified AVZ "
                    "payload, or scan preserved files on a supported full Windows analysis host"
                )
            self.database.ingest_collector_result(case_id, run_id, result)
            finished = utc_now()
            item = PipelineStageResult(
                stage,
                "partial",
                f"{missing_reason}; built-in investigation will continue",
                started,
                finished,
                {
                    "confirmed_detections": 0,
                    "detection_count": 0,
                    "target_mode": "offline" if offline_mode else "live",
                    "avz_started": False,
                    "suspect_file_scanned": False,
                    "offline_root_scanned": False,
                },
            )
            self._emit(callback, stage, "stage_finished", item.status, item.message)
            return result, item, []

        output = (self.artifact_root / f"case-{case_id}" / f"run-{run_id}" / "avz").absolute()
        output.mkdir(parents=True, exist_ok=True)
        try:
            runner, importer = self._avz_components()
            if offline_mode:
                run_result = runner.run(output, scan_directory=scan_directory)
            else:
                run_result = runner.run(
                    output,
                    scan_file=Path(suspect_path) if suspect_path else None,
                )
            reports = self._safe_reports(run_result.report_paths, output)
            primary = self._primary_report(reports)
            if primary is None:
                result = self._gap_result(
                    "avz_detection",
                    f"AVZ finished with status {run_result.status!r} but produced no importable report",
                    "No AVZ detection verdict could be imported",
                )
            else:
                result = importer.import_report(primary, filename=primary.name)
                result.collector = "avz_detection"
                if run_result.status != "completed":
                    result.gaps.append(
                        GapDraft(
                            collector="avz_detection",
                            source="AVZ runner",
                            reason=f"AVZ process status: {run_result.status}",
                            impact="The imported report may be incomplete",
                            recommendation="Review the AVZ runner status and rerun from trusted media",
                        )
                    )
                    result.status = "partial"
            for report in reports:
                digest, size = _sha256_regular_file(report)
                self.database.add_artifact(
                    case_id,
                    report.name,
                    report,
                    run_id=run_id,
                    kind="avz_report",
                    sha256=digest,
                    size_bytes=size,
                    properties={
                        "read_only_scan": True,
                        "runner_status": run_result.status,
                        "scope": (
                            "offline_mounted_file_tree"
                            if offline_mode
                            else (
                                "selected_file_and_system"
                                if suspect_path
                                else "system_report_only"
                            )
                        ),
                        "offline_root": str(scan_directory) if scan_directory else "",
                        "live_system_inventory": not offline_mode,
                    },
                )
        except Exception as exc:
            result = self._gap_result(
                "avz_detection",
                f"AVZ detection failed safely: {type(exc).__name__}: {exc}",
                "No reliable AVZ verdict was accepted",
            )

        self.database.ingest_collector_result(case_id, run_id, result)
        detections = [item for item in result.evidence if item.entity_type == "malware_detection"]
        confirmed = [
            item
            for item in detections
            if item.properties.get("confirmed_malware") is True
        ]
        confirmed_paths = [
            str(item.properties.get("path") or "")
            for item in confirmed
            if item.properties.get("path")
        ]
        status = "partial" if result.gaps or result.status == "partial" else result.status
        status = "failed" if result.status == "failed" else status
        message = (
            f"AVZ imported {len(detections)} detection(s), "
            f"{len(confirmed)} confirmed by the scanner"
        )
        if result.gaps and not detections:
            message = result.gaps[0].reason
        finished = utc_now()
        item = PipelineStageResult(
            stage,
            status or "completed",
            message,
            started,
            finished,
            {
                "detection_count": len(detections),
                "confirmed_detections": len(confirmed),
                "confirmed_paths": confirmed_paths,
                "gap_count": len(result.gaps),
                "target_mode": "offline" if offline_mode else "live",
                "avz_started": True,
                "suspect_file_scanned": bool(suspect_path and not offline_mode),
                "offline_root_scanned": bool(scan_directory and offline_mode),
            },
        )
        self._emit(callback, stage, "stage_finished", item.status, item.message)
        return result, item, confirmed_paths

    def _preserve(
        self,
        case_id: int,
        run_id: int,
        suspect_path: str,
        cancellation: Event,
        callback: PipelineProgressCallback | None,
    ) -> tuple[PreservedEvidence | None, PipelineStageResult]:
        stage = "PRESERVE"
        started = utc_now()
        self._emit(callback, stage, "stage_started", "running", "Evidence preservation started")
        if cancellation.is_set():
            item = PipelineStageResult(stage, "cancelled", "Preservation cancelled", started, utc_now())
            self._emit(callback, stage, "stage_finished", item.status, item.message)
            return None, item
        if not suspect_path:
            result = self._gap_result(
                "preservation",
                "No single suspect file was available for preservation",
                "A byte-for-byte entry artifact was not stored",
            )
            self.database.ingest_collector_result(case_id, run_id, result)
            item = PipelineStageResult(
                stage,
                "partial",
                "No single suspect file was available; preservation was not attempted",
                started,
                utc_now(),
            )
            self._emit(callback, stage, "stage_finished", item.status, item.message)
            return None, item

        try:
            preserver = self._preserver or EvidencePreserver(
                self.artifact_root / f"case-{case_id}" / "evidence_store"
            )
            preserved = preserver.preserve(suspect_path)
            self.database.add_artifact(
                case_id,
                Path(suspect_path).name or "preserved-evidence",
                preserved.stored_path,
                run_id=run_id,
                kind="preserved_evidence",
                sha256=preserved.sha256,
                size_bytes=preserved.size_bytes,
                properties={
                    "source_path": str(preserved.source_path),
                    "content_addressed": True,
                    "copied": preserved.copied,
                },
            )
            self.database.log_action(
                case_id,
                "evidence_preserved",
                {
                    "source_path": str(preserved.source_path),
                    "stored_path": str(preserved.stored_path),
                    "sha256": preserved.sha256,
                    "size_bytes": preserved.size_bytes,
                },
                actor="system",
            )
            item = PipelineStageResult(
                stage,
                "completed",
                f"Entry artifact preserved as SHA-256 {preserved.sha256}",
                started,
                utc_now(),
                {
                    "sha256": preserved.sha256,
                    "size_bytes": preserved.size_bytes,
                    "stored_path": str(preserved.stored_path),
                    "new_copy": preserved.copied,
                },
            )
        except Exception as exc:
            result = self._gap_result(
                "preservation",
                f"Evidence preservation failed safely: {type(exc).__name__}: {exc}",
                "No verified byte-for-byte entry artifact was stored",
            )
            self.database.ingest_collector_result(case_id, run_id, result)
            preserved = None
            item = PipelineStageResult(
                stage, "failed", result.gaps[0].reason, started, utc_now()
            )
        self._emit(callback, stage, "stage_finished", item.status, item.message)
        return preserved, item

    def _investigate(
        self,
        case_id: int,
        suspect_path: str,
        lookback_days: int,
        options: Mapping[str, Any],
        cancellation: Event,
        callback: PipelineProgressCallback | None,
    ) -> tuple[EngineRunSummary | None, PipelineStageResult]:
        stage = "INVESTIGATE"
        started = utc_now()
        self._emit(callback, stage, "stage_started", "running", "Host investigation started")
        if cancellation.is_set():
            item = PipelineStageResult(stage, "cancelled", "Investigation cancelled", started, utc_now())
            self._emit(callback, stage, "stage_finished", item.status, item.message)
            return None, item

        try:
            offline_mode = str(options.get("target_mode") or "live").casefold() == "offline"
            if offline_mode:
                candidates = (
                    list(self.collectors)
                    if self.collectors is not None
                    else default_offline_collectors()
                )
                selected = [
                    collector
                    for collector in candidates
                    if bool(getattr(collector, "supports_offline", False))
                ]
                excluded = [
                    str(getattr(collector, "name", type(collector).__name__))
                    for collector in candidates
                    if not bool(getattr(collector, "supports_offline", False))
                ]
                if not any(
                    str(getattr(collector, "name", "")) == OfflineCoverageCollector.name
                    for collector in selected
                ):
                    selected.append(OfflineCoverageCollector())
                if excluded:
                    self.database.log_action(
                        case_id,
                        "offline_collectors_excluded",
                        {
                            "collectors": excluded,
                            "reason": "collector is not marked as offline-target safe",
                        },
                        actor="system",
                    )
            else:
                selected = list(self.collectors) if self.collectors is not None else default_collectors()
            engine = CollectionEngine(
                self.database, selected, artifact_root=self.artifact_root
            )

            def forward(event: dict[str, Any]) -> None:
                self._emit(
                    callback,
                    stage,
                    str(event.get("phase") or "progress"),
                    str(event.get("status") or "running"),
                    str(event.get("message") or "Host investigation"),
                    **{key: value for key, value in event.items() if key not in {"phase", "status", "message"}},
                )

            summary = engine.run(
                case_id,
                suspect_path,
                lookback_days=lookback_days,
                options={**dict(options), "pipeline_stage": stage},
                cancel_event=cancellation,
                progress_callback=forward,
            )
            status = summary.status
            message = (
                f"Built-in investigation {status}: "
                f"{sum(item.evidence_count for item in summary.outcomes)} evidence item(s) observed"
            )
            details = {
                "run_id": summary.run_id,
                "collector_count": len(summary.outcomes),
                "outcomes": [dict(item) for item in summary.outcomes],
            }
        except Exception as exc:
            summary = None
            status = "failed"
            message = f"Host investigation failed: {type(exc).__name__}: {exc}"
            details = {"error": message}
            self.database.log_action(
                case_id, "incident_pipeline_investigation_error", details, actor="system"
            )
        item = PipelineStageResult(stage, status, message, started, utc_now(), details)
        self._emit(callback, stage, "stage_finished", item.status, item.message)
        return summary, item

    def _assess_impact(
        self,
        case_id: int,
        suspect_path: str,
        cancellation: Event,
        callback: PipelineProgressCallback | None,
    ) -> tuple[ImpactAssessment | None, PipelineStageResult]:
        stage = "IMPACT"
        started = utc_now()
        self._emit(callback, stage, "stage_started", "running", "Impact correlation started")
        if cancellation.is_set():
            item = PipelineStageResult(stage, "cancelled", "Impact correlation cancelled", started, utc_now())
            self._emit(callback, stage, "stage_finished", item.status, item.message)
            return None, item
        try:
            impact = self._impact_analyzer.analyze(case_id, suspect_path)
            counts = impact.as_dict()["counts"]
            status = "completed" if impact.entry_keys and impact.complete else "partial"
            message = (
                "Impact graph classified recorded objects: "
                f"{counts['process']} process(es), {counts['file']} file(s), "
                f"{counts['persistence']} persistence object(s), "
                f"{counts['network']} network object(s)"
            )
            details = {
                "counts": counts,
                "basis_counts": impact.as_dict()["basis_counts"],
                "complete": impact.complete,
                "limitations": list(impact.limitations),
            }
        except Exception as exc:
            impact = None
            status = "failed"
            message = f"Impact correlation failed: {type(exc).__name__}: {exc}"
            details = {"error": message}
        item = PipelineStageResult(stage, status, message, started, utc_now(), details)
        self._emit(callback, stage, "stage_finished", item.status, item.message)
        return impact, item

    def _avz_components(self) -> tuple[_AVZRunner, _AVZImporter]:
        runner = self._avz_runner
        importer = self._avz_importer
        if runner is None or importer is None:
            # AVZ support is intentionally optional at import time so the core
            # incident workflow remains usable when the integration package or
            # approved binary is absent.
            from .avz import AVZImporter, AVZRunner

            if runner is None:
                if self.avz_executable is None:
                    raise RuntimeError("AVZ executable is not configured")
                runner = AVZRunner(self.avz_executable)
            if importer is None:
                importer = AVZImporter()
        return runner, importer

    @staticmethod
    def _safe_reports(paths: Iterable[Path], output_directory: Path) -> list[Path]:
        root = output_directory.resolve(strict=True)
        accepted: list[Path] = []
        for candidate in paths:
            path = Path(candidate)
            try:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root):
                    continue
                _sha256_regular_file(resolved)
            except (OSError, ValueError):
                continue
            accepted.append(resolved)
        return accepted

    @staticmethod
    def _primary_report(reports: Iterable[Path]) -> Path | None:
        candidates = list(reports)
        for suffix in (".xml", ".log", ".txt"):
            for path in candidates:
                if path.suffix.casefold() == suffix:
                    return path
        return None

    @staticmethod
    def _gap_result(collector: str, reason: str, impact: str) -> CollectorResult:
        now = utc_now()
        return CollectorResult(
            collector=collector,
            started_at=now,
            finished_at=now,
            status="partial",
            gaps=[
                GapDraft(
                    collector=collector,
                    source="AVZ" if collector.startswith("avz") else collector,
                    reason=reason,
                    impact=impact,
                    recommendation=(
                        "Select a local suspect file and configure a verified AVZ binary from trusted media, then rerun"
                        if collector.startswith("avz")
                        else "Preserve a stable local regular-file copy and rerun"
                    ),
                )
            ],
        )

    @staticmethod
    def _combined_status(stages: Iterable[PipelineStageResult]) -> str:
        statuses = [item.status for item in stages]
        if any(status == "cancelled" for status in statuses):
            return "cancelled" if all(status == "cancelled" for status in statuses) else "partial"
        if any(status == "failed" for status in statuses):
            return "failed" if all(status == "failed" for status in statuses) else "partial"
        if any(status in {"partial", "skipped"} for status in statuses):
            return "partial"
        return "completed"

    @staticmethod
    def _emit(
        callback: PipelineProgressCallback | None,
        stage: str,
        phase: str,
        status: str,
        message: str,
        **details: Any,
    ) -> None:
        if callback is None:
            return
        event = {
            "stage": stage,
            "stage_index": STAGES.index(stage) + 1,
            "total_stages": len(STAGES),
            "phase": phase,
            "status": status,
            "message": message,
            **details,
        }
        callback(event)


DetectorFirstPipeline = IncidentPipeline


def run_incident_pipeline(
    database: Database,
    case_id: int,
    suspect_path: str = "",
    **kwargs: Any,
) -> PipelineResult:
    constructor_names = {
        "artifact_root",
        "collectors",
        "avz_executable",
        "avz_runner",
        "avz_importer",
        "impact_analyzer",
        "preserver",
    }
    constructor: dict[str, Any] = {}
    run_options: dict[str, Any] = {}
    for key, value in kwargs.items():
        (constructor if key in constructor_names else run_options)[key] = value
    return IncidentPipeline(database, **constructor).run(
        case_id, suspect_path, **run_options
    )


__all__ = [
    "DetectorFirstPipeline",
    "IncidentPipeline",
    "PipelineResult",
    "PipelineStageResult",
    "STAGES",
    "run_incident_pipeline",
]
