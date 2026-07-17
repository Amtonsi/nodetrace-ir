from __future__ import annotations

import inspect
import os
from pathlib import Path
import sys
from threading import Event
import traceback
from typing import Any, Callable, Iterable, Mapping, Sequence

from .contracts import (
    CollectionContext,
    Collector,
    CollectorResult,
    EvidenceDraft,
    GapDraft,
    RelationDraft,
    utc_now,
)
from .database import Database
from .models import CollectorOutcome, EngineRunSummary


ProgressCallback = Callable[..., None]


class CollectionEngine:
    """Run evidence collectors with per-collector failure isolation."""

    def __init__(
        self,
        database: Database,
        collectors: Iterable[Collector] | str | Path | None = None,
        artifact_root: str | Path | None = None,
    ) -> None:
        self.database = database
        if isinstance(collectors, (str, Path)) and artifact_root is None:
            artifact_root = collectors
            collectors = None
        self.collectors = list(collectors or [])
        default_root = database.path.parent / "artifacts"
        self.artifact_root = Path(artifact_root) if artifact_root is not None else default_root

    def run(
        self,
        case_id: int,
        suspect_path: str = "",
        *,
        collectors: Iterable[Collector] | None = None,
        lookback_days: int = 30,
        options: Mapping[str, Any] | None = None,
        cancel_event: Event | None = None,
        progress_callback: ProgressCallback | None = None,
        progress: ProgressCallback | None = None,
    ) -> EngineRunSummary:
        selected = list(self.collectors if collectors is None else collectors)
        cancellation = cancel_event or Event()
        callback = progress_callback or progress
        run_options = dict(options or {})
        run_options.setdefault("lookback_days", max(0, int(lookback_days)))
        collection_cutoff = utc_now()
        run_options.setdefault("collection_cutoff_utc", collection_cutoff)
        run_options.setdefault("collector_pid", os.getpid())
        run_options.setdefault("collector_executable", str(Path(sys.executable).resolve(strict=False)))
        if suspect_path:
            run_options.setdefault("suspect_path", suspect_path)

        run = self.database.start_collection_run(
            case_id,
            collector_count=len(selected),
            options=run_options,
            started_at=collection_cutoff,
        )
        artifact_dir = self.artifact_root / f"case-{case_id}" / f"run-{run.id}"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        self.database.log_action(
            case_id,
            "collection_started",
            {
                "run_id": run.id,
                "collector_count": len(selected),
                "collection_cutoff_utc": collection_cutoff,
                "collector_pid": os.getpid(),
                "collector_executable": run_options["collector_executable"],
            },
            actor="system",
        )

        outcomes: list[CollectorOutcome] = []
        successful = 0
        failed = 0
        cancelled = 0
        had_partial = False
        errors: list[str] = []
        self._emit_progress(
            callback,
            phase="run_started",
            collector="",
            completed=0,
            total=len(selected),
            status="running",
            message="Collection started",
            run_id=run.id,
        )

        for index, collector in enumerate(selected):
            name = self._collector_name(collector, index)
            if cancellation.is_set():
                remaining = len(selected) - index
                cancelled += remaining
                for skipped in selected[index:]:
                    skipped_name = self._collector_name(skipped, len(outcomes))
                    outcomes.append(CollectorOutcome(collector=skipped_name, status="cancelled"))
                self._emit_progress(
                    callback,
                    phase="cancelled",
                    collector=name,
                    completed=index,
                    total=len(selected),
                    status="cancelled",
                    message="Collection cancelled",
                    run_id=run.id,
                )
                break

            self._emit_progress(
                callback,
                phase="collector_started",
                collector=name,
                completed=index,
                total=len(selected),
                status="running",
                message=f"Running {name}",
                run_id=run.id,
            )
            collector_started = utc_now()
            context = CollectionContext(
                case_id=case_id,
                suspect_path=suspect_path,
                started_at=run.started_at,
                lookback_days=max(0, int(lookback_days)),
                artifact_dir=artifact_dir / self._safe_component(name),
                cancel_event=cancellation,
                options=dict(run_options),
            )
            context.artifact_dir.mkdir(parents=True, exist_ok=True)

            error = ""
            try:
                result = collector.collect(context)
                if not isinstance(result, CollectorResult):
                    raise TypeError(
                        f"collector {name!r} returned {type(result).__name__}, expected CollectorResult"
                    )
                if not result.collector:
                    result.collector = name
                if not result.started_at:
                    result.started_at = collector_started
                if not result.finished_at:
                    result.finished_at = utc_now()
                if not result.status:
                    result.status = "completed"
                for draft in result.evidence:
                    if draft.entity_type == "file" and draft.properties.get("is_seed"):
                        run_options["seed_key"] = draft.key()
                        if draft.properties.get("sha256"):
                            run_options["seed_sha256"] = draft.properties["sha256"]
                        break
            except Exception as exc:  # collector isolation is an explicit engine guarantee
                error = f"{type(exc).__name__}: {exc}"
                errors.append(f"{name}: {error}")
                result = CollectorResult(
                    collector=name,
                    started_at=collector_started,
                    finished_at=utc_now(),
                    status="failed",
                    gaps=[
                        GapDraft(
                            collector=name,
                            source=name,
                            reason=error,
                            impact="This evidence source was not collected; conclusions may be incomplete.",
                            recommendation="Review permissions and collector prerequisites, then rerun collection.",
                        )
                    ],
                    raw_payload={
                        "error": error,
                        "traceback": traceback.format_exc(),
                    },
                )

            try:
                self.database.ingest_collector_result(case_id, run.id, result)
            except Exception as exc:
                ingest_error = f"database ingest failed: {type(exc).__name__}: {exc}"
                error = f"{error}; {ingest_error}" if error else ingest_error
                errors.append(f"{name}: {ingest_error}")
                result.status = "failed"

            normalized_status = result.status.lower().strip()
            if cancellation.is_set() and normalized_status in {"cancelled", "canceled"}:
                cancelled += 1
                outcome_status = "cancelled"
            elif normalized_status in {"failed", "error"} or error:
                failed += 1
                outcome_status = "failed"
            else:
                successful += 1
                outcome_status = normalized_status or "completed"
                if normalized_status == "partial" or result.gaps:
                    had_partial = True

            outcome = CollectorOutcome(
                collector=name,
                status=outcome_status,
                evidence_count=len(result.evidence),
                relation_count=len(result.relations),
                gap_count=len(result.gaps),
                error=error,
            )
            outcomes.append(outcome)
            self._emit_progress(
                callback,
                phase="collector_finished",
                collector=name,
                completed=index + 1,
                total=len(selected),
                status=outcome_status,
                message=f"{name}: {outcome_status}",
                run_id=run.id,
            )

        if cancelled:
            final_status = "cancelled" if successful == 0 and failed == 0 else "partial"
        elif failed:
            final_status = "failed" if successful == 0 else "partial"
        elif had_partial:
            final_status = "partial"
        else:
            final_status = "completed"

        finished = self.database.finish_collection_run(
            run.id,
            final_status,
            successful_count=successful,
            failed_count=failed,
            cancelled_count=cancelled,
            error_text="\n".join(errors),
        )
        self.database.log_action(
            case_id,
            "collection_finished",
            {
                "run_id": run.id,
                "status": final_status,
                "successful_count": successful,
                "failed_count": failed,
                "cancelled_count": cancelled,
            },
            actor="system",
        )
        self._emit_progress(
            callback,
            phase="run_finished",
            collector="",
            completed=min(len(outcomes), len(selected)),
            total=len(selected),
            status=final_status,
            message=f"Collection {final_status}",
            run_id=run.id,
        )
        return EngineRunSummary(run=finished, outcomes=tuple(outcomes))

    collect = run
    run_collectors = run
    run_case = run

    @staticmethod
    def _collector_name(collector: Collector, index: int) -> str:
        value = getattr(collector, "name", "") or getattr(collector, "display_name", "")
        return str(value or f"collector-{index + 1}")

    @staticmethod
    def _safe_component(value: str) -> str:
        cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
        return cleaned.strip("._") or "collector"

    @staticmethod
    def _emit_progress(callback: ProgressCallback | None, **event: Any) -> None:
        if callback is None:
            return
        try:
            signature = inspect.signature(callback)
            positional = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind
                in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
            ]
            has_varargs = any(
                parameter.kind == parameter.VAR_POSITIONAL
                for parameter in signature.parameters.values()
            )
        except (TypeError, ValueError):
            callback(event)
            return

        if has_varargs or len(positional) >= 4:
            callback(
                event["completed"], event["total"], event["message"], event["status"]
            )
        elif len(positional) == 3:
            callback(event["completed"], event["total"], event["message"])
        elif len(positional) == 2:
            callback(event["completed"], event["total"])
        elif len(positional) == 0:
            callback()
        else:
            callback(event)


def generate_demo_collector_result(timestamp: str | None = None) -> CollectorResult:
    """Build deterministic-looking evidence for first-launch exploration."""
    observed = timestamp or utc_now()
    suspect_key = "file:demo-suspect"
    process_key = "process:demo-powershell"
    persistence_key = "registry:demo-run-key"
    return CollectorResult(
        collector="demo",
        started_at=observed,
        finished_at=observed,
        status="completed",
        evidence=[
            EvidenceDraft(
                entity_type="file",
                label=r"C:\Users\Public\invoice_viewer.exe",
                observed_at=observed,
                source="demo filesystem snapshot",
                stable_key=suspect_key,
                confidence="high",
                severity="critical",
                properties={
                    "sha256": "55d77344d72cc655510728e066ccfe02f21b4da37954fa20c2c1e2e9d6d1f287",
                    "signed": False,
                    "first_seen": observed,
                },
                raw={"demo": True, "size": 184320},
            ),
            EvidenceDraft(
                entity_type="process",
                label="powershell.exe -EncodedCommand ...",
                observed_at=observed,
                source="demo process telemetry",
                stable_key=process_key,
                confidence="high",
                severity="high",
                properties={"pid": 4816, "parent_pid": 3320, "user": "WORKSTATION\\analyst"},
                raw={"demo": True},
            ),
            EvidenceDraft(
                entity_type="registry",
                label=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                observed_at=observed,
                source="demo registry snapshot",
                stable_key=persistence_key,
                confidence="medium",
                severity="high",
                properties={"value": r"C:\Users\Public\invoice_viewer.exe --silent"},
                raw={"demo": True},
            ),
        ],
        relations=[
            RelationDraft(
                source_key=suspect_key,
                target_key=process_key,
                relation_type="spawned",
                confidence="high",
                rationale="The suspicious executable launched PowerShell in the demo timeline.",
                observed_at=observed,
            ),
            RelationDraft(
                source_key=process_key,
                target_key=persistence_key,
                relation_type="modified",
                confidence="medium",
                rationale="The process wrote a Run key for persistence.",
                observed_at=observed,
            ),
        ],
        gaps=[
            GapDraft(
                collector="demo",
                source="EDR telemetry",
                reason="EDR integration is not configured in demo mode.",
                impact="Process ancestry is illustrative rather than independently corroborated.",
                recommendation="Import an EDR export or run live collectors for a real case.",
            )
        ],
        raw_payload={"demo": True},
    )


def create_demo_case(database: Database) -> int:
    """Create and populate a self-contained case; return its database id."""
    case = database.create_case(
        "Demo: suspicious invoice execution",
        suspect_path=r"C:\Users\Public\invoice_viewer.exe",
        description="Synthetic case for learning the evidence timeline and relationship graph.",
        hostname="DEMO-WORKSTATION",
        properties={"demo": True},
    )
    result = generate_demo_collector_result()
    run = database.start_collection_run(case.id, collector_count=1, options={"demo": True})
    database.ingest_collector_result(case.id, run.id, result)
    database.finish_collection_run(run.id, "completed", successful_count=1)
    database.log_action(case.id, "demo_case_created", {"run_id": run.id}, actor="system")
    return case.id


# Alternate naming used by the desktop shell.
Engine = CollectionEngine
seed_demo_case = create_demo_case


def run_collection(
    database: Database,
    case_id: int,
    collectors: Iterable[Collector],
    suspect_path: str = "",
    **kwargs: Any,
) -> EngineRunSummary:
    """Functional wrapper for callers that do not need a reusable engine."""
    return CollectionEngine(database, collectors).run(case_id, suspect_path, **kwargs)
