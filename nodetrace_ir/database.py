from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Iterator, Mapping, Sequence

from .contracts import CollectorResult, canonical_json, canonical_sha256, utc_now
from .models import (
    AnalystLogRecord,
    ArtifactRecord,
    CaseRecord,
    CollectionRunRecord,
    CoverageGapRecord,
    EvidenceRecord,
    IngestStats,
    ObservationRecord,
    RelationRecord,
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    suspect_path TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    properties_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'running',
    collector_count INTEGER NOT NULL DEFAULT 0,
    successful_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    cancelled_count INTEGER NOT NULL DEFAULT 0,
    options_json TEXT NOT NULL DEFAULT '{}',
    error_text TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id INTEGER REFERENCES collection_runs(id) ON DELETE SET NULL,
    collector TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    label TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    stable_key TEXT NOT NULL,
    source_ref TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'medium',
    severity TEXT NOT NULL DEFAULT 'info',
    properties_json TEXT NOT NULL DEFAULT '{}',
    raw_json TEXT NOT NULL DEFAULT '{}',
    evidence_digest TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(case_id, stable_key)
);

CREATE TABLE IF NOT EXISTS evidence_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id INTEGER REFERENCES collection_runs(id) ON DELETE SET NULL,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    label TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    source_ref TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'medium',
    severity TEXT NOT NULL DEFAULT 'info',
    properties_json TEXT NOT NULL DEFAULT '{}',
    raw_json TEXT NOT NULL DEFAULT '{}',
    evidence_digest TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    UNIQUE(run_id, evidence_digest)
);

CREATE TABLE IF NOT EXISTS relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id INTEGER REFERENCES collection_runs(id) ON DELETE SET NULL,
    collector TEXT NOT NULL,
    source_key TEXT NOT NULL,
    target_key TEXT NOT NULL,
    source_evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    target_evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    relation_type TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    rationale TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(case_id, source_key, target_key, relation_type)
);

CREATE TABLE IF NOT EXISTS coverage_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id INTEGER REFERENCES collection_runs(id) ON DELETE SET NULL,
    collector TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT NOT NULL,
    impact TEXT NOT NULL,
    recommendation TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id INTEGER REFERENCES collection_runs(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'file',
    sha256 TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    properties_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS analyst_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'analyst',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_case ON collection_runs(case_id, id);
CREATE INDEX IF NOT EXISTS idx_evidence_case_time ON evidence(case_id, observed_at, id);
CREATE INDEX IF NOT EXISTS idx_evidence_case_type ON evidence(case_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_observations_case_time
    ON evidence_observations(case_id, observed_at, id);
CREATE INDEX IF NOT EXISTS idx_observations_evidence
    ON evidence_observations(evidence_id, id);
CREATE INDEX IF NOT EXISTS idx_observations_run
    ON evidence_observations(run_id, id);
CREATE INDEX IF NOT EXISTS idx_relations_case ON relations(case_id, id);
CREATE INDEX IF NOT EXISTS idx_gaps_case ON coverage_gaps(case_id, id);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id, id);
CREATE INDEX IF NOT EXISTS idx_log_case ON analyst_log(case_id, id);
"""


def _json_loads(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return {"_unparsed": value}
    return decoded if isinstance(decoded, dict) else {"value": decoded}


class Database:
    """SQLite-backed incident case store.

    Connections are intentionally short lived. Every public operation opens its
    own connection and closes it in ``finally`` so packaged GUI applications do
    not retain database file locks between actions.
    """

    def __init__(self, path: str | Path) -> None:
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        if str(path) == ":memory:":
            # Short-lived connections cannot share SQLite's ordinary :memory:
            # database. A private temporary file preserves ephemeral semantics
            # while still letting every operation close its connection.
            self._temporary_directory = tempfile.TemporaryDirectory(prefix="nodetrace_ir_")
            self.path = Path(self._temporary_directory.name) / "memory.sqlite3"
        else:
            self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()
        self.recover_interrupted_runs()

    def close(self) -> None:
        temporary = self._temporary_directory
        if temporary is not None:
            self._temporary_directory = None
            temporary.cleanup()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)
            connection.commit()

    def recover_interrupted_runs(self, *, interrupted_at: str | None = None) -> int:
        """Finalize runs left active by an earlier unclean process exit."""
        timestamp = interrupted_at or utc_now()
        recovery_message = "Collection interrupted before the previous process exited."
        with self._connect() as connection:
            stale_rows = connection.execute(
                "SELECT id, case_id FROM collection_runs WHERE status = 'running'"
            ).fetchall()
            if not stale_rows:
                return 0
            connection.execute(
                """
                UPDATE cases SET updated_at = ?
                WHERE id IN (
                    SELECT DISTINCT case_id FROM collection_runs
                    WHERE status = 'running'
                )
                """,
                (timestamp,),
            )
            connection.execute(
                """
                UPDATE collection_runs SET
                    finished_at = ?,
                    status = 'interrupted',
                    error_text = CASE
                        WHEN error_text = '' THEN ?
                        ELSE error_text || char(10) || ?
                    END
                WHERE status = 'running'
                """,
                (timestamp, recovery_message, recovery_message),
            )
            connection.commit()
        return len(stale_rows)

    def create_case(
        self,
        title: str = "",
        suspect_path: str = "",
        description: str = "",
        hostname: str = "",
        status: str = "open",
        properties: Mapping[str, Any] | None = None,
        *,
        created_at: str | None = None,
        name: str = "",
    ) -> CaseRecord:
        title = str(title or name).strip()
        if not title:
            raise ValueError("case title must not be empty")
        timestamp = created_at or utc_now()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO cases
                    (title, description, status, suspect_path, hostname,
                     created_at, updated_at, properties_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    title,
                    description,
                    status,
                    suspect_path,
                    hostname,
                    timestamp,
                    timestamp,
                    canonical_json(dict(properties or {})),
                ),
            )
            case_id = int(cursor.lastrowid)
            connection.commit()
            row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        assert row is not None
        return self._case_from_row(row)

    def get_case(self, case_id: int) -> CaseRecord | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        return self._case_from_row(row) if row is not None else None

    def list_cases(
        self,
        status: str | None = None,
        *,
        limit: int | None = None,
    ) -> list[CaseRecord]:
        query = "SELECT * FROM cases"
        parameters: list[Any] = []
        if status:
            query += " WHERE status = ?"
            parameters.append(status)
        query += " ORDER BY updated_at DESC, id DESC"
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(max(0, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._case_from_row(row) for row in rows]

    def update_case_status(self, case_id: int, status: str) -> CaseRecord:
        status = str(status).strip()
        if not status:
            raise ValueError("case status must not be empty")
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
                (status, utc_now(), case_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"case {case_id} does not exist")
            connection.commit()
            row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        assert row is not None
        return self._case_from_row(row)

    def start_collection_run(
        self,
        case_id: int,
        collector_count: int = 0,
        options: Mapping[str, Any] | None = None,
        *,
        started_at: str | None = None,
    ) -> CollectionRunRecord:
        timestamp = started_at or utc_now()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO collection_runs
                    (case_id, started_at, status, collector_count, options_json)
                VALUES (?, ?, 'running', ?, ?)
                """,
                (case_id, timestamp, max(0, int(collector_count)), canonical_json(dict(options or {}))),
            )
            run_id = int(cursor.lastrowid)
            connection.execute(
                "UPDATE cases SET updated_at = ? WHERE id = ?", (timestamp, case_id)
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM collection_runs WHERE id = ?", (run_id,)
            ).fetchone()
        assert row is not None
        return self._run_from_row(row)

    def finish_collection_run(
        self,
        run_id: int,
        status: str,
        successful_count: int = 0,
        failed_count: int = 0,
        cancelled_count: int = 0,
        *,
        finished_at: str | None = None,
        error_text: str = "",
    ) -> CollectionRunRecord:
        timestamp = finished_at or utc_now()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE collection_runs
                SET finished_at = ?, status = ?, successful_count = ?,
                    failed_count = ?, cancelled_count = ?, error_text = ?
                WHERE id = ?
                """,
                (
                    timestamp,
                    status,
                    max(0, int(successful_count)),
                    max(0, int(failed_count)),
                    max(0, int(cancelled_count)),
                    error_text,
                    run_id,
                ),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"collection run {run_id} does not exist")
            row = connection.execute(
                "SELECT * FROM collection_runs WHERE id = ?", (run_id,)
            ).fetchone()
            assert row is not None
            connection.execute(
                "UPDATE cases SET updated_at = ? WHERE id = ?", (timestamp, row["case_id"])
            )
            connection.commit()
        return self._run_from_row(row)

    def get_collection_run(self, run_id: int) -> CollectionRunRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM collection_runs WHERE id = ?", (run_id,)
            ).fetchone()
        return self._run_from_row(row) if row is not None else None

    def list_collection_runs(self, case_id: int) -> list[CollectionRunRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM collection_runs WHERE case_id = ? ORDER BY id DESC",
                (case_id,),
            ).fetchall()
        return [self._run_from_row(row) for row in rows]

    def ingest_collector_result(
        self,
        case_id: int,
        run_id: int | None,
        result: CollectorResult,
    ) -> IngestStats:
        """Atomically persist one collector result.

        Evidence is deduplicated on ``(case_id, stable_key)``. A repeated item
        retains its database id and first-seen timestamp while its latest source
        representation and digest are refreshed.
        """
        if not isinstance(result, CollectorResult):
            raise TypeError("result must be CollectorResult")
        ingested_at = utc_now()
        inserted_evidence = 0
        updated_evidence = 0
        inserted_relations = 0
        inserted_gaps = 0
        evidence_ids: dict[str, int] = {}

        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_case_and_run(connection, case_id, run_id)

                for draft in result.evidence:
                    stable_key = draft.key()
                    document = {
                        "entity_type": draft.entity_type,
                        "label": draft.label,
                        "observed_at": draft.observed_at,
                        "source": draft.source,
                        "stable_key": stable_key,
                        "source_ref": draft.source_ref,
                        "confidence": draft.confidence,
                        "severity": draft.severity,
                        "properties": draft.properties,
                        "raw": draft.raw,
                    }
                    digest = canonical_sha256(document)
                    existing = connection.execute(
                        "SELECT id FROM evidence WHERE case_id = ? AND stable_key = ?",
                        (case_id, stable_key),
                    ).fetchone()
                    if existing is None:
                        cursor = connection.execute(
                            """
                            INSERT INTO evidence (
                                case_id, run_id, collector, entity_type, label,
                                observed_at, source, stable_key, source_ref,
                                confidence, severity, properties_json, raw_json,
                                evidence_digest, first_seen_at, last_seen_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                case_id,
                                run_id,
                                result.collector,
                                draft.entity_type,
                                draft.label,
                                draft.observed_at,
                                draft.source,
                                stable_key,
                                draft.source_ref,
                                draft.confidence,
                                draft.severity,
                                canonical_json(draft.properties),
                                canonical_json(draft.raw),
                                digest,
                                ingested_at,
                                ingested_at,
                            ),
                        )
                        evidence_id = int(cursor.lastrowid)
                        inserted_evidence += 1
                    else:
                        evidence_id = int(existing["id"])
                        connection.execute(
                            """
                            UPDATE evidence SET
                                run_id = ?, collector = ?, entity_type = ?,
                                label = ?, observed_at = ?, source = ?,
                                source_ref = ?, confidence = ?, severity = ?,
                                properties_json = ?, raw_json = ?,
                                evidence_digest = ?, last_seen_at = ?
                            WHERE id = ?
                            """,
                            (
                                run_id,
                                result.collector,
                                draft.entity_type,
                                draft.label,
                                draft.observed_at,
                                draft.source,
                                draft.source_ref,
                                draft.confidence,
                                draft.severity,
                                canonical_json(draft.properties),
                                canonical_json(draft.raw),
                                digest,
                                ingested_at,
                                evidence_id,
                            ),
                        )
                        updated_evidence += 1
                    evidence_ids[stable_key] = evidence_id
                    connection.execute(
                        """
                        INSERT INTO evidence_observations (
                            case_id, run_id, evidence_id, collector, entity_type,
                            label, observed_at, source, source_ref, confidence,
                            severity, properties_json, raw_json, evidence_digest,
                            collected_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(run_id, evidence_digest) DO NOTHING
                        """,
                        (
                            case_id,
                            run_id,
                            evidence_id,
                            result.collector,
                            draft.entity_type,
                            draft.label,
                            draft.observed_at,
                            draft.source,
                            draft.source_ref,
                            draft.confidence,
                            draft.severity,
                            canonical_json(draft.properties),
                            canonical_json(draft.raw),
                            digest,
                            ingested_at,
                        ),
                    )

                for relation in result.relations:
                    source_id = self._evidence_id(
                        connection, case_id, relation.source_key, evidence_ids
                    )
                    target_id = self._evidence_id(
                        connection, case_id, relation.target_key, evidence_ids
                    )
                    cursor = connection.execute(
                        """
                        INSERT INTO relations (
                            case_id, run_id, collector, source_key, target_key,
                            source_evidence_id, target_evidence_id, relation_type,
                            confidence, rationale, observed_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(case_id, source_key, target_key, relation_type)
                        DO UPDATE SET
                            run_id = excluded.run_id,
                            collector = excluded.collector,
                            source_evidence_id = excluded.source_evidence_id,
                            target_evidence_id = excluded.target_evidence_id,
                            confidence = excluded.confidence,
                            rationale = excluded.rationale,
                            observed_at = excluded.observed_at
                        """,
                        (
                            case_id,
                            run_id,
                            result.collector,
                            relation.source_key,
                            relation.target_key,
                            source_id,
                            target_id,
                            relation.relation_type,
                            relation.confidence,
                            relation.rationale,
                            relation.observed_at,
                            ingested_at,
                        ),
                    )
                    if cursor.rowcount > 0:
                        inserted_relations += 1

                for gap in result.gaps:
                    connection.execute(
                        """
                        INSERT INTO coverage_gaps (
                            case_id, run_id, collector, source, reason, impact,
                            recommendation, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            case_id,
                            run_id,
                            gap.collector or result.collector,
                            gap.source,
                            gap.reason,
                            gap.impact,
                            gap.recommendation,
                            ingested_at,
                        ),
                    )
                    inserted_gaps += 1

                connection.execute(
                    "UPDATE cases SET updated_at = ? WHERE id = ?", (ingested_at, case_id)
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

        return IngestStats(
            inserted_evidence=inserted_evidence,
            updated_evidence=updated_evidence,
            inserted_relations=inserted_relations,
            inserted_gaps=inserted_gaps,
        )

    def list_evidence(
        self,
        case_id: int,
        *,
        entity_type: str | None = None,
        severity: str | None = None,
        run_id: int | None = None,
        limit: int | None = None,
    ) -> list[EvidenceRecord]:
        query = "SELECT * FROM evidence WHERE case_id = ?"
        parameters: list[Any] = [case_id]
        for column, value in (
            ("entity_type", entity_type),
            ("severity", severity),
            ("run_id", run_id),
        ):
            if value is not None:
                query += f" AND {column} = ?"
                parameters.append(value)
        query += " ORDER BY observed_at ASC, id ASC"
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(max(0, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._evidence_from_row(row) for row in rows]

    def list_timeline(
        self, case_id: int, limit: int | None = None
    ) -> list[ObservationRecord]:
        query = """
            SELECT * FROM evidence_observations
            WHERE case_id = ?
            ORDER BY observed_at ASC, id ASC
        """
        parameters: list[Any] = [case_id]
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(max(0, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._observation_from_row(row) for row in rows]

    def list_relations(
        self, case_id: int, *, run_id: int | None = None
    ) -> list[RelationRecord]:
        query = "SELECT * FROM relations WHERE case_id = ?"
        parameters: list[Any] = [case_id]
        if run_id is not None:
            query += " AND run_id = ?"
            parameters.append(run_id)
        query += " ORDER BY id ASC"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._relation_from_row(row) for row in rows]

    def list_gaps(
        self, case_id: int, *, run_id: int | None = None
    ) -> list[CoverageGapRecord]:
        query = "SELECT * FROM coverage_gaps WHERE case_id = ?"
        parameters: list[Any] = [case_id]
        if run_id is not None:
            query += " AND run_id = ?"
            parameters.append(run_id)
        query += " ORDER BY id ASC"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._gap_from_row(row) for row in rows]

    def add_artifact(
        self,
        case_id: int,
        name: str,
        path: str | Path,
        *,
        run_id: int | None = None,
        kind: str = "file",
        sha256: str = "",
        size_bytes: int = 0,
        properties: Mapping[str, Any] | None = None,
    ) -> ArtifactRecord:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO artifacts (
                    case_id, run_id, name, path, kind, sha256, size_bytes,
                    created_at, properties_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    run_id,
                    name,
                    str(path),
                    kind,
                    sha256,
                    max(0, int(size_bytes)),
                    utc_now(),
                    canonical_json(dict(properties or {})),
                ),
            )
            artifact_id = int(cursor.lastrowid)
            connection.commit()
            row = connection.execute(
                "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
            ).fetchone()
        assert row is not None
        return self._artifact_from_row(row)

    register_artifact = add_artifact

    def list_artifacts(self, case_id: int) -> list[ArtifactRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM artifacts WHERE case_id = ? ORDER BY id ASC", (case_id,)
            ).fetchall()
        return [self._artifact_from_row(row) for row in rows]

    def log_action(
        self,
        case_id: int,
        action: str,
        details: Mapping[str, Any] | None = None,
        actor: str = "analyst",
        *,
        created_at: str | None = None,
    ) -> AnalystLogRecord:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO analyst_log (case_id, action, actor, details_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    action,
                    actor,
                    canonical_json(dict(details or {})),
                    created_at or utc_now(),
                ),
            )
            log_id = int(cursor.lastrowid)
            connection.commit()
            row = connection.execute(
                "SELECT * FROM analyst_log WHERE id = ?", (log_id,)
            ).fetchone()
        assert row is not None
        return self._log_from_row(row)

    def list_analyst_log(self, case_id: int) -> list[AnalystLogRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM analyst_log WHERE case_id = ? ORDER BY id ASC", (case_id,)
            ).fetchall()
        return [self._log_from_row(row) for row in rows]

    def case_summary(self, case_id: int) -> dict[str, Any]:
        case = self.get_case(case_id)
        if case is None:
            raise KeyError(f"case {case_id} does not exist")
        with self._connect() as connection:
            counts = {
                "collection_runs": self._count(connection, "collection_runs", case_id),
                "evidence": self._count(connection, "evidence", case_id),
                "evidence_observations": self._count(
                    connection, "evidence_observations", case_id
                ),
                "relations": self._count(connection, "relations", case_id),
                "coverage_gaps": self._count(connection, "coverage_gaps", case_id),
                "artifacts": self._count(connection, "artifacts", case_id),
                "analyst_log": self._count(connection, "analyst_log", case_id),
            }
            severity_counts = {
                str(row["severity"]): int(row["count"])
                for row in connection.execute(
                    """
                    SELECT severity, COUNT(*) AS count FROM evidence
                    WHERE case_id = ? GROUP BY severity ORDER BY severity
                    """,
                    (case_id,),
                ).fetchall()
            }
            entity_counts = {
                str(row["entity_type"]): int(row["count"])
                for row in connection.execute(
                    """
                    SELECT entity_type, COUNT(*) AS count FROM evidence
                    WHERE case_id = ? GROUP BY entity_type ORDER BY entity_type
                    """,
                    (case_id,),
                ).fetchall()
            }
            latest_run_row = connection.execute(
                """
                SELECT * FROM collection_runs WHERE case_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (case_id,),
            ).fetchone()
        return {
            "case": case,
            "counts": counts,
            "severity_counts": severity_counts,
            "entity_counts": entity_counts,
            "latest_run": self._run_from_row(latest_run_row) if latest_run_row else None,
            # Flat aliases keep summaries easy to consume in a status bar while
            # the grouped counts remain convenient for reports.
            "case_id": case.id,
            "title": case.title,
            "status": case.status,
            "run_count": counts["collection_runs"],
            "evidence_count": counts["evidence"],
            "observation_count": counts["evidence_observations"],
            "relation_count": counts["relations"],
            "gap_count": counts["coverage_gaps"],
            "artifact_count": counts["artifacts"],
        }

    @staticmethod
    def _validate_case_and_run(
        connection: sqlite3.Connection, case_id: int, run_id: int | None
    ) -> None:
        case = connection.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone()
        if case is None:
            raise KeyError(f"case {case_id} does not exist")
        if run_id is None:
            return
        run = connection.execute(
            "SELECT case_id FROM collection_runs WHERE id = ?", (run_id,)
        ).fetchone()
        if run is None:
            raise KeyError(f"collection run {run_id} does not exist")
        if int(run["case_id"]) != int(case_id):
            raise ValueError(f"collection run {run_id} belongs to a different case")

    @staticmethod
    def _evidence_id(
        connection: sqlite3.Connection,
        case_id: int,
        stable_key: str,
        current: Mapping[str, int],
    ) -> int | None:
        if stable_key in current:
            return current[stable_key]
        row = connection.execute(
            "SELECT id FROM evidence WHERE case_id = ? AND stable_key = ?",
            (case_id, stable_key),
        ).fetchone()
        return int(row["id"]) if row is not None else None

    @staticmethod
    def _count(connection: sqlite3.Connection, table: str, case_id: int) -> int:
        # `table` is only called with hard-coded schema identifiers above.
        row = connection.execute(
            f"SELECT COUNT(*) AS count FROM {table} WHERE case_id = ?", (case_id,)
        ).fetchone()
        return int(row["count"])

    @staticmethod
    def _case_from_row(row: sqlite3.Row) -> CaseRecord:
        return CaseRecord(
            id=int(row["id"]),
            title=str(row["title"]),
            description=str(row["description"]),
            status=str(row["status"]),
            suspect_path=str(row["suspect_path"]),
            hostname=str(row["hostname"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            properties=_json_loads(row["properties_json"]),
        )

    @staticmethod
    def _run_from_row(row: sqlite3.Row) -> CollectionRunRecord:
        return CollectionRunRecord(
            id=int(row["id"]),
            case_id=int(row["case_id"]),
            started_at=str(row["started_at"]),
            finished_at=str(row["finished_at"]),
            status=str(row["status"]),
            collector_count=int(row["collector_count"]),
            successful_count=int(row["successful_count"]),
            failed_count=int(row["failed_count"]),
            cancelled_count=int(row["cancelled_count"]),
            options=_json_loads(row["options_json"]),
            error_text=str(row["error_text"]),
        )

    @staticmethod
    def _evidence_from_row(row: sqlite3.Row) -> EvidenceRecord:
        return EvidenceRecord(
            id=int(row["id"]),
            case_id=int(row["case_id"]),
            run_id=int(row["run_id"]) if row["run_id"] is not None else None,
            collector=str(row["collector"]),
            entity_type=str(row["entity_type"]),
            label=str(row["label"]),
            observed_at=str(row["observed_at"]),
            source=str(row["source"]),
            stable_key=str(row["stable_key"]),
            source_ref=str(row["source_ref"]),
            confidence=str(row["confidence"]),
            severity=str(row["severity"]),
            properties=_json_loads(row["properties_json"]),
            raw=_json_loads(row["raw_json"]),
            evidence_digest=str(row["evidence_digest"]),
            first_seen_at=str(row["first_seen_at"]),
            last_seen_at=str(row["last_seen_at"]),
        )

    @staticmethod
    def _observation_from_row(row: sqlite3.Row) -> ObservationRecord:
        return ObservationRecord(
            id=int(row["id"]),
            case_id=int(row["case_id"]),
            run_id=int(row["run_id"]) if row["run_id"] is not None else None,
            evidence_id=int(row["evidence_id"]),
            collector=str(row["collector"]),
            entity_type=str(row["entity_type"]),
            label=str(row["label"]),
            observed_at=str(row["observed_at"]),
            source=str(row["source"]),
            source_ref=str(row["source_ref"]),
            confidence=str(row["confidence"]),
            severity=str(row["severity"]),
            properties=_json_loads(row["properties_json"]),
            raw=_json_loads(row["raw_json"]),
            evidence_digest=str(row["evidence_digest"]),
            collected_at=str(row["collected_at"]),
        )

    @staticmethod
    def _relation_from_row(row: sqlite3.Row) -> RelationRecord:
        return RelationRecord(
            id=int(row["id"]),
            case_id=int(row["case_id"]),
            run_id=int(row["run_id"]) if row["run_id"] is not None else None,
            collector=str(row["collector"]),
            source_key=str(row["source_key"]),
            target_key=str(row["target_key"]),
            source_evidence_id=(
                int(row["source_evidence_id"])
                if row["source_evidence_id"] is not None
                else None
            ),
            target_evidence_id=(
                int(row["target_evidence_id"])
                if row["target_evidence_id"] is not None
                else None
            ),
            relation_type=str(row["relation_type"]),
            confidence=str(row["confidence"]),
            rationale=str(row["rationale"]),
            observed_at=str(row["observed_at"]),
            created_at=str(row["created_at"]),
        )

    @staticmethod
    def _gap_from_row(row: sqlite3.Row) -> CoverageGapRecord:
        return CoverageGapRecord(
            id=int(row["id"]),
            case_id=int(row["case_id"]),
            run_id=int(row["run_id"]) if row["run_id"] is not None else None,
            collector=str(row["collector"]),
            source=str(row["source"]),
            reason=str(row["reason"]),
            impact=str(row["impact"]),
            recommendation=str(row["recommendation"]),
            created_at=str(row["created_at"]),
        )

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> ArtifactRecord:
        return ArtifactRecord(
            id=int(row["id"]),
            case_id=int(row["case_id"]),
            run_id=int(row["run_id"]) if row["run_id"] is not None else None,
            name=str(row["name"]),
            path=str(row["path"]),
            kind=str(row["kind"]),
            sha256=str(row["sha256"]),
            size_bytes=int(row["size_bytes"]),
            created_at=str(row["created_at"]),
            properties=_json_loads(row["properties_json"]),
        )

    @staticmethod
    def _log_from_row(row: sqlite3.Row) -> AnalystLogRecord:
        return AnalystLogRecord(
            id=int(row["id"]),
            case_id=int(row["case_id"]),
            action=str(row["action"]),
            actor=str(row["actor"]),
            details=_json_loads(row["details_json"]),
            created_at=str(row["created_at"]),
        )


# Public aliases used by different front ends during the prototype phase.
IRDatabase = Database
CaseDatabase = Database
IncidentDatabase = Database
