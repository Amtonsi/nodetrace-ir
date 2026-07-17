from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
import unittest

from nodetrace_ir.contracts import CollectorResult, EvidenceDraft, GapDraft, RelationDraft
from nodetrace_ir.database import Database


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "cases.sqlite3"
        self.database = Database(self.db_path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_schema_contains_all_required_tables_and_connections_are_released(self) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
        finally:
            connection.close()
        self.assertTrue(
            {
                "cases",
                "collection_runs",
                "evidence",
                "relations",
                "coverage_gaps",
                "artifacts",
                "analyst_log",
            }.issubset(tables)
        )

        moved = self.db_path.with_suffix(".moved")
        self.db_path.replace(moved)
        moved.replace(self.db_path)

    def test_case_lifecycle_json_and_summary(self) -> None:
        case = self.database.create_case(
            "Workstation 42",
            suspect_path=r"C:\Temp\dropper.exe",
            properties={"priority": 1, "tags": ["malware"]},
        )
        self.assertEqual(case.properties["tags"], ["malware"])
        self.assertEqual(self.database.get_case(case.id).title, "Workstation 42")  # type: ignore[union-attr]
        self.assertEqual([item.id for item in self.database.list_cases()], [case.id])
        closed = self.database.update_case_status(case.id, "closed")
        self.assertEqual(closed.status, "closed")

        log = self.database.log_action(case.id, "triage", {"decision": "isolate"})
        self.assertEqual(log.details, {"decision": "isolate"})
        summary = self.database.case_summary(case.id)
        self.assertEqual(summary["counts"]["analyst_log"], 1)
        self.assertEqual(summary["counts"]["evidence"], 0)

    def test_reopening_database_marks_running_collection_runs_interrupted(self) -> None:
        case = self.database.create_case("Interrupted")
        run = self.database.start_collection_run(case.id, 2)

        reopened = Database(self.db_path)
        recovered = reopened.get_collection_run(run.id)

        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.status, "interrupted")  # type: ignore[union-attr]
        self.assertTrue(recovered.finished_at)  # type: ignore[union-attr]
        self.assertIn("interrupted", recovered.error_text.lower())  # type: ignore[union-attr]
        self.assertEqual(reopened.recover_interrupted_runs(), 0)

    def test_ingest_deduplicates_evidence_and_links_relations(self) -> None:
        case = self.database.create_case("Dedup")
        run = self.database.start_collection_run(case.id, 1, {"scope": "local"})
        result = CollectorResult(
            collector="fixture",
            started_at="2026-07-13T00:00:00+00:00",
            finished_at="2026-07-13T00:01:00+00:00",
            status="completed",
            evidence=[
                EvidenceDraft(
                    entity_type="file",
                    label="bad.exe",
                    observed_at="2026-07-12T23:59:00+00:00",
                    source="fixture",
                    stable_key="file:bad",
                    properties={"size": 10},
                    raw={"line": "one"},
                ),
                EvidenceDraft(
                    entity_type="process",
                    label="bad.exe --run",
                    observed_at="2026-07-13T00:00:00+00:00",
                    source="fixture",
                    stable_key="process:bad:1",
                    properties={"pid": 1},
                ),
            ],
            relations=[
                RelationDraft(
                    source_key="file:bad",
                    target_key="process:bad:1",
                    relation_type="executed_as",
                    confidence="high",
                    rationale="matching image path",
                )
            ],
            gaps=[GapDraft("fixture", "prefetch", "disabled", "execution gaps")],
        )
        first = self.database.ingest_collector_result(case.id, run.id, result)
        self.assertEqual(first.inserted_evidence, 2)
        self.assertEqual(first.inserted_relations, 1)

        result.evidence[0].properties["size"] = 20
        second = self.database.ingest_collector_result(case.id, run.id, result)
        self.assertEqual(second.inserted_evidence, 0)
        self.assertEqual(second.updated_evidence, 2)
        evidence = self.database.list_evidence(case.id)
        self.assertEqual(len(evidence), 2)
        file_item = next(item for item in evidence if item.stable_key == "file:bad")
        self.assertEqual(file_item.properties["size"], 20)
        self.assertEqual(len(file_item.evidence_digest), 64)
        self.assertEqual(file_item.raw, {"line": "one"})

        relations = self.database.list_relations(case.id)
        self.assertEqual(len(relations), 1)
        self.assertIsNotNone(relations[0].source_evidence_id)
        self.assertIsNotNone(relations[0].target_evidence_id)
        self.assertEqual(len(self.database.list_gaps(case.id)), 2)

        finished = self.database.finish_collection_run(run.id, "completed", 1)
        self.assertEqual(finished.successful_count, 1)
        summary = self.database.case_summary(case.id)
        self.assertEqual(summary["counts"]["evidence"], 2)
        self.assertEqual(summary["counts"]["relations"], 1)
        self.assertEqual(summary["entity_counts"], {"file": 1, "process": 1})


if __name__ == "__main__":
    unittest.main()
