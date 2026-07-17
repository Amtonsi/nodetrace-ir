from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
import unittest

from nodetrace_ir.contracts import CollectorResult, EvidenceDraft
from nodetrace_ir.database import Database
from nodetrace_ir.models import ObservationRecord


class ObservationHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "observations.sqlite3"
        self.database = Database(self.db_path)

    def tearDown(self) -> None:
        self.database.close()
        self.temporary.cleanup()

    @staticmethod
    def _result(*evidence: EvidenceDraft) -> CollectorResult:
        return CollectorResult(
            collector="fixture",
            started_at="2026-07-13T00:00:00+00:00",
            finished_at="2026-07-13T00:01:00+00:00",
            status="completed",
            evidence=list(evidence),
        )

    def test_schema_migration_creates_observation_table_and_indexes(self) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(evidence_observations)"
                ).fetchall()
            }
            indexes = {
                row[1]: bool(row[2])
                for row in connection.execute(
                    "PRAGMA index_list(evidence_observations)"
                ).fetchall()
            }
        finally:
            connection.close()

        self.assertEqual(
            columns,
            {
                "id",
                "case_id",
                "run_id",
                "evidence_id",
                "collector",
                "entity_type",
                "label",
                "observed_at",
                "source",
                "source_ref",
                "confidence",
                "severity",
                "properties_json",
                "raw_json",
                "evidence_digest",
                "collected_at",
            },
        )
        self.assertIn("idx_observations_case_time", indexes)
        self.assertIn("idx_observations_evidence", indexes)
        self.assertIn("idx_observations_run", indexes)
        self.assertTrue(any(indexes.values()))

    def test_ingest_preserves_changed_snapshots_and_deduplicates_exact_run_digest(self) -> None:
        case = self.database.create_case("Append-only")
        first_run = self.database.start_collection_run(case.id, 1)
        draft = EvidenceDraft(
            entity_type="file",
            label="sample.exe",
            observed_at="2026-07-13T00:00:00+00:00",
            source="filesystem",
            source_ref=r"C:\Temp\sample.exe",
            stable_key="file:sample",
            confidence="high",
            severity="high",
            properties={"size": 10},
            raw={"record": "first"},
        )
        result = self._result(draft)

        self.database.ingest_collector_result(case.id, first_run.id, result)
        draft.properties["size"] = 20
        draft.raw["record"] = "changed"
        self.database.ingest_collector_result(case.id, first_run.id, result)
        self.database.ingest_collector_result(case.id, first_run.id, result)

        second_run = self.database.start_collection_run(case.id, 1)
        self.database.ingest_collector_result(case.id, second_run.id, result)

        entities = self.database.list_evidence(case.id)
        timeline = self.database.list_timeline(case.id)
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].properties, {"size": 20})
        self.assertEqual(len(timeline), 3)
        self.assertTrue(all(isinstance(item, ObservationRecord) for item in timeline))
        self.assertEqual(
            [item.run_id for item in timeline],
            [first_run.id, first_run.id, second_run.id],
        )
        self.assertEqual([item.properties["size"] for item in timeline], [10, 20, 20])
        self.assertEqual([item.raw["record"] for item in timeline], ["first", "changed", "changed"])
        self.assertEqual({item.evidence_id for item in timeline}, {entities[0].id})
        self.assertEqual(timeline[1].evidence_digest, timeline[2].evidence_digest)
        self.assertNotEqual(timeline[0].evidence_digest, timeline[1].evidence_digest)

        summary = self.database.case_summary(case.id)
        self.assertEqual(summary["counts"]["evidence_observations"], 3)
        self.assertEqual(summary["observation_count"], 3)

    def test_list_timeline_is_chronological_and_honors_limit(self) -> None:
        case = self.database.create_case("Timeline")
        run = self.database.start_collection_run(case.id, 1)
        result = self._result(
            EvidenceDraft(
                entity_type="event",
                label="third",
                observed_at="2026-07-13T03:00:00+00:00",
                source="fixture",
                stable_key="event:third",
            ),
            EvidenceDraft(
                entity_type="event",
                label="first",
                observed_at="2026-07-13T01:00:00+00:00",
                source="fixture",
                stable_key="event:first",
            ),
            EvidenceDraft(
                entity_type="event",
                label="second",
                observed_at="2026-07-13T02:00:00+00:00",
                source="fixture",
                stable_key="event:second",
            ),
        )
        self.database.ingest_collector_result(case.id, run.id, result)

        self.assertEqual(
            [item.label for item in self.database.list_timeline(case.id)],
            ["first", "second", "third"],
        )
        self.assertEqual(
            [item.label for item in self.database.list_timeline(case.id, limit=2)],
            ["first", "second"],
        )
        self.assertEqual(self.database.list_timeline(case.id, limit=0), [])


if __name__ == "__main__":
    unittest.main()
