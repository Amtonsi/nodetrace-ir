from __future__ import annotations

import tempfile
from pathlib import Path
from threading import Event
import unittest

from nodetrace_ir.contracts import CollectorResult, EvidenceDraft, utc_now
from nodetrace_ir.database import Database
from nodetrace_ir.engine import CollectionEngine, create_demo_case


class GoodCollector:
    name = "good"
    display_name = "Good"

    def collect(self, context):
        now = utc_now()
        return CollectorResult(
            collector=self.name,
            started_at=now,
            finished_at=now,
            status="completed",
            evidence=[
                EvidenceDraft(
                    entity_type="file",
                    label=context.suspect_path or "sample.exe",
                    observed_at=now,
                    source="unit test",
                    stable_key="file:sample",
                    properties={"lookback_days": context.lookback_days},
                )
            ],
        )


class BrokenCollector:
    name = "broken"
    display_name = "Broken"

    def collect(self, context):
        raise PermissionError("event log access denied")


class NeverCollector:
    name = "never"
    display_name = "Never"

    def __init__(self) -> None:
        self.called = False

    def collect(self, context):
        self.called = True
        raise AssertionError("must not run")


class CancellingCollector(GoodCollector):
    name = "canceller"

    def collect(self, context):
        result = super().collect(context)
        context.cancel_event.set()
        return result


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.temporary.name) / "cases.sqlite3")
        self.case = self.database.create_case("Engine")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_one_collector_failure_does_not_abort_other_collectors(self) -> None:
        events = []
        engine = CollectionEngine(
            self.database,
            [BrokenCollector(), GoodCollector()],
            Path(self.temporary.name) / "artifacts",
        )
        summary = engine.run(
            self.case.id,
            r"C:\Temp\sample.exe",
            progress_callback=events.append,
        )
        self.assertEqual(summary.status, "partial")
        self.assertEqual(summary.run.failed_count, 1)
        self.assertEqual(summary.run.successful_count, 1)
        self.assertEqual(len(self.database.list_evidence(self.case.id)), 1)
        gaps = self.database.list_gaps(self.case.id)
        self.assertEqual(len(gaps), 1)
        self.assertIn("PermissionError", gaps[0].reason)
        self.assertTrue(any(event["phase"] == "run_finished" for event in events))

    def test_cancel_event_stops_before_next_collector(self) -> None:
        never = NeverCollector()
        cancellation = Event()
        engine = CollectionEngine(self.database, [CancellingCollector(), never])
        summary = engine.run(self.case.id, cancel_event=cancellation)
        self.assertEqual(summary.status, "partial")
        self.assertEqual(summary.run.successful_count, 1)
        self.assertEqual(summary.run.cancelled_count, 1)
        self.assertFalse(never.called)

    def test_already_cancelled_run_records_all_collectors_as_cancelled(self) -> None:
        cancellation = Event()
        cancellation.set()
        never = NeverCollector()
        summary = CollectionEngine(self.database, [never]).run(
            self.case.id, cancel_event=cancellation
        )
        self.assertEqual(summary.status, "cancelled")
        self.assertEqual(summary.run.cancelled_count, 1)
        self.assertFalse(never.called)

    def test_demo_case_generator_populates_graph(self) -> None:
        case_id = create_demo_case(self.database)
        summary = self.database.case_summary(case_id)
        self.assertEqual(summary["counts"]["evidence"], 3)
        self.assertEqual(summary["counts"]["relations"], 2)
        self.assertEqual(summary["counts"]["coverage_gaps"], 1)


if __name__ == "__main__":
    unittest.main()
