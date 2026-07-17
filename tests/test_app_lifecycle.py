from __future__ import annotations

from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nodetrace_ir.app import NodeTraceApp, resource_path


class _Root:
    def __init__(self) -> None:
        self.after_callbacks: list[object] = []
        self.destroyed = False
        self.icon: object | None = None

    def after(self, _delay: int, callback: object) -> None:
        self.after_callbacks.append(callback)

    def destroy(self) -> None:
        self.destroyed = True

    def iconphoto(self, _default: bool, image: object) -> None:
        self.icon = image


class _Database:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Value:
    def __init__(self) -> None:
        self.value = ""

    def set(self, value: str) -> None:
        self.value = value


class _Button:
    def __init__(self) -> None:
        self.state = "normal"

    def configure(self, *, state: str) -> None:
        self.state = state


class _CancelEvent:
    def __init__(self) -> None:
        self.was_set = False

    def set(self) -> None:
        self.was_set = True


class _Worker:
    def __init__(self, cancel_event: _CancelEvent) -> None:
        self.alive = True
        self.join_calls = 0
        self.cancel_event = cancel_event

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float | None = None) -> None:
        self.join_calls += 1
        if not self.cancel_event.was_set:
            raise AssertionError("worker was joined before cancellation")
        if timeout != 0.05:
            raise AssertionError("GUI shutdown join must remain responsive")
        if self.join_calls >= 2:
            self.alive = False


class _PhotoImage:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.scaled: _PhotoImage | None = None

    def width(self) -> int:
        return 128

    def height(self) -> int:
        return 128

    def subsample(self, _x: int, _y: int) -> "_PhotoImage":
        self.scaled = _PhotoImage(kind="scaled")
        return self.scaled


class AppLifecycleTests(unittest.TestCase):
    @staticmethod
    def _bare_app() -> NodeTraceApp:
        app = NodeTraceApp.__new__(NodeTraceApp)
        app.root = _Root()  # type: ignore[assignment]
        app.database = _Database()  # type: ignore[assignment]
        app.status_var = _Value()  # type: ignore[assignment]
        app.cancel_button = _Button()  # type: ignore[assignment]
        app._closing = False
        return app

    def test_close_cancels_and_waits_for_worker_before_destroying_root(self) -> None:
        app = self._bare_app()
        cancellation = _CancelEvent()
        worker = _Worker(cancellation)
        app._cancel_event = cancellation  # type: ignore[assignment]
        app._worker = worker  # type: ignore[assignment]

        app._on_close()

        self.assertTrue(cancellation.was_set)
        self.assertEqual(worker.join_calls, 1)
        self.assertFalse(app.root.destroyed)  # type: ignore[attr-defined]
        self.assertFalse(app.database.closed)  # type: ignore[attr-defined]
        self.assertEqual(app.cancel_button.state, "disabled")  # type: ignore[attr-defined]

        callback = app.root.after_callbacks.pop()  # type: ignore[attr-defined]
        callback()  # type: ignore[operator]
        self.assertEqual(worker.join_calls, 2)
        self.assertTrue(app.database.closed)  # type: ignore[attr-defined]
        self.assertTrue(app.root.destroyed)  # type: ignore[attr-defined]

    def test_worker_launcher_explicitly_creates_non_daemon_thread(self) -> None:
        app = self._bare_app()
        thread = Mock()
        with patch("nodetrace_ir.app.Thread", return_value=thread) as thread_type:
            target = lambda: None
            app._launch_worker(target, "fixture")

        thread_type.assert_called_once_with(target=target, name="fixture", daemon=False)
        thread.start.assert_called_once_with()

    def test_resource_path_uses_source_tree_and_meipass(self) -> None:
        expected_source = Path(__file__).resolve().parent.parent / "assets" / "nodetrace-icon.png"
        self.assertEqual(resource_path("assets", "nodetrace-icon.png"), expected_source)
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(sys, "_MEIPASS", temporary, create=True):
                self.assertEqual(
                    resource_path("assets", "nodetrace-icon.png"),
                    Path(temporary) / "assets" / "nodetrace-icon.png",
                )

    def test_brand_images_are_retained_on_application_instance(self) -> None:
        app = self._bare_app()
        app._window_icon = None
        app._brand_image = None
        with patch("nodetrace_ir.app.tk.PhotoImage", _PhotoImage):
            app._load_brand_assets()

        self.assertIsNotNone(app._window_icon)
        self.assertIs(app.root.icon, app._window_icon)  # type: ignore[attr-defined]
        self.assertIs(app._brand_image, app._window_icon.scaled)  # type: ignore[union-attr]

    def test_causal_chain_uses_only_supported_source_and_impact_links(self) -> None:
        evidence = [
            {
                "stable_key": "process:downloader",
                "entity_type": "process",
                "label": "browser.exe (PID 42)",
                "confidence": "high",
                "properties": {},
            },
            {
                "stable_key": "file:seed",
                "entity_type": "file",
                "label": "invoice.exe",
                "confidence": "high",
                "properties": {"is_seed": True},
            },
        ]
        relations = [
            {
                "source_key": "process:downloader",
                "target_key": "file:seed",
                "relation_type": "created",
                "confidence": "high",
            }
        ]
        assessment = SimpleNamespace(
            entry_keys=("file:seed",),
            entry_path=r"C:\Users\analyst\Downloads\invoice.exe",
            findings=(
                SimpleNamespace(category="entry", basis="observed"),
                SimpleNamespace(category="process", basis="observed"),
                SimpleNamespace(category="file", basis="hypothesis"),
            ),
        )

        chain = NodeTraceApp._causal_chain_display(
            evidence, relations, assessment
        )

        self.assertEqual(chain["source"], "browser.exe (PID 42)")
        self.assertIn("Наблюдение", chain["source_meta"])
        self.assertEqual(chain["file"], "invoice.exe")
        self.assertEqual(chain["impact"], "процессов: 1")
        self.assertIn("корреляций: 0", chain["impact_meta"])

    def test_causal_chain_does_not_promote_low_confidence_origin(self) -> None:
        evidence = [
            {
                "stable_key": "archive:possible",
                "entity_type": "file",
                "label": "possible.zip",
                "confidence": "low",
                "properties": {},
            },
            {
                "stable_key": "file:seed",
                "entity_type": "file",
                "label": "payload.exe",
                "confidence": "high",
                "properties": {"is_seed": True},
            },
        ]
        relations = [
            {
                "source_key": "file:seed",
                "target_key": "archive:possible",
                "relation_type": "extracted_from",
                "confidence": "low",
            }
        ]
        assessment = SimpleNamespace(
            entry_keys=("file:seed",),
            entry_path=r"C:\Temp\payload.exe",
            findings=(SimpleNamespace(category="file", basis="hypothesis"),),
        )

        chain = NodeTraceApp._causal_chain_display(
            evidence, relations, assessment
        )

        self.assertEqual(chain["source"], "Не установлен")
        self.assertEqual(chain["impact"], "Не установлено")
        self.assertIn("гипотезы", chain["impact_meta"].casefold())

    def test_causal_chain_can_show_observed_zone_without_claiming_channel(self) -> None:
        evidence = [
            {
                "stable_key": "file:seed",
                "entity_type": "file",
                "label": "payload.exe",
                "confidence": "high",
                "properties": {"is_seed": True, "zone_id": 3},
            }
        ]
        assessment = SimpleNamespace(
            entry_keys=("file:seed",), entry_path="", findings=()
        )

        chain = NodeTraceApp._causal_chain_display(evidence, [], assessment)

        self.assertEqual(chain["source"], "Зона Интернета (ZoneId=3)")
        self.assertIn("точный канал не установлен", chain["source_meta"])

    def test_causal_chain_accepts_preserved_reported_download_source(self) -> None:
        evidence = [
            {
                "stable_key": "origin:zone",
                "entity_type": "download_origin",
                "label": "https://downloads.example.test/payload.exe",
                "confidence": "medium",
                "properties": {"reported_by": "Zone.Identifier"},
            },
            {
                "stable_key": "file:seed",
                "entity_type": "file",
                "label": "payload.exe",
                "confidence": "high",
                "properties": {"is_seed": True},
            },
        ]
        relations = [
            {
                "source_key": "origin:zone",
                "target_key": "file:seed",
                "relation_type": "reported_download_source",
                "confidence": "medium",
            }
        ]
        assessment = SimpleNamespace(
            entry_keys=("file:seed",),
            entry_path=r"C:\Temp\payload.exe",
            findings=(
                SimpleNamespace(category="source", basis="correlated"),
                SimpleNamespace(category="process", basis="observed"),
            ),
        )

        chain = NodeTraceApp._causal_chain_display(evidence, relations, assessment)

        self.assertEqual(
            chain["source"], "https://downloads.example.test/payload.exe"
        )
        self.assertIn("Корреляция", chain["source_meta"])
        self.assertEqual(chain["impact"], "процессов: 1")

    def test_specific_delivery_source_outranks_generic_zone_marker(self) -> None:
        evidence = [
            {
                "stable_key": "delivery:mail",
                "entity_type": "delivery_source",
                "label": "Почтовое вложение invoice.exe",
                "confidence": "medium",
                "properties": {},
            },
            {
                "stable_key": "file:seed",
                "entity_type": "file",
                "label": "invoice.exe",
                "confidence": "high",
                "properties": {"is_seed": True, "zone_id": 3},
            },
        ]
        relations = [
            {
                "source_key": "delivery:mail",
                "target_key": "file:seed",
                "relation_type": "reported_delivery_source",
                "confidence": "medium",
            }
        ]
        assessment = SimpleNamespace(
            entry_keys=("file:seed",), entry_path="", findings=()
        )

        chain = NodeTraceApp._causal_chain_display(evidence, relations, assessment)

        self.assertEqual(chain["source"], "Почтовое вложение invoice.exe")
        self.assertIn("Корреляция", chain["source_meta"])

    def test_causal_chain_shows_exact_current_usb_identifier_with_boundary(self) -> None:
        evidence = [
            {
                "stable_key": "media:usb:SERIAL-42",
                "entity_type": "removable_media",
                "label": "USB E: · SERIAL-42 · USBSTOR\\DISK&VEN_TEST",
                "confidence": "high",
                "properties": {"device_serial": "SERIAL-42"},
            },
            {
                "stable_key": "file:seed",
                "entity_type": "file",
                "label": "payload.exe",
                "confidence": "high",
                "properties": {"is_seed": True},
            },
        ]
        relations = [
            {
                "source_key": "media:usb:SERIAL-42",
                "target_key": "file:seed",
                "relation_type": "present_on_removable_media",
                "confidence": "high",
            }
        ]
        assessment = SimpleNamespace(
            entry_keys=("file:seed",), entry_path="", findings=()
        )

        chain = NodeTraceApp._causal_chain_display(evidence, relations, assessment)

        self.assertIn("SERIAL-42", chain["source"])
        self.assertIn("историческая доставка не доказана", chain["source_meta"])


if __name__ == "__main__":
    unittest.main()
