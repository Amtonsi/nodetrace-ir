from __future__ import annotations

from nodetrace_ir.contracts import Collector

from .event_logs import EventLogCollector
from .file_seed import FileSeedCollector
from .filesystem import FilesystemContextCollector
from .network import NetworkCollector
from .offline import OfflineCoverageCollector
from .offline_sources import OfflineBrowserDownloadCollector, OfflineUsbHistoryCollector
from .persistence import PersistenceCollector
from .prefetch import PrefetchCollector
from .processes import LiveProcessCollector


def default_collectors() -> list[Collector]:
    """Return the defensive collectors in a deterministic collection order."""

    return [
        FileSeedCollector(),
        LiveProcessCollector(),
        NetworkCollector(),
        PersistenceCollector(),
        EventLogCollector(),
        FilesystemContextCollector(),
        PrefetchCollector(),
    ]


def default_offline_collectors() -> list[Collector]:
    """Return collectors that inspect only a mounted, non-running Windows target."""

    return [
        FileSeedCollector(),
        OfflineBrowserDownloadCollector(),
        OfflineUsbHistoryCollector(),
        EventLogCollector(),
        PrefetchCollector(),
        OfflineCoverageCollector(),
    ]


__all__ = [
    "EventLogCollector",
    "FileSeedCollector",
    "FilesystemContextCollector",
    "LiveProcessCollector",
    "NetworkCollector",
    "OfflineBrowserDownloadCollector",
    "OfflineCoverageCollector",
    "OfflineUsbHistoryCollector",
    "PersistenceCollector",
    "PrefetchCollector",
    "default_collectors",
    "default_offline_collectors",
]
