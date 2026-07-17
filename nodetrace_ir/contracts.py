from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from threading import Event
from typing import Any, Protocol


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class EvidenceDraft:
    entity_type: str
    label: str
    observed_at: str
    source: str
    stable_key: str = ""
    source_ref: str = ""
    confidence: str = "medium"
    severity: str = "info"
    properties: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        if self.stable_key:
            return self.stable_key
        return f"{self.entity_type}:{canonical_sha256({'label': self.label, 'source': self.source, 'properties': self.properties})[:24]}"


@dataclass(slots=True)
class RelationDraft:
    source_key: str
    target_key: str
    relation_type: str
    confidence: str
    rationale: str
    observed_at: str = ""


@dataclass(slots=True)
class GapDraft:
    collector: str
    source: str
    reason: str
    impact: str
    recommendation: str = ""


@dataclass(slots=True)
class CollectorResult:
    collector: str
    started_at: str
    finished_at: str
    status: str
    evidence: list[EvidenceDraft] = field(default_factory=list)
    relations: list[RelationDraft] = field(default_factory=list)
    gaps: list[GapDraft] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CollectionContext:
    case_id: int
    suspect_path: str
    started_at: str
    lookback_days: int
    artifact_dir: Path
    cancel_event: Event
    options: dict[str, Any] = field(default_factory=dict)


class Collector(Protocol):
    name: str
    display_name: str

    def collect(self, context: CollectionContext) -> CollectorResult:
        ...
