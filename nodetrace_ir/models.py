from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterator, Mapping


class RecordMixin(Mapping[str, Any]):
    """Small mapping facade so records work in both UI and typed code."""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[arg-type]

    def __getitem__(self, key: str) -> Any:
        if not hasattr(self, key):
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(self.__dataclass_fields__)  # type: ignore[attr-defined]

    def __len__(self) -> int:
        return len(self.__dataclass_fields__)  # type: ignore[attr-defined]


@dataclass(frozen=True, slots=True)
class CaseRecord(RecordMixin):
    id: int
    title: str
    description: str
    status: str
    suspect_path: str
    hostname: str
    created_at: str
    updated_at: str
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.title

    @property
    def host(self) -> str:
        return self.hostname


@dataclass(frozen=True, slots=True)
class CollectionRunRecord(RecordMixin):
    id: int
    case_id: int
    started_at: str
    finished_at: str
    status: str
    collector_count: int
    successful_count: int
    failed_count: int
    cancelled_count: int
    options: dict[str, Any] = field(default_factory=dict)
    error_text: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceRecord(RecordMixin):
    id: int
    case_id: int
    run_id: int | None
    collector: str
    entity_type: str
    label: str
    observed_at: str
    source: str
    stable_key: str
    source_ref: str
    confidence: str
    severity: str
    properties: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    evidence_digest: str = ""
    first_seen_at: str = ""
    last_seen_at: str = ""


@dataclass(frozen=True, slots=True)
class ObservationRecord(RecordMixin):
    id: int
    case_id: int
    run_id: int | None
    evidence_id: int
    collector: str
    entity_type: str
    label: str
    observed_at: str
    source: str
    source_ref: str
    confidence: str
    severity: str
    properties: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    evidence_digest: str = ""
    collected_at: str = ""


@dataclass(frozen=True, slots=True)
class RelationRecord(RecordMixin):
    id: int
    case_id: int
    run_id: int | None
    collector: str
    source_key: str
    target_key: str
    source_evidence_id: int | None
    target_evidence_id: int | None
    relation_type: str
    confidence: str
    rationale: str
    observed_at: str
    created_at: str


@dataclass(frozen=True, slots=True)
class CoverageGapRecord(RecordMixin):
    id: int
    case_id: int
    run_id: int | None
    collector: str
    source: str
    reason: str
    impact: str
    recommendation: str
    created_at: str


@dataclass(frozen=True, slots=True)
class ArtifactRecord(RecordMixin):
    id: int
    case_id: int
    run_id: int | None
    name: str
    path: str
    kind: str
    sha256: str
    size_bytes: int
    created_at: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AnalystLogRecord(RecordMixin):
    id: int
    case_id: int
    action: str
    actor: str
    details: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class IngestStats(RecordMixin):
    inserted_evidence: int = 0
    updated_evidence: int = 0
    inserted_relations: int = 0
    inserted_gaps: int = 0

    @property
    def evidence_total(self) -> int:
        return self.inserted_evidence + self.updated_evidence


@dataclass(frozen=True, slots=True)
class CollectorOutcome(RecordMixin):
    collector: str
    status: str
    evidence_count: int = 0
    relation_count: int = 0
    gap_count: int = 0
    error: str = ""


@dataclass(frozen=True, slots=True)
class EngineRunSummary(RecordMixin):
    run: CollectionRunRecord
    outcomes: tuple[CollectorOutcome, ...]

    @property
    def run_id(self) -> int:
        return self.run.id

    @property
    def status(self) -> str:
        return self.run.status


# Short aliases are convenient for call sites and keep backwards compatibility
# with early prototypes that used the shorter names.
Case = CaseRecord
CollectionRun = CollectionRunRecord
Evidence = EvidenceRecord
Observation = ObservationRecord
Relation = RelationRecord
CoverageGap = CoverageGapRecord
Artifact = ArtifactRecord
AnalystLog = AnalystLogRecord
