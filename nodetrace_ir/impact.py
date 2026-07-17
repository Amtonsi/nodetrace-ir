from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
import heapq
import ntpath
from typing import Any, Iterable

from .database import Database
from .models import EvidenceRecord, RelationRecord


_PROCESS_TYPES = {"process"}
_FILE_TYPES = {"file", "module", "alternate_data_stream"}
_PERSISTENCE_TYPES = {
    "autorun",
    "registry",
    "scheduled_task",
    "service",
    "startup_item",
}
_NETWORK_TYPES = {
    "dns_query",
    "domain",
    "ip",
    "network_connection",
    "network_endpoint",
}
_DETECTION_TYPES = {"alert", "malware_detection"}
_SOURCE_TYPES = {"delivery_source", "download_origin", "removable_media"}

_DIRECT_RELATIONS = {
    "configured_as_service",
    "connected_to",
    "created",
    "created_registry",
    "deleted",
    "detected_as",
    "executed_as",
    "has_alternate_stream",
    "installed_as_service",
    "loaded",
    "modified",
    "modified_registry",
    "owns_connection",
    "remote_endpoint",
    "renamed_registry",
    "resolved",
    "spawned",
}
_HYPOTHESIS_RELATIONS = {
    "possible_persistence_reference",
    "possible_prefetch_name_match",
    "reported_parent_of",
    "temporally_adjacent_file",
}
_PROVENANCE_RELATIONS = {
    "present_on_removable_media",
    "reported_delivery_source",
    "reported_download_source",
}
_REVERSE_ANCESTRY_RELATIONS = {
    "reported_parent_of",
    "spawned",
    *_PROVENANCE_RELATIONS,
}
_BASIS_RANK = {"observed": 0, "correlated": 1, "hypothesis": 2}


@dataclass(frozen=True, slots=True)
class ImpactFinding:
    stable_key: str
    entity_type: str
    label: str
    category: str
    basis: str
    confidence: str
    depth: int
    relation_path: tuple[str, ...]
    evidence_path: tuple[str, ...]
    rationale: str
    observed_at: str
    properties: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ImpactAssessment:
    case_id: int
    entry_path: str
    entry_keys: tuple[str, ...]
    findings: tuple[ImpactFinding, ...]
    complete: bool
    limitations: tuple[str, ...]
    coverage_gap_count: int = 0

    @property
    def affected_processes(self) -> tuple[ImpactFinding, ...]:
        return tuple(item for item in self.findings if item.category == "process")

    @property
    def affected_files(self) -> tuple[ImpactFinding, ...]:
        return tuple(item for item in self.findings if item.category == "file")

    @property
    def persistence(self) -> tuple[ImpactFinding, ...]:
        return tuple(item for item in self.findings if item.category == "persistence")

    @property
    def network_activity(self) -> tuple[ImpactFinding, ...]:
        return tuple(item for item in self.findings if item.category == "network")

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "entry_path": self.entry_path,
            "entry_keys": list(self.entry_keys),
            "complete": self.complete,
            "coverage_gap_count": self.coverage_gap_count,
            "limitations": list(self.limitations),
            "findings": [item.as_dict() for item in self.findings],
            "counts": {
                category: sum(1 for item in self.findings if item.category == category)
                for category in ("source", "entry", "process", "file", "persistence", "network")
            },
            "basis_counts": {
                basis: sum(1 for item in self.findings if item.basis == basis)
                for basis in ("observed", "correlated", "hypothesis")
            },
        }


def _normalized_path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    if not text:
        return ""
    return ntpath.normcase(ntpath.normpath(text))


def _candidate_paths(item: EvidenceRecord) -> Iterable[str]:
    for key in (
        "path",
        "normalized_path",
        "image",
        "image_path",
        "executable",
        "target",
    ):
        value = item.properties.get(key)
        if value:
            yield str(value)
    if item.source_ref:
        yield item.source_ref


def _category(item: EvidenceRecord, *, entry: bool = False) -> str:
    if entry:
        return "entry"
    kind = item.entity_type.casefold()
    if kind in _PROCESS_TYPES:
        return "process"
    if kind in _FILE_TYPES:
        return "file"
    if kind in _PERSISTENCE_TYPES:
        return "persistence"
    if kind in _NETWORK_TYPES:
        return "network"
    if kind in _DETECTION_TYPES:
        return "detection"
    if kind in _SOURCE_TYPES:
        return "source"
    return ""


def _edge_basis(relation: RelationRecord, *, reverse: bool = False) -> str:
    relation_type = relation.relation_type.casefold()
    confidence = relation.confidence.casefold()
    if (
        (reverse and relation_type not in _PROVENANCE_RELATIONS)
        or relation_type in _HYPOTHESIS_RELATIONS
        or confidence == "low"
    ):
        return "hypothesis"
    if confidence == "high" and relation_type in _DIRECT_RELATIONS:
        return "observed"
    return "correlated"


def _combine_basis(current: str, edge: str) -> str:
    return max((current, edge), key=lambda value: _BASIS_RANK[value])


def _confidence_for_basis(basis: str) -> str:
    return {"observed": "high", "correlated": "medium", "hypothesis": "low"}[basis]


class ImpactAnalyzer:
    """Conservative graph walk over evidence already stored for one case.

    It reports observed objects, correlations, and hypotheses separately.  It
    does not infer data exfiltration, successful compromise, business harm, or
    causation merely from a connection, timestamp, filename, or graph path.
    """

    def __init__(self, database: Database, *, max_depth: int = 5, max_nodes: int = 1000):
        if max_depth < 0:
            raise ValueError("max_depth cannot be negative")
        if max_nodes < 1:
            raise ValueError("max_nodes must be positive")
        self.database = database
        self.max_depth = max_depth
        self.max_nodes = max_nodes

    def analyze(self, case_id: int, entry_path: str = "") -> ImpactAssessment:
        case = self.database.get_case(case_id)
        if case is None:
            raise KeyError(f"case {case_id} does not exist")
        effective_path = str(entry_path or case.suspect_path or "")
        evidence = self.database.list_evidence(case_id)
        relations = self.database.list_relations(case_id)
        coverage_gaps = self.database.list_gaps(case_id)
        by_key = {item.stable_key: item for item in evidence}
        entry_keys = self._entry_keys(evidence, relations, effective_path)
        limitations = [
            "The assessment contains only evidence present in this case; missing host telemetry remains unknown.",
            "Network activity is not proof of data transfer or exfiltration.",
            "File, process, and persistence relations describe recorded activity, not quantified damage or business impact.",
        ]
        if coverage_gaps:
            limitations.append(
                f"The case records {len(coverage_gaps)} collection coverage gap(s); unobserved activity cannot be reconstructed."
            )
        if not entry_keys:
            limitations.append(
                "No exact entry artifact was found, so no affected-object chain can be attributed."
            )
            return ImpactAssessment(
                case_id=case_id,
                entry_path=effective_path,
                entry_keys=(),
                findings=(),
                complete=False,
                limitations=tuple(limitations),
                coverage_gap_count=len(coverage_gaps),
            )

        forward: dict[str, list[RelationRecord]] = defaultdict(list)
        reverse_ancestry: dict[str, list[RelationRecord]] = defaultdict(list)
        for relation in relations:
            if relation.source_key in by_key and relation.target_key in by_key:
                forward[relation.source_key].append(relation)
                if relation.relation_type.casefold() in _REVERSE_ANCESTRY_RELATIONS:
                    reverse_ancestry[relation.target_key].append(relation)

        # Heap ordering prefers stronger evidence before weaker graph paths.
        queue: list[tuple[int, int, int, str, str, tuple[str, ...], tuple[str, ...], bool]] = []
        serial = 0
        for key in entry_keys:
            heapq.heappush(
                queue,
                (0, 0, serial, key, "observed", (), (key,), False),
            )
            serial += 1

        best: dict[str, tuple[int, int]] = {}
        findings: dict[str, ImpactFinding] = {}
        truncated = False
        while queue:
            rank, depth, _, key, basis, relation_path, evidence_path, terminal = heapq.heappop(
                queue
            )
            previous = best.get(key)
            if previous is not None and previous <= (rank, depth):
                continue
            if len(best) >= self.max_nodes:
                truncated = True
                break
            best[key] = (rank, depth)
            item = by_key.get(key)
            if item is None:
                continue
            is_entry = key in entry_keys
            category = _category(item, entry=is_entry)
            if category and category != "detection":
                if is_entry:
                    rationale = "Exact case entry artifact or explicitly marked seed evidence."
                elif relation_path:
                    rationale = (
                        f"Connected through recorded relation chain: {' -> '.join(relation_path)}. "
                        "This chain does not by itself prove causation or quantify harm."
                    )
                else:
                    rationale = "Evidence object present in the case."
                findings[key] = ImpactFinding(
                    stable_key=key,
                    entity_type=item.entity_type,
                    label=item.label,
                    category=category,
                    basis=basis,
                    confidence=_confidence_for_basis(basis),
                    depth=depth,
                    relation_path=relation_path,
                    evidence_path=evidence_path,
                    rationale=rationale,
                    observed_at=item.observed_at,
                    properties=dict(item.properties),
                )

            if terminal or depth >= self.max_depth:
                continue

            for relation in forward.get(key, ()):
                target = relation.target_key
                edge_basis = _edge_basis(relation)
                next_basis = _combine_basis(basis, edge_basis)
                heapq.heappush(
                    queue,
                    (
                        _BASIS_RANK[next_basis],
                        depth + 1,
                        serial,
                        target,
                        next_basis,
                        relation_path + (relation.relation_type,),
                        evidence_path + (target,),
                        False,
                    ),
                )
                serial += 1

            # A parent can help explain provenance, but reverse traversal is
            # deliberately terminal so a shared parent cannot pull unrelated
            # sibling processes into the alleged impact chain.
            for relation in reverse_ancestry.get(key, ()):
                source = relation.source_key
                next_basis = _combine_basis(basis, _edge_basis(relation, reverse=True))
                heapq.heappush(
                    queue,
                    (
                        _BASIS_RANK[next_basis],
                        depth + 1,
                        serial,
                        source,
                        next_basis,
                        relation_path + (f"reverse:{relation.relation_type}",),
                        evidence_path + (source,),
                        True,
                    ),
                )
                serial += 1

        if truncated:
            limitations.append(
                f"Graph traversal stopped at the safety limit of {self.max_nodes} objects."
            )
        ordered = sorted(
            findings.values(),
            key=lambda item: (
                item.depth,
                _BASIS_RANK[item.basis],
                item.category,
                item.observed_at,
                item.stable_key,
            ),
        )
        return ImpactAssessment(
            case_id=case_id,
            entry_path=effective_path,
            entry_keys=tuple(entry_keys),
            findings=tuple(ordered),
            complete=not truncated and not coverage_gaps,
            limitations=tuple(limitations),
            coverage_gap_count=len(coverage_gaps),
        )

    @staticmethod
    def _entry_keys(
        evidence: list[EvidenceRecord],
        relations: list[RelationRecord],
        entry_path: str,
    ) -> list[str]:
        normalized = _normalized_path(entry_path)
        keys: list[str] = []
        for item in evidence:
            exact_path = (
                normalized
                and item.entity_type.casefold() in (_FILE_TYPES | _DETECTION_TYPES)
                and any(
                    _normalized_path(value) == normalized
                    for value in _candidate_paths(item)
                )
            )
            if bool(item.properties.get("is_seed")) or exact_path:
                keys.append(item.stable_key)

        if not keys:
            confirmed = {
                item.stable_key
                for item in evidence
                if item.entity_type == "malware_detection"
                and item.properties.get("confirmed_malware") is True
            }
            keys.extend(sorted(confirmed))
            # A confirmed detection is useful as an entry only together with
            # the file explicitly named by that detection relation.
            keys.extend(
                relation.source_key
                for relation in relations
                if relation.relation_type == "detected_as"
                and relation.target_key in confirmed
            )
        return list(dict.fromkeys(keys))


def analyze_impact(
    database: Database,
    case_id: int,
    entry_path: str = "",
    *,
    max_depth: int = 5,
    max_nodes: int = 1000,
) -> ImpactAssessment:
    return ImpactAnalyzer(
        database, max_depth=max_depth, max_nodes=max_nodes
    ).analyze(case_id, entry_path)


__all__ = [
    "ImpactAnalyzer",
    "ImpactAssessment",
    "ImpactFinding",
    "analyze_impact",
]
