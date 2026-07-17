from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
import csv
from hashlib import sha256
from html import escape
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from . import __version__
from .impact import ImpactAnalyzer
from .presentation import entity_group


@dataclass(slots=True)
class ExportResult:
    zip_path: Path
    sha256: str
    manifest_sha256: str
    file_count: int


def _record(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "keys"):
        return {key: value[key] for key in value.keys()}
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    return {"value": str(value)}


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return value


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return asdict(value)
    return str(value)


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-zА-Яа-я0-9._-]+", "_", value, flags=re.UNICODE).strip("._")
    return cleaned[:70] or "case"


def _csv_safe(value: Any) -> str:
    """Prevent spreadsheet formula execution when investigators open CSV."""
    rendered = value if isinstance(value, str) else str(value)
    if rendered.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + rendered
    return rendered


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_FORBIDDEN_RAW_SUFFIXES = {
    ".7z",
    ".cab",
    ".dll",
    ".exe",
    ".rar",
    ".sys",
    ".zip",
}

_SOURCE_URL_FIELDS = {
    "url": "Точный URL",
    "hosturl": "HostUrl",
    "referrerurl": "ReferrerUrl",
    "sourceurl": "URL источника",
    "downloadurl": "URL загрузки",
    "originurl": "URL происхождения",
}
_REMOVABLE_MEDIA_FIELDS = {
    "pnpdeviceid": "PNP Device ID",
    "deviceid": "Device ID",
    "instanceid": "Instance ID",
    "uniqueid": "Unique ID",
    "serialnumber": "Серийный номер устройства",
    "deviceserialnumber": "Серийный номер устройства",
    "diskserialnumber": "Серийный номер диска",
    "volumeserialnumber": "Серийный номер тома",
    "volumeserial": "Серийный номер тома",
    "volumeguid": "GUID тома",
    "driveletter": "Буква диска",
    "drivetypename": "Тип тома",
    "mountpoint": "Точка монтирования",
    "volumelabel": "Метка тома",
    "friendlyname": "Имя устройства",
    "manufacturer": "Производитель",
    "model": "Модель",
    "diskmodel": "Модель диска",
    "diskinterfacetype": "Интерфейс диска",
    "diskmediatype": "Тип носителя",
    "diskdeviceid": "Device ID диска",
    "vendorid": "Vendor ID",
    "productid": "Product ID",
    "vid": "USB VID",
    "pid": "USB PID",
    "bustype": "Тип шины",
    "filesystem": "Файловая система",
}
_DELIVERY_SOURCE_FIELDS = {
    "channel": "Канал",
    "sender": "Отправитель",
    "recipient": "Получатель",
    "messageid": "Message ID",
    "attachment": "Вложение",
    "attachmentname": "Имя вложения",
}


def _relative_posix(path: Path, root: Path) -> str:
    relative = path.relative_to(root)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Unsafe bundle path: {relative}")
    rendered = relative.as_posix()
    if not rendered or rendered.startswith("/") or "\\" in rendered:
        raise ValueError(f"Unsafe bundle path: {rendered}")
    return rendered


def _is_reparse_or_link(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _validate_raw_report_source(path: Path) -> os.stat_result:
    """Return lstat metadata only for an absolute, stable regular file.

    Parent components are checked too: accepting a report through a junction or
    symlink would make the absolute path check meaningless on Windows.
    """

    if not path.is_absolute():
        raise ValueError("AVZ report path must be absolute")
    components = [path, *path.parents]
    try:
        for component in components:
            if _is_reparse_or_link(component):
                raise ValueError("AVZ report path must not contain symlinks or reparse points")
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError("AVZ report source does not exist") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("AVZ report source must be a regular file")
    return metadata


def _bundle_files(root: Path, *, excluded: set[str] | None = None) -> list[Path]:
    excluded = excluded or set()
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"Symlink is not allowed in export staging: {path.name}")
        if not path.is_file():
            continue
        relative = _relative_posix(path, root)
        if relative in excluded:
            continue
        if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
            raise ValueError(f"Non-regular file is not allowed in export: {relative}")
        files.append(path)
    return sorted(files, key=lambda item: _relative_posix(item, root).casefold())


class CaseExporter:
    """Export a self-contained, integrity-verifiable investigation bundle."""

    def __init__(self, database: Any) -> None:
        self.database = database

    def export(self, case_id: int, destination: str | Path) -> ExportResult:
        case = _record(self.database.get_case(case_id))
        if not case:
            raise ValueError(f"Кейс {case_id} не найден")
        destination = Path(destination)
        if destination.suffix.lower() != ".zip":
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            destination = destination / f"NodeTraceIR_{_safe_name(str(case.get('title', case_id)))}_{stamp}.zip"
        destination.parent.mkdir(parents=True, exist_ok=True)

        try:
            self.database.log_action(case_id, "export_started", {"destination": str(destination)})
        except Exception:
            pass

        evidence = [_record(row) for row in self.database.list_evidence(case_id)]
        timeline = self._optional_rows("list_timeline", case_id)
        relations = [_record(row) for row in self.database.list_relations(case_id)]
        gaps = [_record(row) for row in self.database.list_gaps(case_id)]
        actions = self._optional_rows("list_analyst_log", case_id)
        runs = self._optional_rows("list_collection_runs", case_id)
        artifacts = self._optional_rows("list_artifacts", case_id)
        impact_assessment = ImpactAnalyzer(self.database).analyze(case_id).as_dict()

        for row in evidence:
            row["properties"] = _json_value(row.get("properties", {}))
            row["raw"] = _json_value(row.get("raw", {}))
        for artifact in artifacts:
            artifact["properties"] = _json_value(artifact.get("properties", {}))
            artifact["included_in_bundle"] = False

        with tempfile.TemporaryDirectory(prefix="nodetrace_ir_export_") as temporary:
            root = Path(temporary) / "NodeTraceIR_Case"
            root.mkdir()
            self._copy_verified_avz_reports(root, artifacts)
            payload = {
                "schema": "nodetrace-ir/case-export/v1",
                "export_profile": f"detector-first/{__version__}",
                "exported_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                "application_version": __version__,
                "case": case,
                "evidence": evidence,
                "timeline": timeline,
                "relations": relations,
                "coverage_gaps": gaps,
                "collection_runs": runs,
                "artifacts": artifacts,
                "impact_assessment": impact_assessment,
                "analyst_log": actions,
            }
            (root / "case.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default),
                encoding="utf-8",
            )
            (root / "impact.json").write_text(
                json.dumps(
                    {
                        "schema": "nodetrace-ir/impact-assessment/v1",
                        **impact_assessment,
                    },
                    ensure_ascii=False,
                    indent=2,
                    default=_json_default,
                ),
                encoding="utf-8",
            )
            graph_payload = {
                "nodes": evidence,
                "edges": relations,
            }
            (root / "graph.json").write_text(
                json.dumps(graph_payload, ensure_ascii=False, indent=2, default=_json_default),
                encoding="utf-8",
            )
            graph_svg = self._svg_graph(evidence, relations)
            (root / "graph.svg").write_text(graph_svg, encoding="utf-8")
            self._write_csv(root / "evidence.csv", evidence)
            self._write_csv(root / "timeline.csv", timeline)
            (root / "report.html").write_text(
                self._html(
                    case,
                    evidence,
                    timeline,
                    relations,
                    gaps,
                    runs,
                    actions,
                    impact_assessment,
                    graph_svg=graph_svg,
                ),
                encoding="utf-8",
            )
            (root / "README.txt").write_text(self._bundle_readme(), encoding="utf-8")

            entries = []
            for path in _bundle_files(
                root, excluded={"manifest.json", "SHA256SUMS.txt"}
            ):
                entries.append(
                    {
                        "path": _relative_posix(path, root),
                        "size": path.stat().st_size,
                        "sha256": file_sha256(path),
                    }
                )
            manifest = {
                "schema": "nodetrace-ir/manifest/v1",
                "case_id": case_id,
                "created_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                "hash_algorithm": "SHA-256",
                "files": entries,
                "note": "Manifest hashes exported files. It does not assert that a compromised source OS returned truthful data.",
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            manifest_digest = file_sha256(manifest_path)
            checksums = [f"{entry['sha256']}  {entry['path']}" for entry in entries]
            checksums.append(f"{manifest_digest}  manifest.json")
            (root / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")

            handle = tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{destination.stem}.",
                suffix=".tmp",
                dir=destination.parent,
                delete=False,
            )
            staging = Path(handle.name)
            handle.close()
            try:
                with ZipFile(staging, "w", ZIP_DEFLATED, compresslevel=9) as archive:
                    final_files = _bundle_files(root)
                    for path in final_files:
                        relative = _relative_posix(path, root)
                        archive.write(path, arcname=f"NodeTraceIR_Case/{relative}")
                os.replace(staging, destination)
            finally:
                staging.unlink(missing_ok=True)

        result = ExportResult(
            zip_path=destination,
            sha256=file_sha256(destination),
            manifest_sha256=manifest_digest,
            file_count=len(final_files),
        )
        try:
            self.database.log_action(
                case_id,
                "export_completed",
                {"destination": str(destination), "sha256": result.sha256, "manifest_sha256": manifest_digest},
            )
        except Exception:
            pass
        return result

    @staticmethod
    def _copy_verified_avz_reports(
        root: Path, artifacts: list[dict[str, Any]]
    ) -> None:
        """Copy only byte-verified original AVZ reports into ``raw/avz``.

        All other registered artifacts remain metadata-only.  In particular,
        preserved evidence, AVZ executables, signature bases, archives, and
        quarantine content can never enter an analyst-facing export here.
        """

        used_names: set[str] = set()
        for ordinal, artifact in enumerate(artifacts, start=1):
            if str(artifact.get("kind", "")).casefold() != "avz_report":
                continue
            source = Path(str(artifact.get("path") or ""))
            source_parts = [part.casefold() for part in source.parts]
            source_name = source.name.casefold()
            if (
                source.suffix.casefold() in _FORBIDDEN_RAW_SUFFIXES
                or any("quarantine" in part for part in source_parts)
                or source_name in {"avz", "avz.exe", "avz4.zip", "avzbase.zip"}
            ):
                raise ValueError("Executable, archive, base, or quarantine content is not an AVZ report")

            expected_sha256 = str(artifact.get("sha256") or "").strip().casefold()
            if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
                raise ValueError("AVZ report artifact must contain a stored SHA-256")
            try:
                expected_size = int(artifact.get("size_bytes"))
            except (TypeError, ValueError) as exc:
                raise ValueError("AVZ report artifact must contain a stored size") from exc
            if expected_size < 0:
                raise ValueError("AVZ report artifact size cannot be negative")

            metadata = _validate_raw_report_source(source)
            if metadata.st_size != expected_size:
                raise ValueError("AVZ report size does not match stored artifact metadata")
            if file_sha256(source).casefold() != expected_sha256:
                raise ValueError("AVZ report SHA-256 does not match stored artifact metadata")

            # Revalidate after the first hash pass, then hash again while
            # copying. This closes ordinary mutation races without trusting a
            # path merely because it was safe at the start of the export.
            metadata = _validate_raw_report_source(source)
            raw_name = _safe_name(source.name or str(artifact.get("name") or "avz-report"))
            if raw_name.casefold() in used_names:
                raw_name = f"{ordinal:03d}_{raw_name}"
            used_names.add(raw_name.casefold())
            destination = root / "raw" / "avz" / raw_name
            destination.parent.mkdir(parents=True, exist_ok=True)

            copied_digest = sha256()
            copied_size = 0
            try:
                with source.open("rb") as input_stream, destination.open("xb") as output_stream:
                    opened = os.fstat(input_stream.fileno())
                    if not stat.S_ISREG(opened.st_mode):
                        raise ValueError("AVZ report changed into a non-regular file")
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise ValueError("AVZ report changed while the export was prepared")
                    for block in iter(lambda: input_stream.read(1024 * 1024), b""):
                        output_stream.write(block)
                        copied_digest.update(block)
                        copied_size += len(block)
                    after = os.fstat(input_stream.fileno())
                    if after.st_size != opened.st_size:
                        raise ValueError("AVZ report changed while it was copied")
                if copied_size != expected_size:
                    raise ValueError("Copied AVZ report size does not match stored metadata")
                if copied_digest.hexdigest().casefold() != expected_sha256:
                    raise ValueError("Copied AVZ report SHA-256 does not match stored metadata")
                if (
                    destination.stat().st_size != expected_size
                    or file_sha256(destination).casefold() != expected_sha256
                ):
                    raise ValueError("Exported AVZ report failed its final integrity check")
            except Exception:
                destination.unlink(missing_ok=True)
                raise

            artifact["included_in_bundle"] = True
            artifact["exported_path"] = _relative_posix(destination, root)

    def _optional_rows(self, method_name: str, case_id: int) -> list[dict[str, Any]]:
        method = getattr(self.database, method_name, None)
        if method is None:
            return []
        try:
            return [_record(row) for row in method(case_id)]
        except Exception:
            return []

    @staticmethod
    def _write_csv(path: Path, evidence: list[dict[str, Any]]) -> None:
        fields = [
            "id",
            "entity_type",
            "label",
            "observed_at",
            "source",
            "source_ref",
            "confidence",
            "severity",
            "stable_key",
            "evidence_digest",
            "properties",
        ]
        with path.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in evidence:
                export_row = dict(row)
                export_row["properties"] = json.dumps(row.get("properties", {}), ensure_ascii=False, default=_json_default)
                writer.writerow({key: _csv_safe(value) for key, value in export_row.items()})

    def _html(
        self,
        case: dict[str, Any],
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
        relations: list[dict[str, Any]],
        gaps: list[dict[str, Any]],
        runs: list[dict[str, Any]],
        actions: list[dict[str, Any]],
        impact_assessment: dict[str, Any],
        *,
        graph_svg: str | None = None,
    ) -> str:
        counts: dict[str, int] = {}
        for item in evidence:
            counts[str(item.get("entity_type", "artifact"))] = counts.get(str(item.get("entity_type", "artifact")), 0) + 1
        graph_svg = graph_svg or self._svg_graph(evidence, relations)
        timeline_rows = "".join(self._timeline_row(item) for item in sorted(timeline or evidence, key=lambda row: str(row.get("observed_at", ""))))
        evidence_cards = "".join(self._evidence_card(item) for item in evidence)
        gap_cards = "".join(self._gap_card(item) for item in gaps) or '<div class="empty">Заявленных пробелов нет. Это не означает полноту телеметрии.</div>'
        relation_rows = "".join(self._relation_row(item, evidence) for item in relations)
        entity_chips = "".join(f'<span class="chip">{escape(key)} · {value}</span>' for key, value in sorted(counts.items()))
        findings = list(impact_assessment.get("findings") or [])
        source_findings = [item for item in findings if item.get("category") == "source"]
        entry_findings = [item for item in findings if item.get("category") == "entry"]
        process_findings = [item for item in findings if item.get("category") == "process"]
        affected_findings = [
            item
            for item in findings
            if item.get("category") in {"file", "persistence", "network"}
        ]
        avz_detections = [
            item
            for item in evidence
            if str(item.get("entity_type", "")).casefold() == "malware_detection"
            and (
                "avz" in str(item.get("source", "")).casefold()
                or str((item.get("properties") or {}).get("scanner", "")).casefold()
                == "avz"
            )
        ]
        avz_gaps = [
            item
            for item in gaps
            if str(item.get("collector", "")).casefold() == "avz_detection"
        ]
        detection_cards = "".join(self._detection_card(item) for item in avz_detections)
        if not detection_cards:
            reason = (
                "; ".join(str(item.get("reason", "")) for item in avz_gaps if item.get("reason"))
                or "В принятой телеметрии нет обнаружений AVZ."
            )
            detection_cards = (
                '<div class="empty"><b>Детектирование не дало принятого срабатывания.</b><br>'
                f'{escape(reason)} Это означает только «не обнаружено в проверенном объёме», а не «узел чист».</div>'
            )
        entry_cards = "".join(
            self._impact_card(item) for item in (source_findings + entry_findings)
        )
        if not entry_cards:
            entry_cards = '<div class="empty">Канал поступления не установлен по имеющимся артефактам.</div>'
        source_detail_cards = "".join(
            self._source_provenance_card(item) for item in source_findings
        )
        if not source_detail_cards:
            source_detail_cards = (
                '<div class="empty">Точный URL или идентификаторы съёмного носителя '
                'не установлены по связанным показаниям кейса.</div>'
            )
        process_cards = "".join(self._impact_card(item) for item in process_findings)
        if not process_cards:
            process_cards = '<div class="empty">Затронутые процессы не подтверждены имеющимися связями.</div>'
        affected_cards = "".join(self._impact_card(item) for item in affected_findings)
        if not affected_cards:
            affected_cards = '<div class="empty">Файлы, закрепление и сетевые объекты воздействия не установлены.</div>'
        impact_limitations = "".join(
            f"<li>{escape(str(item))}</li>"
            for item in impact_assessment.get("limitations") or []
        )
        basis_legend = (
            '<div class="basis-legend">Основание: '
            '<span class="badge observed">observed · наблюдаемый факт</span> '
            '<span class="badge correlated">correlated · корреляция</span> '
            '<span class="badge hypothesis">hypothesis · гипотеза</span></div>'
        )
        title = escape(str(case.get("title", f"Кейс {case.get('id', '')}")))
        suspect = escape(str(case.get("suspect_path") or "не указан"))
        host = escape(str(case.get("host") or case.get("hostname") or "локальный узел"))
        created = escape(str(case.get("created_at") or case.get("created_at_utc") or ""))
        status = escape(str(case.get("status") or "open"))
        entry_path = escape(
            str(
                impact_assessment.get("entry_path")
                or case.get("suspect_path")
                or "не установлен"
            )
        )
        source_label = escape(
            str(source_findings[0].get("label"))
            if source_findings
            else "Источник не установлен"
        )
        source_basis = escape(
            str(source_findings[0].get("basis") or "unknown")
            if source_findings
            else "нет показаний"
        )
        file_label = escape(
            str(entry_findings[0].get("label"))
            if entry_findings
            else str(impact_assessment.get("entry_path") or "Файл не установлен")
        )
        impact_label = escape(
            f"Процессы: {len(process_findings)} · объекты: {len(affected_findings)}"
        )
        generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        graph_limit_note = (
            f" В HTML и graph.svg показаны 160 приоритетных узлов из {len(evidence)}; полный набор сохранён в graph.json."
            if len(evidence) > 160 else ""
        )
        return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NodeTrace IR — {title}</title>
<style>
:root{{--bg:#08111f;--panel:#101c2f;--panel2:#15243a;--line:#26364d;--text:#e6edf7;--muted:#91a3bb;--accent:#2dd4bf;--red:#ef4444;--yellow:#f59e0b;--blue:#38bdf8}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",Arial,sans-serif}}
header{{padding:28px 36px 22px;background:linear-gradient(130deg,#101e34,#0f2b36);border-bottom:1px solid var(--line)}}
.brand{{font-size:13px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);font-weight:700}} h1{{margin:7px 0 4px;font-size:28px}} h2{{margin:0 0 16px;font-size:19px}} h3{{margin:0 0 8px;font-size:15px}}
.sub{{color:var(--muted)}} nav{{position:sticky;top:0;z-index:3;padding:10px 36px;background:#0b1627ee;border-bottom:1px solid var(--line);backdrop-filter:blur(10px)}} nav a{{color:#b8c7da;text-decoration:none;margin-right:22px;font-size:13px}} nav a:hover{{color:white}}
main{{max-width:1500px;margin:0 auto;padding:26px 34px 70px}} section{{margin:0 0 26px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px}}
.grid{{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:13px}} .metric{{background:var(--panel2);border:1px solid var(--line);border-radius:11px;padding:15px}} .metric b{{display:block;font-size:24px}} .metric span{{color:var(--muted)}}
.facts{{display:grid;grid-template-columns:170px 1fr;gap:7px 14px;margin-top:18px}} .facts dt{{color:var(--muted)}} .facts dd{{margin:0;word-break:break-word}} .chip{{display:inline-block;padding:5px 9px;margin:5px 5px 0 0;background:#1b2b42;border:1px solid #31435d;border-radius:999px;color:#c8d5e5;font-size:12px}}
.notice{{padding:14px 16px;border-left:4px solid var(--yellow);background:#2a2316;color:#f5dfac;border-radius:7px;margin-top:16px}} .graph{{overflow:auto;background:#091423;border-radius:10px;border:1px solid var(--line);padding:8px}} .graph svg{{display:block;width:100%;height:auto}} a{{color:#67e8f9}}
table{{width:100%;border-collapse:collapse}} th{{text-align:left;color:#98abc2;font-size:12px;text-transform:uppercase;letter-spacing:.04em}} td,th{{padding:10px 9px;border-bottom:1px solid #223248;vertical-align:top}} tr:hover td{{background:#13223a}} .mono{{font-family:Consolas,monospace;font-size:12px;word-break:break-all}}
.badge{{display:inline-block;border-radius:999px;padding:3px 7px;font-size:11px;font-weight:700;background:#243550}} .high,.critical{{background:#5e2028;color:#fecdd3}} .medium{{background:#5a4519;color:#fde68a}} .low{{background:#173d46;color:#a5f3fc}}
.observed{{background:#164e3f;color:#a7f3d0}} .correlated{{background:#164e63;color:#bae6fd}} .hypothesis{{background:#5a4519;color:#fde68a}} .basis-legend{{margin:0 0 14px;color:var(--muted)}} .basis-legend .badge{{margin:4px 3px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:12px}} .card{{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:15px}} .card .meta{{color:var(--muted);font-size:12px;margin-bottom:8px}} details{{margin-top:9px}} pre{{white-space:pre-wrap;word-break:break-word;background:#091423;padding:10px;border-radius:7px;color:#b9c8db;max-height:360px;overflow:auto}} .empty{{color:var(--muted);padding:20px;text-align:center}}
.gap{{border-left:4px solid var(--yellow)}} footer{{color:var(--muted);font-size:12px;margin-top:28px}} .path{{padding:10px 12px;background:#091423;border:1px solid var(--line);border-radius:8px;margin-bottom:14px}}
.causal-chain{{display:grid;grid-template-columns:minmax(0,1fr) 42px minmax(0,1fr) 42px minmax(0,1fr);align-items:stretch;gap:8px;margin:14px 0 18px}} .chain-node{{min-height:104px;padding:15px 16px;border:1px solid var(--line);border-radius:11px;background:linear-gradient(145deg,#14243a,#0c1929)}} .chain-node b{{display:block;color:var(--accent);font-size:11px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px}} .chain-node strong{{display:block;font-size:15px;word-break:break-word}} .chain-node span{{display:block;margin-top:7px;color:var(--muted);font-size:12px}} .chain-arrow{{align-self:center;text-align:center;color:var(--accent);font-size:27px;font-weight:700}}
.source-details{{display:grid;grid-template-columns:minmax(150px,220px) 1fr;gap:7px 13px;margin:12px 0 0}} .source-details dt{{color:var(--muted)}} .source-details dd{{margin:0;overflow-wrap:anywhere}} .source-caveat{{color:#f5dfac;border-top:1px solid var(--line);padding-top:11px;margin:13px 0 0}}
@media(max-width:850px){{.grid{{grid-template-columns:1fr 1fr}}main{{padding:18px}}nav{{padding-left:18px}}}}
@media(max-width:720px){{.causal-chain{{grid-template-columns:1fr}}.chain-arrow{{transform:rotate(90deg)}}}}
@media print{{nav{{display:none}}body{{background:white;color:#111}}section,.card,.metric{{break-inside:avoid;background:white;border-color:#ccc}}header{{background:white;color:#111}}.sub,.meta,dt{{color:#555!important}}}}
</style></head><body>
<header><div class="brand">NodeTrace IR · detector-first расследование</div><h1>{title}</h1><div class="sub">Узел: {host} · создан: {created} · статус: {status}</div></header>
<nav><a href="#summary">Сводка</a><a href="#avz-detection">AVZ</a><a href="#entry">Как попало</a><a href="#processes">Процессы</a><a href="#impact">Что затронуто</a><a href="#timeline">Таймлайн</a><a href="#gaps">Пробелы</a></nav>
<main>
<section id="summary"><h2>Сводка расследования</h2><div class="grid"><div class="metric"><b>{len(avz_detections)}</b><span>срабатываний AVZ</span></div><div class="metric"><b>{len(process_findings)}</b><span>затронутых процессов</span></div><div class="metric"><b>{len(affected_findings)}</b><span>прочих затронутых объектов</span></div><div class="metric"><b>{len(gaps)}</b><span>пробелов телеметрии</span></div></div>
<dl class="facts"><dt>Подозрительный файл</dt><dd class="mono">{suspect}</dd><dt>Идентификатор</dt><dd>{escape(str(case.get('id','')))}</dd><dt>Сформирован UTC</dt><dd>{generated}</dd></dl>
<div>{entity_chips}</div><div class="notice"><b>Граница достоверности.</b> AVZ используется как детектор и источник системного отчёта, а не как доказательство способа заражения или размера ущерба. Отчёт разделяет observed, correlated и hypothesis. Без заранее включённых Sysmon/EDR и политик аудита невозможно доказать полную последовательность всех действий. Временная близость сама по себе не является причинностью.</div></section>
<section id="avz-detection"><h2>Детектирование AVZ</h2><div class="sub">Сначала показан принятый вердикт детектора. Эвристическое подозрение требует проверки аналитиком; отсутствие срабатывания не доказывает чистоту узла.</div><div class="cards">{detection_cards}</div></section>
<section id="entry"><h2>Цепочка инцидента: откуда → файл → воздействие</h2>{basis_legend}<div class="causal-chain"><div class="chain-node"><b>1 · Откуда попал</b><strong>{source_label}</strong><span>Основание: {source_basis}</span></div><div class="chain-arrow">→</div><div class="chain-node"><b>2 · Файл</b><strong>{file_label}</strong><span class="mono">{entry_path}</span></div><div class="chain-arrow">→</div><div class="chain-node"><b>3 · Воздействие</b><strong>{impact_label}</strong><span>Только связанные показания кейса</span></div></div><h3>Детализация источника</h3><div class="cards">{source_detail_cards}</div><h3 style="margin-top:18px">Основание цепочки</h3><div class="cards">{entry_cards}</div><div class="notice"><b>Не переоценивать.</b> URL из Zone.Identifier является сохранённым показанием метаданных, а идентификаторы USB описывают наблюдавшийся носитель. Ни то ни другое само по себе не доказывает, что именно этот сайт или носитель исторически доставил файл. «Источник не установлен» означает, что канал доставки нельзя доказать по доступной телеметрии.</div></section>
<section id="processes"><h2>Затронутые процессы</h2>{basis_legend}<div class="cards">{process_cards}</div><div class="notice"><b>Не переоценивать.</b> Корреляция с процессом не равна доказанному выполнению вредоносного кода или управлению процессом. Основание каждого вывода указано на карточке.</div></section>
<section id="impact"><h2>Что затронуто</h2>{basis_legend}<div class="cards">{affected_cards}</div><div class="notice"><b>Не переоценивать ущерб.</b> Наблюдавшийся файл, механизм закрепления или сетевой адрес не доказывает уничтожение данных, кражу учётных данных, эксфильтрацию или бизнес-ущерб. Эти утверждения требуют отдельных артефактов.</div><h3 style="margin-top:18px">Ограничения оценки</h3><ul>{impact_limitations}</ul></section>
<section id="graph"><h2>Граф воздействия</h2><div class="sub">Сплошные связи лучше подтверждены; пунктиром отмечены гипотезы низкой уверенности. <a href="graph.svg">Откройте graph.svg</a> для масштабирования без потери качества, graph.json — для машинной обработки.{graph_limit_note}</div><div class="graph">{graph_svg}</div></section>
<section id="timeline"><h2>Временная шкала</h2><div style="overflow:auto"><table id="timelineTable"><thead><tr><th>Время</th><th>Тип</th><th>Событие</th><th>Источник</th><th>Уверенность</th></tr></thead><tbody>{timeline_rows}</tbody></table></div></section>
<section id="relations"><h2>Обоснование связей</h2><div style="overflow:auto"><table><thead><tr><th>Источник</th><th>Связь</th><th>Цель</th><th>Уверенность</th><th>Основание</th></tr></thead><tbody>{relation_rows}</tbody></table></div></section>
<section id="evidence"><h2>Карточки доказательств</h2><div class="cards">{evidence_cards}</div></section>
<section id="gaps"><h2>Пробелы и ограничения</h2><div class="cards">{gap_cards}</div></section>
<footer>NodeTrace IR {__version__}. Целостность файлов набора проверяется по manifest.json и SHA256SUMS.txt. SHA-256 подтверждает неизменность выгрузки после формирования, но не истинность ответов с уже скомпрометированной ОС.</footer>
</main></body></html>"""

    @staticmethod
    def _timeline_row(item: dict[str, Any]) -> str:
        severity = escape(str(item.get("severity", "info")))
        confidence = escape(str(item.get("confidence", "medium")))
        return (
            "<tr>"
            f"<td class='mono'>{escape(str(item.get('observed_at', '')))}</td>"
            f"<td>{escape(str(item.get('entity_type', 'artifact')))}</td>"
            f"<td>{escape(str(item.get('label', '')))} <span class='badge {severity}'>{severity}</span></td>"
            f"<td>{escape(str(item.get('source', '')))}</td>"
            f"<td><span class='badge {confidence}'>{confidence}</span></td>"
            "</tr>"
        )

    @staticmethod
    def _detection_card(item: dict[str, Any]) -> str:
        properties = item.get("properties") or {}
        rendered = json.dumps(
            properties, ensure_ascii=False, indent=2, default=_json_default
        )
        verdict = escape(str(properties.get("verdict") or "не указан"))
        confidence = escape(str(item.get("confidence", "medium")))
        severity = escape(str(item.get("severity", "info")))
        return f"""<article class="card" data-basis="observed"><h3>{escape(str(item.get('label','Срабатывание AVZ')))}</h3>
<div class="meta">{escape(str(item.get('source','AVZ')))} · {escape(str(item.get('observed_at','')))}</div>
<span class="badge observed">observed</span> <span class="badge {severity}">{severity}</span> <span class="badge {confidence}">{confidence}</span>
<p><b>Вердикт детектора:</b> {verdict}</p><details><summary>Свойства срабатывания</summary><pre>{escape(rendered)}</pre></details></article>"""

    @staticmethod
    def _impact_card(item: dict[str, Any]) -> str:
        basis = str(item.get("basis") or "hypothesis").casefold()
        if basis not in {"observed", "correlated", "hypothesis"}:
            basis = "hypothesis"
        properties = json.dumps(
            item.get("properties") or {},
            ensure_ascii=False,
            indent=2,
            default=_json_default,
        )
        relation_path = " → ".join(str(value) for value in item.get("relation_path") or [])
        path_line = (
            f"<p><b>Цепочка:</b> {escape(relation_path)}</p>" if relation_path else ""
        )
        return f"""<article class="card" data-basis="{basis}"><h3>{escape(str(item.get('label','Объект')))}</h3>
<div class="meta">{escape(str(item.get('category','object')))} · {escape(str(item.get('entity_type','artifact')))} · глубина {escape(str(item.get('depth',0)))}</div>
<span class="badge {basis}">{basis}</span> <span class="badge {escape(str(item.get('confidence','low')))}">{escape(str(item.get('confidence','low')))}</span>
<p>{escape(str(item.get('rationale','Основание не указано.')))}</p>{path_line}
<details><summary>Свойства объекта</summary><pre>{escape(properties)}</pre></details></article>"""

    @staticmethod
    def _source_provenance_card(item: dict[str, Any]) -> str:
        """Render only explicit provenance values preserved with source evidence.

        The report deliberately does not infer a missing URL, USB serial, or
        historical delivery event from a filename, drive letter, or timestamp.
        Nested collector payloads are supported, but only a small allowlist of
        provenance fields is promoted into the human-readable summary.
        """

        properties = item.get("properties") or {}
        flattened: list[tuple[str, Any]] = []

        def visit(value: Any, *, depth: int = 0) -> None:
            if depth > 4 or not isinstance(value, dict):
                return
            for key, child in value.items():
                normalized = re.sub(r"[^a-z0-9]+", "", str(key).casefold())
                if isinstance(child, dict):
                    visit(child, depth=depth + 1)
                elif isinstance(child, (list, tuple)):
                    scalar_values = [
                        str(part) for part in child if isinstance(part, (str, int, float, bool))
                    ]
                    if scalar_values:
                        flattened.append((normalized, ", ".join(scalar_values)))
                elif isinstance(child, (str, int, float, bool)) and str(child).strip():
                    flattened.append((normalized, child))

        visit(properties)
        recognized = {
            **_SOURCE_URL_FIELDS,
            **_REMOVABLE_MEDIA_FIELDS,
            **_DELIVERY_SOURCE_FIELDS,
        }
        rows: list[str] = []
        seen: set[tuple[str, str]] = set()
        has_url = False
        has_media_identifier = False
        for field, value in flattened:
            caption = recognized.get(field)
            if caption is None:
                continue
            rendered = str(value)
            identity = (caption.casefold(), rendered.casefold())
            if identity in seen:
                continue
            seen.add(identity)
            has_url = has_url or field in _SOURCE_URL_FIELDS
            has_media_identifier = has_media_identifier or field in _REMOVABLE_MEDIA_FIELDS
            rows.append(
                f'<dt>{escape(caption)}</dt><dd class="mono">{escape(rendered)}</dd>'
            )

        entity_type = str(item.get("entity_type") or "source").casefold()
        basis = str(item.get("basis") or "hypothesis").casefold()
        if basis not in {"observed", "correlated", "hypothesis"}:
            basis = "hypothesis"
        confidence = escape(str(item.get("confidence") or "low"))
        if has_url:
            caveat = (
                "URL воспроизведён точно из сохранённых свойств артефакта. "
                "Такие метаданные могут изменяться и сами по себе не доказывают факт загрузки."
            )
        elif has_media_identifier or entity_type == "removable_media":
            caveat = (
                "Идентификаторы описывают носитель, наблюдавшийся при сборе. "
                "Совпадение или наличие файла на нём не доказывает историческую доставку."
            )
        else:
            caveat = (
                "Показаны только сохранённые атрибуты связанного источника; "
                "они не заменяют исходный журнал доставки."
            )
        details = (
            f'<dl class="source-details">{"".join(rows)}</dl>'
            if rows
            else '<p class="sub">Точный URL или идентификатор носителя в свойствах не сохранён.</p>'
        )
        return (
            '<article class="card source-provenance">'
            f'<h3>{escape(str(item.get("label") or "Источник"))}</h3>'
            f'<div class="meta">{escape(entity_type)} · источник, связанный с файлом</div>'
            f'<span class="badge {basis}">{basis}</span> '
            f'<span class="badge {confidence}">{confidence}</span>'
            f'{details}<p class="source-caveat">{escape(caveat)}</p></article>'
        )

    @staticmethod
    def _evidence_card(item: dict[str, Any]) -> str:
        props = json.dumps(item.get("properties", {}), ensure_ascii=False, indent=2, default=_json_default)
        raw = json.dumps(item.get("raw", {}), ensure_ascii=False, indent=2, default=_json_default)
        severity = escape(str(item.get("severity", "info")))
        confidence = escape(str(item.get("confidence", "medium")))
        digest = escape(str(item.get("evidence_digest", "")))
        return f"""<article class="card"><h3>{escape(str(item.get('label','')))}</h3>
<div class="meta">{escape(str(item.get('entity_type','artifact')))} · {escape(str(item.get('source','')))} · {escape(str(item.get('observed_at','')))}</div>
<span class="badge {severity}">{severity}</span> <span class="badge {confidence}">{confidence}</span>
<details><summary>Свойства</summary><pre>{escape(props)}</pre></details><details><summary>Исходная запись</summary><pre>{escape(raw)}</pre></details>
<div class="meta mono">digest: {digest}</div></article>"""

    @staticmethod
    def _gap_card(item: dict[str, Any]) -> str:
        return f"""<article class="card gap"><h3>{escape(str(item.get('source','Источник недоступен')))}</h3>
<div class="meta">Коллектор: {escape(str(item.get('collector','')))}</div><p>{escape(str(item.get('reason','')))}</p>
<p><b>Влияние:</b> {escape(str(item.get('impact','')))}</p><p><b>Рекомендация:</b> {escape(str(item.get('recommendation','')))}</p></article>"""

    @staticmethod
    def _relation_row(item: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
        labels = {row.get("id"): row.get("label", row.get("id")) for row in evidence}
        source_id = item.get("source_evidence_id", item.get("source_id"))
        target_id = item.get("target_evidence_id", item.get("target_id"))
        confidence = escape(str(item.get("confidence", "medium")))
        return (
            "<tr>"
            f"<td>{escape(str(labels.get(source_id, source_id)))}</td>"
            f"<td>{escape(str(item.get('relation_type','связь')).replace('_',' '))}</td>"
            f"<td>{escape(str(labels.get(target_id, target_id)))}</td>"
            f"<td><span class='badge {confidence}'>{confidence}</span></td>"
            f"<td>{escape(str(item.get('rationale','')))}</td>"
            "</tr>"
        )

    @staticmethod
    def _svg_graph(evidence: list[dict[str, Any]], relations: list[dict[str, Any]]) -> str:
        svg_attributes = (
            'xmlns="http://www.w3.org/2000/svg" '
            'preserveAspectRatio="xMidYMid meet" '
            'role="img" aria-label="Граф воздействия" '
            'style="display:block;width:100%;height:auto;max-width:100%;background:#091423"'
        )
        if not evidence:
            return (
                f'<svg {svg_attributes} viewBox="0 0 1200 260">'
                '<title>Граф воздействия</title>'
                '<rect x="0" y="0" width="1200" height="260" fill="#091423"/>'
                '<text x="600" y="135" fill="#91a3bb" font-family="Segoe UI,Arial" '
                'font-size="22" text-anchor="middle">Нет узлов</text></svg>'
            )
        degree: dict[Any, int] = {}
        for relation in relations:
            for node_id in (
                relation.get("source_evidence_id", relation.get("source_id")),
                relation.get("target_evidence_id", relation.get("target_id")),
            ):
                if node_id is not None:
                    degree[node_id] = degree.get(node_id, 0) + 1
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        prioritized = sorted(
            evidence,
            key=lambda row: (
                0 if (row.get("properties") or {}).get("is_seed") or row.get("source") == "filesystem seed" else 1,
                severity_rank.get(str(row.get("severity", "info")), 5),
                -degree.get(row.get("id"), 0),
                0 if row.get("confidence") == "high" else 1,
                str(row.get("observed_at", "")),
            ),
        )
        nodes = {row.get("id"): row for row in prioritized[:160] if row.get("id") is not None}
        if not nodes:
            return (
                f'<svg {svg_attributes} viewBox="0 0 1200 260">'
                '<title>Граф воздействия</title>'
                '<rect x="0" y="0" width="1200" height="260" fill="#091423"/>'
                '<text x="600" y="135" fill="#91a3bb" font-family="Segoe UI,Arial" '
                'font-size="22" text-anchor="middle">Нет узлов с идентификаторами</text></svg>'
            )
        root = next(
            (
                node_id
                for node_id, row in nodes.items()
                if (row.get("properties") or {}).get("is_seed")
                or str(row.get("stable_key", "")).startswith("file:seed")
                or row.get("source") == "filesystem seed"
            ),
            next(iter(nodes)),
        )
        adjacency: dict[Any, set[Any]] = {node_id: set() for node_id in nodes}
        for relation in relations:
            source = relation.get("source_evidence_id", relation.get("source_id"))
            target = relation.get("target_evidence_id", relation.get("target_id"))
            if source in nodes and target in nodes:
                adjacency[source].add(target)
                adjacency[target].add(source)
        distances = {root: 0}
        queue = [root]
        while queue:
            current = queue.pop(0)
            for neighbour in adjacency[current]:
                if neighbour not in distances:
                    distances[neighbour] = distances[current] + 1
                    queue.append(neighbour)
        detached = max(distances.values(), default=0) + 1
        levels: dict[int, list[Any]] = {}
        for node_id in nodes:
            levels.setdefault(distances.get(node_id, detached), []).append(node_id)
        width, height = 1200, 760
        cx, cy = width / 2, height / 2
        positions: dict[Any, tuple[float, float]] = {}
        for level, ids in sorted(levels.items()):
            if level == 0:
                positions[ids[0]] = (cx, cy)
                continue
            radius = 135 + 125 * (level - 1)
            for index, node_id in enumerate(ids):
                angle = -math.pi / 2 + 2 * math.pi * index / max(1, len(ids)) + level * .15
                positions[node_id] = (cx + math.cos(angle) * radius, cy + math.sin(angle) * radius * .67)
        colors = {"file": "#ef4444", "process": "#f97316", "registry": "#eab308", "service": "#eab308", "scheduled_task": "#eab308", "persistence": "#eab308", "ip": "#06b6d4", "domain": "#06b6d4", "network": "#06b6d4", "event": "#3b82f6", "alert": "#dc2626", "user": "#8b5cf6", "prefetch": "#14b8a6", "source": "#d97706"}
        padding_x, padding_y = 95.0, 72.0
        min_x = min(point[0] for point in positions.values()) - padding_x
        max_x = max(point[0] for point in positions.values()) + padding_x
        min_y = min(point[1] for point in positions.values()) - padding_y
        max_y = max(point[1] for point in positions.values()) + padding_y
        view_width = max(320.0, max_x - min_x)
        view_height = max(220.0, max_y - min_y)
        parts = [
            f'<svg {svg_attributes} viewBox="{min_x:.1f} {min_y:.1f} {view_width:.1f} {view_height:.1f}">',
            '<title>Граф воздействия NodeTrace IR</title>',
            '<desc>Векторный граф связанных показаний. Пунктиром отмечены связи низкой уверенности.</desc>',
            f'<rect x="{min_x:.1f}" y="{min_y:.1f}" width="{view_width:.1f}" height="{view_height:.1f}" fill="#091423"/>',
            '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="#64748b"/></marker></defs>',
        ]
        for relation in relations:
            source = relation.get("source_evidence_id", relation.get("source_id"))
            target = relation.get("target_evidence_id", relation.get("target_id"))
            if source not in positions or target not in positions:
                continue
            sx, sy = positions[source]; tx, ty = positions[target]
            dash = ' stroke-dasharray="7 6"' if relation.get("confidence") == "low" else ""
            parts.append(f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{tx:.1f}" y2="{ty:.1f}" stroke="#52647b" stroke-width="2" vector-effect="non-scaling-stroke" marker-end="url(#arrow)"{dash}/>' )
        for node_id, row in nodes.items():
            x, y = positions[node_id]
            entity = str(row.get("entity_type", "artifact"))
            group = entity_group(entity)
            label = str(row.get("label", entity))
            short = label if len(label) <= 28 else label[:25] + "…"
            color = colors.get(entity, colors.get(group, "#64748b"))
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="25" fill="{color}" stroke="#dbeafe" stroke-width="2" vector-effect="non-scaling-stroke"><title>{escape(label)}</title></circle>')
            parts.append(f'<text x="{x:.1f}" y="{y+43:.1f}" fill="#dbeafe" font-family="Segoe UI,Arial" font-size="12" font-weight="600" text-anchor="middle">{escape(short)}</text>')
        parts.append("</svg>")
        return "".join(parts)

    @staticmethod
    def _bundle_readme() -> str:
        return r"""NodeTrace IR — набор материалов расследования

report.html       человекочитаемый автономный отчёт
case.json         полный нормализованный экспорт кейса
impact.json       оценка точки входа и затронутых объектов с основанием вывода
graph.json        узлы и связи графа
graph.svg         автономный масштабируемый векторный граф без внешних ресурсов
evidence.csv      плоский список доказательств
timeline.csv      append-only наблюдения временной шкалы
raw/avz/          исходные отчёты AVZ, включённые только после проверки SHA-256
manifest.json     размеры и SHA-256 экспортированных файлов
SHA256SUMS.txt    контрольные суммы для быстрой проверки

Проверка в PowerShell:
  Get-FileHash .\report.html -Algorithm SHA256
  Get-FileHash .\graph.svg -Algorithm SHA256

report.html содержит тот же SVG-граф внутри страницы. graph.svg можно отдельно
открыть в браузере и увеличивать без потери качества; JavaScript не требуется.

Важно: контрольные суммы подтверждают неизменность файлов после экспорта.
Они не доказывают, что уже скомпрометированная операционная система вернула
полные или истинные данные. AVZ-срабатывание не доказывает канал заражения или
размер ущерба. Сохранённые подозрительные файлы, AVZ.exe, базы, архивы и
карантин в экспорт не включаются. Для критичных выводов используйте офлайн-образ.
"""
