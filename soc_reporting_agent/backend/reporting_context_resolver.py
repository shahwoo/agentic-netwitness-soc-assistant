from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from backend import ticket_workflow


INVESTIGATION_FILENAMES = [
    "investigation_result.json",
]

APPROVAL_FILENAMES = [
    "investigation_approval_result.json",
    "approval_result.json",
]


@dataclass
class ResolvedContext:
    exists: bool
    usable: bool
    data: dict[str, Any]
    source: str | None
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "exists": self.exists,
            "usable": self.usable,
            "data": self.data,
            "source": self.source,
            "message": self.message,
        }


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if not path.exists() or path.stat().st_size == 0:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _unique_paths(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for p in paths:
        key = str(p.resolve()) if p.is_absolute() else str(p)
        if key not in seen:
            out.append(p)
            seen.add(key)
    return out


def _ticket_value(ticket: dict[str, Any] | None, key: str) -> dict[str, Any]:
    if not isinstance(ticket, dict):
        return {}
    value = ticket.get(key) or {}
    return value if isinstance(value, dict) else {}


def investigation_candidate_paths(project_root: Path, ticket_id: str | None = None) -> list[Path]:
    outputs = project_root / "outputs"
    inputs = project_root / "inputs"
    paths: list[Path] = []
    if ticket_id:
        paths.extend([
            outputs / ticket_id / "investigation" / "investigation_result.json",
            outputs / ticket_id / "investigation_result.json",
            outputs / ticket_id / "agents" / "investigation_result.json",
            outputs / ticket_id / "investigation" / "result.json",
        ])
    paths.extend([
        inputs / "investigation_result.json",
        outputs / "investigation_result.json",
        outputs / "unknown" / "investigation_result.json",
    ])
    # Some reporting runs write under outputs/<incident_id>/reporting_result.json, but
    # investigation runs in this project usually write exactly the filenames above.
    return _unique_paths(paths)


def approval_candidate_paths(project_root: Path, ticket_id: str | None = None) -> list[Path]:
    outputs = project_root / "outputs"
    inputs = project_root / "inputs"
    paths: list[Path] = []
    if ticket_id:
        paths.extend([
            outputs / ticket_id / "approval" / "investigation_approval_result.json",
            outputs / ticket_id / "investigation_approval" / "approval_result.json",
            outputs / ticket_id / "investigation_approval_result.json",
        ])
    paths.extend([
        inputs / "investigation_approval_result.json",
        outputs / "investigation_approval_result.json",
        inputs / "approval_result.json",
        outputs / "approval_result.json",
        outputs / "unknown" / "investigation_approval_result.json",
    ])
    return _unique_paths(paths)


def is_approval_approved(data: dict[str, Any]) -> bool:
    decision = _norm(data.get("decision") or data.get("status") or data.get("approval_status"))
    return decision in {"approved", "approve", "completed", "confirmed"}


def resolve_investigation_context(project_root: Path, ticket_id: str | None = None, ticket: dict[str, Any] | None = None) -> ResolvedContext:
    ticket_inv = _ticket_value(ticket, "investigation_result")
    if ticket_inv:
        usable = ticket_workflow.is_investigation_usable_for_reporting(ticket_inv)
        return ResolvedContext(
            exists=True,
            usable=usable,
            data=ticket_inv,
            source="ticket.investigation_result",
            message="Ticket investigation result is usable for Reporting." if usable else "Ticket investigation result exists but is not usable for Reporting.",
        )

    first_existing: tuple[dict[str, Any], Path] | None = None
    for path in investigation_candidate_paths(project_root, ticket_id):
        data = _read_json(path)
        if not data:
            continue
        if first_existing is None:
            first_existing = (data, path)
        if ticket_workflow.is_investigation_usable_for_reporting(data):
            return ResolvedContext(
                exists=True,
                usable=True,
                data=data,
                source=str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path),
                message="Investigation result found and usable for Reporting.",
            )

    if first_existing:
        data, path = first_existing
        return ResolvedContext(
            exists=True,
            usable=False,
            data=data,
            source=str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path),
            message="Investigation result exists but is failed, invalid, or missing usable findings.",
        )

    return ResolvedContext(
        exists=False,
        usable=False,
        data={},
        source=None,
        message="No investigation result was found in ticket context, inputs, or known outputs paths.",
    )


def resolve_investigation_approval_context(project_root: Path, ticket_id: str | None = None, ticket: dict[str, Any] | None = None) -> ResolvedContext:
    ticket_approval = _ticket_value(ticket, "investigation_approval_result")
    if ticket_approval:
        usable = is_approval_approved(ticket_approval)
        return ResolvedContext(
            exists=True,
            usable=usable,
            data=ticket_approval,
            source="ticket.investigation_approval_result",
            message="Investigation approval is approved." if usable else "Investigation approval exists but is not approved.",
        )

    first_existing: tuple[dict[str, Any], Path] | None = None
    for path in approval_candidate_paths(project_root, ticket_id):
        data = _read_json(path)
        if not data:
            continue
        # Only accept generic approval_result.json if it is clearly the investigation gate
        # or if no explicit gate is present but decision is approved. This keeps legacy
        # files working without bypassing rejected approvals.
        if first_existing is None:
            first_existing = (data, path)
        if is_approval_approved(data):
            return ResolvedContext(
                exists=True,
                usable=True,
                data=data,
                source=str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path),
                message="Investigation approval found and approved.",
            )

    if first_existing:
        data, path = first_existing
        return ResolvedContext(
            exists=True,
            usable=False,
            data=data,
            source=str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path),
            message="Investigation approval exists but is not approved.",
        )

    return ResolvedContext(False, False, {}, None, "No investigation approval result was found.")


def ensure_reporting_inputs(project_root: Path, ticket_id: str | None = None, ticket: dict[str, Any] | None = None) -> dict[str, Any]:
    """Copy resolved investigation/approval contexts into inputs and legacy outputs.

    The dashboard stores ticket context in PostgreSQL while legacy reporting
    helpers still read JSON files from inputs/ and outputs/. This bridge prevents Reporting from
    failing with "Run Investigation first" when a usable limited investigation is
    available in ticket context or a fallback output path.
    """
    inputs = project_root / "inputs"
    outputs = project_root / "outputs"
    inputs.mkdir(parents=True, exist_ok=True)
    outputs.mkdir(parents=True, exist_ok=True)

    inv = resolve_investigation_context(project_root, ticket_id=ticket_id, ticket=ticket)
    approval = resolve_investigation_approval_context(project_root, ticket_id=ticket_id, ticket=ticket)

    if inv.exists and inv.data:
        _write_json(inputs / "investigation_result.json", inv.data)
        _write_json(outputs / "investigation_result.json", inv.data)
    if approval.exists and approval.data:
        _write_json(inputs / "investigation_approval_result.json", approval.data)
        _write_json(outputs / "investigation_approval_result.json", approval.data)
        # Reporting input_loader still expects approval_result.json. Use the investigation
        # approval for Reporting handoff when it is the latest gate.
        _write_json(inputs / "approval_result.json", approval.data)

    return {
        "investigation": inv.as_dict(),
        "investigation_approval": approval.as_dict(),
    }
