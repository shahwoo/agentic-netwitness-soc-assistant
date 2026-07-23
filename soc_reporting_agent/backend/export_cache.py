from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_filename(value: Any) -> str:
    import re
    text = str(value or "unknown")
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")
    return text[:120] or "unknown"


def _json_default(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "<unserialisable>"


def stable_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=_json_default).encode("utf-8")


def file_digest(path: Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists() or not path.is_file():
        return {"path": str(path), "exists": False}
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    stat = path.stat()
    return {
        "path": str(path),
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": h.hexdigest(),
    }


def calculate_source_hash(*, source_files: Iterable[Path], extra_payload: Any | None = None) -> str:
    payload = {
        "files": [file_digest(Path(path)) for path in source_files],
        "extra": extra_payload or {},
    }
    return hashlib.sha256(stable_json(payload)).hexdigest()


def metadata_path(export_dir: Path) -> Path:
    return Path(export_dir) / "_export_cache.json"


def load_metadata(export_dir: Path) -> dict[str, Any]:
    path = metadata_path(export_dir)
    if not path.exists() or path.stat().st_size == 0:
        return {"version": 1, "entries": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("version", 1)
            data.setdefault("entries", {})
            return data
    except Exception:
        pass
    return {"version": 1, "entries": {}}


def save_metadata(export_dir: Path, metadata: dict[str, Any]) -> Path:
    path = metadata_path(export_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def cache_entry(export_dir: Path, key: str) -> dict[str, Any] | None:
    entry = load_metadata(export_dir).get("entries", {}).get(key)
    return entry if isinstance(entry, dict) else None


def is_cache_ready(export_dir: Path, key: str, file_path: Path, source_hash: str) -> bool:
    entry = cache_entry(export_dir, key)
    if not entry:
        return False
    if entry.get("status") != "ready":
        return False
    if entry.get("source_hash") != source_hash:
        return False
    return Path(file_path).exists() and Path(file_path).stat().st_size > 0


def mark_export_status(
    export_dir: Path,
    *,
    key: str,
    status: str,
    source_hash: str | None = None,
    file_path: Path | None = None,
    message: str | None = None,
    related_paths: dict[str, str] | None = None,
) -> None:
    metadata = load_metadata(export_dir)
    entries = metadata.setdefault("entries", {})
    previous = entries.get(key, {}) if isinstance(entries.get(key), dict) else {}
    entry = {
        **previous,
        "status": status,
        "updated_at": utc_now(),
    }
    if source_hash is not None:
        entry["source_hash"] = source_hash
    if file_path is not None:
        entry["path"] = str(file_path)
    if message is not None:
        entry["message"] = message
    if related_paths:
        entry["related_paths"] = related_paths
    if status == "ready":
        entry["generated_at"] = utc_now()
    entries[key] = entry
    save_metadata(export_dir, metadata)


def normalise_status(entry: dict[str, Any] | None, file_path: Path | None = None) -> dict[str, Any]:
    if not entry:
        return {"status": "not_generated"}
    status = entry.get("status") or "not_generated"
    path = Path(file_path or entry.get("path") or "") if (file_path or entry.get("path")) else None
    if status == "ready" and path and not path.exists():
        status = "not_generated"
    return {
        "status": status,
        "generated_at": entry.get("generated_at"),
        "updated_at": entry.get("updated_at"),
        "message": entry.get("message"),
        "path": entry.get("path") if status == "ready" else None,
    }


def collect_ticket_export_status(output_dir: Path, ticket_id: str) -> dict[str, Any]:
    """Return cache readiness for dashboard display.

    This does not generate any files. It only reads export metadata and checks
    known export directories.
    """
    ticket_safe = safe_filename(ticket_id)
    root = Path(output_dir) / "exports" / ticket_safe
    result: dict[str, Any] = {"ticket_id": ticket_id, "agents": {}, "reporting": {}}

    agents_root = root / "agents"
    if agents_root.exists():
        for agent_dir in sorted(p for p in agents_root.iterdir() if p.is_dir()):
            meta = load_metadata(agent_dir)
            agent_status: dict[str, Any] = {}
            for fmt in ["docx", "pdf", "json"]:
                entry = meta.get("entries", {}).get(fmt)
                agent_status[fmt] = normalise_status(entry)
            result["agents"][agent_dir.name] = agent_status

    reporting_root = root / "reporting"
    if reporting_root.exists():
        for report_dir in sorted(p for p in reporting_root.iterdir() if p.is_dir()):
            meta = load_metadata(report_dir)
            report_status: dict[str, Any] = {}
            for fmt in ["docx", "pdf", "json"]:
                entry = meta.get("entries", {}).get(fmt)
                report_status[fmt] = normalise_status(entry)
            result["reporting"][report_dir.name] = report_status

    return result
