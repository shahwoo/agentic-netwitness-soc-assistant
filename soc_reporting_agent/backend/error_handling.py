from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any, Callable

import psycopg2
from flask import jsonify, request

from backend.postgres_casework_store import PostgresUnavailableError


class ApiError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: str = "API_ERROR",
        status_code: int = 400,
        title: str | None = None,
        severity: str = "warning",
        analyst_action: str = "Review the request and try again.",
        details: dict[str, Any] | None = None,
        recoverable: bool = True,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.title = title or code.replace("_", " ").title()
        self.severity = severity
        self.analyst_action = analyst_action
        self.details = details or {}
        self.recoverable = recoverable


def error_payload(
    message: str,
    *,
    code: str = "API_ERROR",
    title: str | None = None,
    severity: str = "warning",
    analyst_action: str = "Review the request and try again.",
    details: dict[str, Any] | None = None,
    recoverable: bool = True,
) -> dict[str, Any]:
    return {
        "success": False,
        "error_code": code,
        "severity": severity,
        "title": title or code.replace("_", " ").title(),
        "message": message,
        "status": message,
        "analyst_action": analyst_action,
        "details": details or {},
        "recoverable": recoverable,
    }


def api_error(
    message: str,
    status_code: int = 400,
    *,
    code: str = "API_ERROR",
    title: str | None = None,
    severity: str = "warning",
    analyst_action: str = "Review the request and try again.",
    details: dict[str, Any] | None = None,
    recoverable: bool = True,
):
    return jsonify(error_payload(
        message,
        code=code,
        title=title,
        severity=severity,
        analyst_action=analyst_action,
        details=details,
        recoverable=recoverable,
    )), status_code


def safe_load_json_file(path: Path | str, *, default: Any = None, required: bool = False, label: str = "JSON file") -> Any:
    path = Path(path)
    if not path.exists():
        if required:
            raise ApiError(
                f"{label} was not found: {path.name}",
                code="MISSING_INPUT_FILE",
                title="Missing input file",
                analyst_action="Run the previous workflow step first, then retry this action.",
                details={"path": str(path)},
            )
        return default
    try:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            if required:
                raise ApiError(
                    f"{label} is empty: {path.name}",
                    code="EMPTY_INPUT_FILE",
                    title="Empty input file",
                    analyst_action="Re-run the previous agent so it writes a complete output file.",
                    details={"path": str(path)},
                )
            return default
        return json.loads(text)
    except ApiError:
        raise
    except json.JSONDecodeError as exc:
        raise ApiError(
            f"{label} contains malformed JSON: {exc}",
            code="MALFORMED_JSON",
            title="Malformed JSON",
            analyst_action="Open the agent output, fix or regenerate the malformed JSON, then retry.",
            details={"path": str(path), "line": exc.lineno, "column": exc.colno},
        )


def safe_write_json_file(path: Path | str, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def api_guard(fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        try:
            return fn(*args, **kwargs)
        except ApiError as exc:
            return api_error(
                exc.message,
                exc.status_code,
                code=exc.code,
                title=exc.title,
                severity=exc.severity,
                analyst_action=exc.analyst_action,
                details=exc.details,
                recoverable=exc.recoverable,
            )
        except KeyError as exc:
            return api_error(
                str(exc).strip("'"),
                404,
                code="NOT_FOUND",
                title="Record not found",
                analyst_action="Refresh the ticket list and confirm the ticket, alert, or recommendation still exists.",
            )
        except ValueError as exc:
            return api_error(
                str(exc),
                400,
                code="INVALID_REQUEST",
                title="Invalid request",
                analyst_action="Check the form values and try again.",
            )
        except PostgresUnavailableError as exc:
            return api_error(
                "PostgreSQL is required. SQLite fallback is disabled.",
                503,
                code="POSTGRES_UNAVAILABLE",
                title="PostgreSQL unavailable",
                severity="critical",
                analyst_action="Start PostgreSQL or fix POSTGRES_DSN, then retry.",
                details={"error": str(exc)},
                recoverable=True,
            )
        except psycopg2.Error as exc:
            return api_error(
                str(exc),
                500,
                code="DATABASE_WRITE_FAILED",
                title="Database operation failed",
                severity="critical",
                analyst_action="Do not repeat risky analyst actions. Refresh the dashboard and check the activity log before retrying.",
                recoverable=True,
            )
        except Exception as exc:
            return api_error(
                str(exc),
                500,
                code="UNHANDLED_BACKEND_ERROR",
                title="Backend error",
                severity="critical",
                analyst_action="Capture this message, check backend logs, then retry after the issue is fixed.",
                recoverable=True,
            )
    return wrapper


def install_api_guards(app) -> None:
    """Wrap JSON API endpoints with a consistent analyst-friendly error contract."""
    for endpoint, view in list(app.view_functions.items()):
        rule_paths = [rule.rule for rule in app.url_map.iter_rules(endpoint)]
        if not any(path.startswith("/api/") for path in rule_paths):
            continue
        if getattr(view, "_api_guarded", False):
            continue
        guarded = api_guard(view)
        setattr(guarded, "_api_guarded", True)
        app.view_functions[endpoint] = guarded
