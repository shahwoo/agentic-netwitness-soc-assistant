from __future__ import annotations

from typing import Any

from backend.postgres_casework_store import (
    PostgresCaseworkStore,
    PostgresUnavailableError,
    postgres_required_payload,
)


class UnavailableCaseworkStore:
    def __init__(self, error: Exception | str):
        self.error = error

    def __getattr__(self, _name: str):
        raise PostgresUnavailableError(str(self.error))


def get_casework_store(*, initialise: bool = True) -> PostgresCaseworkStore:
    """Return the operational SOC store.

    PostgreSQL is the only runtime database. SQLite fallback is intentionally
    disabled so data loss or split-brain workflow state cannot be hidden.
    """
    return PostgresCaseworkStore(initialise=initialise)


def postgres_unavailable_result(error: Exception | str | None = None) -> dict[str, Any]:
    message = "PostgreSQL is required. SQLite fallback is disabled."
    payload = postgres_required_payload(message)
    if error:
        payload["error"] = str(error)
    return payload


__all__ = [
    "PostgresCaseworkStore",
    "PostgresUnavailableError",
    "UnavailableCaseworkStore",
    "get_casework_store",
    "postgres_unavailable_result",
]
