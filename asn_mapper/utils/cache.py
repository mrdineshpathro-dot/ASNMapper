"""Thread-safe on-disk JSON cache.

Responses from public APIs are cached under
``~/.cache/asn-asset-mapper/`` (configurable) so repeated runs don't hammer
the very services the tool depends on. Entries carry their own storage time
and TTL; expired entries are removed on read.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

__all__ = ["FileCache"]


class FileCache:
    """A simple namespace-aware, TTL-based file cache."""

    def __init__(
        self,
        directory: str | Path | None = None,
        default_ttl: int = 86_400,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.default_ttl = int(default_ttl)
        self.directory = Path(directory) if directory else Path.home() / ".cache" / "asn-asset-mapper"
        self._lock = threading.Lock()
        if self.enabled:
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
            except OSError:  # read-only home etc. — degrade to disabled
                self.enabled = False

    # ------------------------------------------------------------------
    def _path_for(self, key: str, namespace: str) -> Path:
        digest = hashlib.sha256(f"{namespace}:{key}".encode()).hexdigest()
        return self.directory / f"{namespace}-{digest}.json"

    def _entry_path(self, key: str, namespace: str | None) -> Path:
        ns = namespace or "default"
        return self._path_for(key, ns)

    # ------------------------------------------------------------------
    def get(self, key: str, namespace: str | None = None, ttl: int | None = None) -> Any | None:
        """Return a cached payload, or ``None`` on miss/expiry/disabled."""
        if not self.enabled:
            return None
        path = self._entry_path(key, namespace)
        with self._lock:
            try:
                raw = path.read_text(encoding="utf-8")
            except (OSError, ValueError):
                return None
        try:
            entry = json.loads(raw)
            stored_at = float(entry["stored_at"])
            entry_ttl = int(entry.get("ttl", self.default_ttl))
        except (ValueError, KeyError, TypeError):
            return None
        age = time.time() - stored_at
        # Genuinely stale (past its own TTL) → remove the file.
        if age > entry_ttl:
            self._remove(path)
            return None
        # Fresh per its own TTL but older than a caller-requested TTL →
        # a miss for this caller, but the entry is kept for others.
        effective_ttl = self.default_ttl if ttl is None else int(ttl)
        if age > effective_ttl:
            return None
        return entry.get("payload")

    def set(self, key: str, value: Any, namespace: str | None = None, ttl: int | None = None) -> None:
        """Store a JSON-serializable payload."""
        if not self.enabled:
            return
        path = self._entry_path(key, namespace)
        entry = {
            "stored_at": time.time(),
            "ttl": self.default_ttl if ttl is None else int(ttl),
            "key": key,
            "payload": value,
        }
        with self._lock:
            self._atomic_write(path, json.dumps(entry, default=str))

    # ------------------------------------------------------------------
    def clear(self, namespace: str | None = None) -> int:
        """Delete cached entries (optionally limited to a namespace).

        :returns: number of removed files
        """
        if not self.directory.is_dir():
            return 0
        removed = 0
        for path in self.directory.glob("*.json"):
            if namespace and not path.name.startswith(f"{namespace}-"):
                continue
            if self._remove(path):
                removed += 1
        return removed

    def clear_expired(self) -> int:
        """Remove all entries past their own TTL; returns the count removed."""
        if not self.directory.is_dir():
            return 0
        removed = 0
        now = time.time()
        for path in self.directory.glob("*.json"):
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
                if now - float(entry["stored_at"]) > int(entry.get("ttl", self.default_ttl)):
                    if self._remove(path):
                        removed += 1
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return removed

    # ------------------------------------------------------------------
    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        """Write via a temp file + rename so concurrent readers never crash."""
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=str(path.parent), delete=False, suffix=".tmp"
            ) as handle:
                handle.write(text)
                temp_name = handle.name
            os.replace(temp_name, path)
        except OSError:
            # Cache write failures must never break a run.
            try:
                os.unlink(temp_name)
            except (OSError, UnboundLocalError):
                pass

    @staticmethod
    def _remove(path: Path) -> bool:
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError:  # pragma: no cover - defensive
            return False
