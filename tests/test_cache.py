"""Tests for the on-disk TTL cache."""
from __future__ import annotations

import time

from asn_mapper.utils.cache import FileCache


class TestFileCache:
    def test_roundtrip(self, tmp_path):
        cache = FileCache(tmp_path / "cache", default_ttl=60)
        assert cache.get("k", namespace="ns") is None
        cache.set("k", {"hello": ["world"]}, namespace="ns")
        assert cache.get("k", namespace="ns") == {"hello": ["world"]}

    def test_namespaces_are_isolated(self, tmp_path):
        cache = FileCache(tmp_path / "cache")
        cache.set("k", "from-a", namespace="a")
        cache.set("k", "from-b", namespace="b")
        assert cache.get("k", namespace="a") == "from-a"
        assert cache.get("k", namespace="b") == "from-b"

    def test_ttl_expiry(self, tmp_path, monkeypatch):
        cache = FileCache(tmp_path / "cache", default_ttl=100)
        cache.set("k", "v", namespace="ns", ttl=10)
        now = time.time()
        # still fresh
        monkeypatch.setattr(time, "time", lambda: now + 5)
        assert cache.get("k", namespace="ns") == "v"
        # expired → miss + file removed
        monkeypatch.setattr(time, "time", lambda: now + 11)
        assert cache.get("k", namespace="ns") is None

    def test_caller_ttl_can_shorten_lifetime(self, tmp_path, monkeypatch):
        cache = FileCache(tmp_path / "cache", default_ttl=3600)
        cache.set("k", "v", namespace="ns", ttl=3600)
        now = time.time()
        monkeypatch.setattr(time, "time", lambda: now + 100)
        assert cache.get("k", namespace="ns", ttl=50) is None
        assert cache.get("k", namespace="ns", ttl=200) == "v"

    def test_disabled_cache(self, tmp_path):
        cache = FileCache(tmp_path / "cache", enabled=False)
        cache.set("k", "v", namespace="ns")
        assert cache.get("k", namespace="ns") is None
        assert not (tmp_path / "cache").exists() or not list((tmp_path / "cache").glob("*.json"))

    def test_corrupt_entry_is_a_miss(self, tmp_path):
        cache = FileCache(tmp_path / "cache")
        cache.set("k", "v", namespace="ns")
        # corrupt every file in the cache dir
        for path in (tmp_path / "cache").glob("*.json"):
            path.write_text("{not json", encoding="utf-8")
        assert cache.get("k", namespace="ns") is None

    def test_clear_expired(self, tmp_path, monkeypatch):
        cache = FileCache(tmp_path / "cache", default_ttl=10)
        cache.set("fresh", 1, namespace="ns", ttl=10_000)
        cache.set("stale", 2, namespace="ns", ttl=1)
        now = time.time()
        monkeypatch.setattr(time, "time", lambda: now + 5)
        removed = cache.clear_expired()
        assert removed == 1
        assert cache.get("fresh", namespace="ns") == 1
        assert cache.get("stale", namespace="ns") is None

    def test_clear_namespace_only(self, tmp_path):
        cache = FileCache(tmp_path / "cache")
        cache.set("k", 1, namespace="ripestat")
        cache.set("k", 2, namespace="bgpview")
        assert cache.clear("ripestat") == 1
        assert cache.get("k", namespace="ripestat") is None
        assert cache.get("k", namespace="bgpview") == 2
