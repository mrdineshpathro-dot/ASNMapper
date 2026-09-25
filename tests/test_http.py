"""Tests for the HTTP client: retries, backoff, 429 handling, rate limiting,
and response caching. Uses a fake requests session — no real network."""
from __future__ import annotations

import pytest
import requests

import asn_mapper.utils.networking as networking
from asn_mapper.utils.cache import FileCache
from asn_mapper.utils.networking import (
    HttpClient,
    MalformedResponseError,
    NetworkError,
    ProviderError,
    RateLimitedError,
    RateLimiter,
    RequestTimeoutError,
)


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None, url="http://unit.test/x"):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}
        self.url = url
        self._raise_on_json = json_data is Ellipsis

    def json(self):
        if self._raise_on_json:
            raise ValueError("no json")
        return self._json_data


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, dict]] = []
        self.headers = {}

    def get(self, url, params=None, headers=None, timeout=None, verify=None):
        self.calls.append((url, {"params": params, "timeout": timeout}))
        if not self.responses:
            raise AssertionError("FakeSession ran out of scripted responses")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def sleeps(monkeypatch):
    """Neutralize time.sleep inside the networking module and record calls."""
    recorded: list[float] = []
    monkeypatch.setattr(networking.time, "sleep", lambda seconds: recorded.append(seconds))
    return recorded


def make_client(session, retries=2, **kwargs) -> HttpClient:
    return HttpClient(
        user_agent="ASN-Asset-Mapper/test",
        timeout=1.0,
        retries=retries,
        backoff_base=1.0,
        max_delay=10.0,
        session=session,
        **kwargs,
    )


class TestRetries:
    def test_success_first_try(self, sleeps):
        session = FakeSession([FakeResponse(200, {"ok": True})])
        client = make_client(session, retries=3)
        assert client.get_json("http://unit.test/x") == {"ok": True}
        assert len(session.calls) == 1
        assert sleeps == []

    def test_429_then_success(self, sleeps):
        session = FakeSession(
            [FakeResponse(429, {}, headers={"Retry-After": "3"}), FakeResponse(200, {"ok": 1})]
        )
        client = make_client(session, retries=2)
        assert client.get_json("http://unit.test/x") == {"ok": 1}
        assert len(session.calls) == 2
        # Retry-After honoured (plus a small jitter allowance)
        assert 3.0 <= sleeps[0] <= 3.5

    def test_429_exhausted(self, sleeps):
        session = FakeSession([FakeResponse(429)] * 3)
        client = make_client(session, retries=2)
        with pytest.raises(RateLimitedError):
            client.get_json("http://unit.test/x")
        assert len(session.calls) == 3

    def test_500_then_success(self, sleeps):
        session = FakeSession([FakeResponse(503), FakeResponse(200, {"ok": 1})])
        client = make_client(session, retries=2)
        assert client.get_json("http://unit.test/x") == {"ok": 1}

    def test_404_does_not_retry(self, sleeps):
        session = FakeSession([FakeResponse(404)])
        client = make_client(session, retries=3)
        with pytest.raises(ProviderError):
            client.get_json("http://unit.test/x")
        assert len(session.calls) == 1

    def test_connection_error_then_success(self, sleeps):
        session = FakeSession(
            [requests.ConnectionError("boom"), requests.ConnectionError("boom"), FakeResponse(200, {"ok": 1})]
        )
        client = make_client(session, retries=2)
        assert client.get_json("http://unit.test/x") == {"ok": 1}
        assert len(session.calls) == 3

    def test_timeout_exhausted(self, sleeps):
        session = FakeSession([requests.Timeout("too slow")] * 3)
        client = make_client(session, retries=2)
        with pytest.raises(NetworkError):
            client.get_json("http://unit.test/x")
        # timeout specifically surfaces as RequestTimeoutError
        session = FakeSession([requests.Timeout("too slow")] * 3)
        client = make_client(session, retries=2)
        with pytest.raises(RequestTimeoutError):
            client.get_json("http://unit.test/y")

    def test_malformed_json(self, sleeps):
        session = FakeSession([FakeResponse(200, Ellipsis)])
        client = make_client(session)
        with pytest.raises(MalformedResponseError):
            client.get_json("http://unit.test/x")

    def test_backoff_is_exponential_and_capped(self, sleeps):
        session = FakeSession([requests.ConnectionError("x")] * 4)
        client = make_client(session, retries=3)
        with pytest.raises(NetworkError):
            client.get("http://unit.test/x")
        # base 1.0 → 1, 2, 4 (each with up to 0.4s jitter, capped at max_delay)
        assert len(sleeps) == 3
        assert 1.0 <= sleeps[0] <= 1.5
        assert 2.0 <= sleeps[1] <= 2.5
        assert 4.0 <= sleeps[2] <= 4.5


class TestCaching:
    def test_successful_response_is_cached(self, tmp_path, sleeps):
        session = FakeSession([FakeResponse(200, {"cached": False})])
        cache = FileCache(tmp_path / "cache", default_ttl=60)
        client = make_client(session, cache=cache)
        first = client.get_json("http://unit.test/x", params={"a": 1}, cache_namespace="test")
        second = client.get_json("http://unit.test/x", params={"a": 1}, cache_namespace="test")
        assert first == second
        assert len(session.calls) == 1  # second call served from cache

    def test_cache_disabled_per_call(self, tmp_path, sleeps):
        session = FakeSession(
            [FakeResponse(200, {"n": 1}), FakeResponse(200, {"n": 2})]
        )
        cache = FileCache(tmp_path / "cache", default_ttl=60)
        client = make_client(session, cache=cache)
        client.get_json("http://unit.test/x", cache_namespace="test", use_cache=False)
        client.get_json("http://unit.test/x", cache_namespace="test", use_cache=False)
        assert len(session.calls) == 2

    def test_failures_are_not_cached(self, tmp_path, sleeps):
        session = FakeSession([FakeResponse(404), FakeResponse(200, {"ok": 1})])
        cache = FileCache(tmp_path / "cache", default_ttl=60)
        client = make_client(session, cache=cache)
        with pytest.raises(ProviderError):
            client.get_json("http://unit.test/x", cache_namespace="test")
        assert client.get_json("http://unit.test/x", cache_namespace="test") == {"ok": 1}
        assert len(session.calls) == 2


class TestRateLimiter:
    def test_enforces_interval(self):
        limiter = RateLimiter(min_interval=0.15)
        import time as real_time

        start = real_time.monotonic()
        limiter.wait()
        limiter.wait()
        elapsed = real_time.monotonic() - start
        assert elapsed >= 0.14  # at least one interval elapsed between calls

    def test_zero_interval_is_free(self):
        limiter = RateLimiter(min_interval=0)
        limiter.wait()
        limiter.wait()  # must not raise or sleep

    def test_user_agent_sent(self, sleeps):
        session = FakeSession([FakeResponse(200, {})])
        client = make_client(session)
        client.get("http://unit.test/x")
        # captured via session.get kwargs is url/params only; check headers on session
        assert client.headers["User-Agent"].startswith("ASN-Asset-Mapper/")
