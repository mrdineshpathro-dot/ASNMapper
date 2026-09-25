"""Polite HTTP client layer.

All outbound traffic goes through :class:`HttpClient`, which provides:

* a consistent ``User-Agent`` identifying the tool,
* connection pooling via a shared :class:`requests.Session`,
* configurable connection/read timeouts,
* automatic retries with exponential backoff and jitter,
* ``HTTP 429`` handling that honours ``Retry-After`` (never bypasses limits),
* a per-provider :class:`RateLimiter` enforcing a minimum interval between
  requests,
* transparent on-disk response caching.

The client is deliberately conservative: it never bypasses rate limits and
always identifies itself.
"""
from __future__ import annotations

import random
import threading
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter

from .cache import FileCache

__all__ = [
    "HttpClient",
    "MalformedResponseError",
    "NetworkError",
    "ProviderError",
    "ProviderUnavailableError",
    "RateLimitedError",
    "RateLimiter",
    "RequestTimeoutError",
]


class NetworkError(Exception):
    """Base class for network/transport failures."""


class RequestTimeoutError(NetworkError):
    """A request timed out after all retries."""


class ProviderError(Exception):
    """The remote provider returned a non-retryable error (4xx etc.)."""


class ProviderUnavailableError(ProviderError):
    """All configured providers failed."""


class RateLimitedError(ProviderError):
    """The remote provider kept returning HTTP 429 after backoff."""


class MalformedResponseError(ProviderError):
    """The provider returned a payload that could not be parsed."""


class RateLimiter:
    """Enforce a minimum interval between requests (thread-safe)."""

    def __init__(self, min_interval: float = 0.5) -> None:
        self.min_interval = max(0.0, float(min_interval))
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        """Block until at least ``min_interval`` has passed since last call."""
        with self._lock:
            now = time.monotonic()
            wait_for = self.min_interval - (now - self._last)
            self._last = now + max(wait_for, 0.0)
        if wait_for > 0:
            time.sleep(wait_for)


class HttpClient:
    """A cached, rate-limited, retrying HTTP GET client.

    :param user_agent: value sent in the ``User-Agent`` header
    :param timeout: default per-request timeout in seconds
    :param retries: number of retries after a transient failure
    :param backoff_base: base delay for exponential backoff (seconds)
    :param max_delay: upper bound for any single backoff sleep
    :param rate_limiter: optional :class:`RateLimiter` applied per request
    :param cache: optional :class:`~asn_mapper.utils.cache.FileCache`
    :param pool_size: connection-pool size (sized to the thread count)
    """

    def __init__(
        self,
        user_agent: str,
        timeout: float = 15.0,
        retries: int = 3,
        backoff_base: float = 1.0,
        max_delay: float = 30.0,
        rate_limiter: RateLimiter | None = None,
        cache: FileCache | None = None,
        verify_tls: bool = True,
        pool_size: int = 10,
        session: requests.Session | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))
        self.backoff_base = max(0.0, float(backoff_base))
        self.max_delay = max(0.0, float(max_delay))
        self.rate_limiter = rate_limiter
        self.cache = cache
        self.verify_tls = verify_tls
        self.headers: dict[str, str] = {
            "User-Agent": user_agent,
            "Accept": "application/json, text/plain;q=0.9, */*;q=0.5",
        }
        self._session = session or self._build_session(pool_size)
        # requests.Session is not guaranteed thread-safe; requests are
        # serialized behind a lock. Concurrency still helps for DNS lookups
        # (which do not use HTTP) and keeps API politeness in check.
        self._request_lock = threading.Lock()

    # ------------------------------------------------------------------
    @staticmethod
    def _build_session(pool_size: int) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def close(self) -> None:
        """Release the underlying session connections."""
        try:
            self._session.close()
        except Exception:  # pragma: no cover - defensive
            pass

    # ------------------------------------------------------------------
    def get(
        self,
        url: str,
        params: Mapping[str, Any] | None = None,
        timeout: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> requests.Response:
        """GET a URL with retries/backoff on transient failures.

        Returns the final :class:`requests.Response` (including 4xx ones —
        callers decide how to interpret them). Raises :class:`NetworkError`
        or :class:`RateLimitedError` when retries are exhausted.
        """
        effective_timeout = timeout if timeout is not None else self.timeout
        merged_headers = dict(self.headers)
        if headers:
            merged_headers.update(headers)

        last_retryable: Exception | None = None
        rate_limited = False
        for attempt in range(self.retries + 1):
            if self.rate_limiter:
                self.rate_limiter.wait()
            try:
                with self._request_lock:
                    response = self._session.get(
                        url,
                        params=dict(params) if params else None,
                        headers=merged_headers,
                        timeout=effective_timeout,
                        verify=self.verify_tls,
                    )
            except requests.Timeout:
                last_retryable = RequestTimeoutError(f"timeout after {effective_timeout:.0f}s: {url}")
                response = None
            except requests.RequestException as exc:
                last_retryable = NetworkError(f"connection failed: {exc.__class__.__name__}: {exc}")
                response = None

            if response is not None:
                status = response.status_code
                if status == 429:
                    rate_limited = True
                    last_retryable = RateLimitedError(f"HTTP 429 (rate limited): {url}")
                elif 500 <= status < 600:
                    rate_limited = False
                    last_retryable = ProviderError(f"HTTP {status} (server error): {url}")
                else:
                    return response

            if attempt < self.retries:
                self._sleep_backoff(attempt, response)

        if rate_limited and isinstance(last_retryable, RateLimitedError):
            raise last_retryable
        if last_retryable is not None:
            raise last_retryable
        raise NetworkError(f"request failed: {url}")  # pragma: no cover - unreachable

    def get_json(
        self,
        url: str,
        params: Mapping[str, Any] | None = None,
        timeout: float | None = None,
        cache_namespace: str | None = None,
        cache_ttl: int | None = None,
        use_cache: bool = True,
    ) -> Any:
        """GET a URL and return the parsed JSON payload.

        Successful responses are cached (when a cache is configured and
        ``use_cache`` is true). Non-2xx responses raise :class:`ProviderError`
        without retries (retries happen inside :meth:`get` for the transient
        cases).
        """
        cache = self.cache if use_cache else None
        cache_key = self._cache_key(url, params)
        if cache is not None and cache_namespace:
            cached = cache.get(cache_key, namespace=cache_namespace, ttl=cache_ttl)
            if cached is not None:
                return cached

        response = self.get(url, params=params, timeout=timeout)
        if response.status_code == 404:
            raise ProviderError(f"HTTP 404 (not found): {url}")
        if response.status_code == 429:
            raise RateLimitedError(f"HTTP 429 (rate limited): {url}")
        if not 200 <= response.status_code < 300:
            raise ProviderError(f"HTTP {response.status_code}: {url}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise MalformedResponseError(
                f"malformed JSON from {url}: {exc.__class__.__name__}"
            ) from exc

        if cache is not None and cache_namespace:
            cache.set(cache_key, payload, namespace=cache_namespace, ttl=cache_ttl)
        return payload

    # ------------------------------------------------------------------
    def _sleep_backoff(self, attempt: int, response: requests.Response | None) -> None:
        """Sleep before the next retry, honouring ``Retry-After`` when given."""
        delay: float
        retry_after: str | None = None
        if response is not None:
            retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                delay = 0.0
            delay = min(max(delay, 0.0), self.max_delay)
        else:
            delay = min(self.max_delay, self.backoff_base * (2**attempt))
        delay += random.uniform(0.0, 0.4)  # jitter
        time.sleep(delay)

    @staticmethod
    def _cache_key(url: str, params: Mapping[str, Any] | None) -> str:
        if not params:
            return url
        query = urlencode(sorted(params.items()))
        return f"{url}?{query}"
