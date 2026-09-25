"""Conservative reverse-DNS (PTR) lookups.

Design goals (per the passive-only philosophy of the tool):

* **Timeouts and retries** — bounded per query and overall.
* **Concurrency limits** — a fixed-size thread pool (default 10).
* **Caching** — positive *and* negative results are cached on disk.
* **Graceful failure** — NXDOMAIN, SERVFAIL and timeouts become
  :class:`~asn_mapper.models.ReverseDNSRecord` entries with an ``error``
  field instead of exceptions.

The service never floods resolvers: lookups go through the system resolver
(or explicitly configured nameservers) at a controlled rate.
"""
from __future__ import annotations

import threading
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..models import ReverseDNSRecord
from ..utils.cache import FileCache
from ..utils.logger import get_logger

try:  # dnspython is a hard dependency, but import defensively anyway.
    import dns.exception
    import dns.resolver
    import dns.reversename

    DNSPYTHON_AVAILABLE = True
except ImportError:  # pragma: no cover - only hit in broken environments
    DNSPYTHON_AVAILABLE = False

__all__ = ["ReverseDNSService"]

LOGGER = get_logger()


class ReverseDNSService:
    """PTR lookup service with caching, retries and bounded concurrency."""

    def __init__(
        self,
        cache: FileCache | None = None,
        timeout: float = 4.0,
        retries: int = 2,
        concurrency: int = 10,
        nameservers: Sequence[str] | None = None,
        negative_ttl: int = 3600,
    ) -> None:
        self.cache = cache
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))
        self.concurrency = max(1, int(concurrency))
        self.negative_ttl = int(negative_ttl)
        self._resolver = self._build_resolver(nameservers)

    # ------------------------------------------------------------------
    def _build_resolver(self, nameservers: Sequence[str] | None) -> Any:
        if not DNSPYTHON_AVAILABLE:  # pragma: no cover
            raise RuntimeError(
                "dnspython is required for reverse DNS lookups "
                "(pip install dnspython)"
            )
        resolver = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            resolver.nameservers = list(nameservers)
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        resolver.retry_servfail = True
        return resolver

    # ------------------------------------------------------------------
    def lookup(self, ip: str) -> ReverseDNSRecord:
        """Perform (or fetch from cache) a single PTR lookup."""
        cached = self._cache_get(ip)
        if cached is not None:
            return cached

        record = self._lookup_live(ip)
        self._cache_set(ip, record)
        return record

    def _lookup_live(self, ip: str) -> ReverseDNSRecord:
        """Perform the live PTR query with retries and graceful failure."""
        try:
            reverse_name = dns.reversename.from_address(ip)
        except Exception as exc:  # noqa: BLE001 - invalid addresses never crash
            return ReverseDNSRecord(ip=ip, error=f"invalid address: {exc}")
        last_error = "lookup failed"
        for attempt in range(self.retries + 1):
            try:
                answers = self._resolver.resolve(reverse_name, "PTR", lifetime=self.timeout)
                hostname = str(answers[0]).rstrip(".") if answers else None
                if not hostname:
                    return ReverseDNSRecord(ip=ip, error="empty PTR answer")
                return ReverseDNSRecord(ip=ip, hostname=hostname)
            except dns.resolver.NXDOMAIN:
                return ReverseDNSRecord(ip=ip, error="NXDOMAIN")
            except dns.resolver.NoAnswer:
                return ReverseDNSRecord(ip=ip, error="no PTR record")
            except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
                last_error = "timeout"
            except dns.resolver.NoNameservers:
                last_error = "no nameservers responded"
            except dns.exception.DNSException as exc:
                last_error = f"{exc.__class__.__name__}"
            if attempt < self.retries:
                LOGGER.debug("PTR lookup for %s failed (%s), retrying", ip, last_error)
        return ReverseDNSRecord(ip=ip, error=last_error)

    # ------------------------------------------------------------------
    def lookup_many(
        self, ips: Iterable[str], progress: Any | None = None
    ) -> list[ReverseDNSRecord]:
        """Look up many addresses with bounded concurrency, order preserved.

        :param ips: addresses to resolve
        :param progress: optional callable invoked with (done, total) counts
        """
        unique_ips = list(dict.fromkeys(ips))
        if not unique_ips:
            return []
        results: dict[str, ReverseDNSRecord] = {}
        total = len(unique_ips)
        counter_lock = threading.Lock()
        counter = [0]

        def _work(ip: str) -> tuple[str, ReverseDNSRecord]:
            record = self.lookup(ip)
            if progress is not None:
                with counter_lock:
                    counter[0] += 1
                    done = counter[0]
                try:
                    progress(done, total)
                except Exception:  # pragma: no cover - defensive
                    pass
            return ip, record

        workers = min(self.concurrency, len(unique_ips))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="aam-dns") as pool:
            for ip, record in pool.map(_work, unique_ips):
                results[ip] = record
        return [results[ip] for ip in unique_ips]

    # ------------------------------------------------------------------
    # Caching helpers
    # ------------------------------------------------------------------
    def _cache_get(self, ip: str) -> ReverseDNSRecord | None:
        if not self.cache or not self.cache.enabled:
            return None
        payload = self.cache.get(f"ptr:{ip}", namespace="dns")
        if payload is None:
            return None
        return ReverseDNSRecord(
            ip=payload.get("ip", ip),
            hostname=payload.get("hostname"),
            prefix=payload.get("prefix"),
            error=payload.get("error"),
        )

    def _cache_set(self, ip: str, record: ReverseDNSRecord) -> None:
        if not self.cache or not self.cache.enabled:
            return
        # Negative answers get a shorter TTL so transient DNS failures
        # don't stick around for a full cache cycle.
        ttl = None if record.ok else self.negative_ttl
        self.cache.set(
            f"ptr:{ip}",
            {
                "ip": record.ip,
                "hostname": record.hostname,
                "prefix": record.prefix,
                "error": record.error,
            },
            namespace="dns",
            ttl=ttl,
        )
