"""The mapping engine — orchestrates providers and collectors.

:class:`MapperEngine` is transport-agnostic: it emits progress through an
optional notifier (duck-typed ``info``/``warn``/``error`` methods) so the
CLI, tests, or library consumers can observe a run without coupling to any
UI framework.

The default workflow is entirely passive: public BGP data and RDAP
registration records. Optional modules (reverse DNS sampling, domain
correlation, CT enumeration) are strictly opt-in.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from .collectors.asn import ASNInfoCollector
from .collectors.domains import DomainCollector
from .collectors.prefixes import PrefixCollector, expand_prefix
from .collectors.reverse_dns import ReverseDNSCollector
from .config import AppConfig
from .models import (
    ASNResult,
    BulkResult,
    DomainRecord,
    FailedASN,
    SourceRecord,
    utc_now_iso,
)
from .providers.bgp import BGPService, build_bgp_service
from .providers.ct import CrtShProvider, CTService
from .providers.dns import ReverseDNSService
from .providers.rdap import RDAPService, build_rdap_service
from .utils.cache import FileCache
from .utils.logger import get_logger
from .utils.networking import HttpClient, RateLimiter
from .validators import format_asn, normalize_domain

__all__ = ["MapperEngine", "Notifier", "NullNotifier", "RunOptions"]

LOGGER = get_logger()


class Notifier(Protocol):
    """Minimal progress-reporting interface used by the engine."""

    def info(self, message: str) -> None: ...

    def warn(self, message: str) -> None: ...

    def error(self, message: str) -> None: ...


class NullNotifier:
    """A notifier that discards everything (used by default and in tests)."""

    def info(self, message: str) -> None:
        pass

    def warn(self, message: str) -> None:
        pass

    def error(self, message: str) -> None:
        pass


@dataclass
class RunOptions:
    """Feature switches for a single engine run (all optional modules off)."""

    rdap: bool = True
    bgp: bool = True
    reverse_dns: bool = False
    domains: bool = False
    ct: bool = False
    ct_seeds: list[str] = field(default_factory=list)
    expand: bool = False
    max_hosts: int = 10_000


ProgressCallback = Callable[[str], None]


class MapperEngine:
    """Runs the full mapping workflow for a list of ASNs."""

    def __init__(
        self,
        config: AppConfig,
        notifier: Notifier | None = None,
        cache: FileCache | None = None,
        bgp_service: BGPService | None = None,
        rdap_service: RDAPService | None = None,
        dns_service: ReverseDNSService | None = None,
        ct_service: CTService | None = None,
    ) -> None:
        self.config = config
        self.notifier: Notifier = notifier or NullNotifier()
        if cache is not None:
            self.cache = cache
        else:
            self.cache = FileCache(
                directory=config.cache.directory,
                default_ttl=config.cache.ttl,
                enabled=config.cache.enabled,
            )
        # Injectable services (tests pass fakes; production builds lazily).
        self._bgp_service = bgp_service
        self._rdap_service = rdap_service
        self._dns_service = dns_service
        self._ct_service = ct_service

    # ------------------------------------------------------------------
    # Lazy service construction
    # ------------------------------------------------------------------
    @property
    def bgp_service(self) -> BGPService:
        if self._bgp_service is None:
            self._bgp_service = build_bgp_service(
                self.config,
                self.cache,
                on_provider_error=self._on_bgp_provider_error,
            )
        return self._bgp_service

    @property
    def rdap_service(self) -> RDAPService:
        if self._rdap_service is None:
            self._rdap_service = build_rdap_service(self.config, self.cache)
        return self._rdap_service

    @property
    def dns_service(self) -> ReverseDNSService:
        if self._dns_service is None:
            self._dns_service = ReverseDNSService(
                cache=self.cache,
                timeout=self.config.dns.timeout,
                retries=self.config.dns.retries,
                concurrency=self.config.dns.concurrency,
                nameservers=self.config.dns.nameservers or None,
                negative_ttl=self.config.dns.negative_cache_ttl,
            )
        return self._dns_service

    @property
    def ct_service(self) -> CTService:
        if self._ct_service is None:
            client = HttpClient(
                user_agent=self.config.user_agent,
                timeout=self.config.providers.ct_timeout,
                retries=self.config.http.retries,
                backoff_base=self.config.http.backoff_base,
                max_delay=self.config.http.max_delay,
                rate_limiter=RateLimiter(self.config.http.min_request_interval),
                cache=self.cache,
                verify_tls=self.config.http.verify_tls,
                pool_size=self.config.threads,
            )
            self._ct_service = CTService(
                CrtShProvider(client, self.config.providers.crt_sh_url, self.config.providers.ct_timeout)
            )
        return self._ct_service

    def _on_bgp_provider_error(self, provider_name: str, reason: str) -> None:
        self.notifier.warn(f"BGP provider {provider_name} unavailable: {reason}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self, asns: Sequence[int], options: RunOptions | None = None) -> BulkResult:
        """Map every ASN in *asns*; never raises for per-ASN failures."""
        options = options or RunOptions()
        started = time.perf_counter()
        results: list[ASNResult] = []
        failed: list[FailedASN] = []
        for asn in asns:
            try:
                results.append(self._process(asn, options))
            except Exception as exc:  # noqa: BLE001 — one ASN must never abort the run
                message = f"unexpected error while processing AS{asn}: {exc.__class__.__name__}: {exc}"
                LOGGER.exception(message)
                self.notifier.error(message)
                failed.append(FailedASN(asn=format_asn(asn), reason=str(exc)))
        return BulkResult(
            results=results,
            failed=failed,
            started_at=utc_now_iso(),
            completed_in=time.perf_counter() - started,
        )

    # ------------------------------------------------------------------
    def _process(self, asn: int, options: RunOptions) -> ASNResult:
        """Collect everything for a single ASN."""
        started = time.perf_counter()
        asn_str = format_asn(asn)
        result = ASNResult(asn=asn_str)
        sources: list[SourceRecord] = []
        errors: list[str] = []
        notes: list[str] = []

        self.notifier.info(f"Fetching ASN information for {asn_str} ...")
        info_collector = ASNInfoCollector(
            self.bgp_service,
            self.rdap_service,
            include_rdap=options.rdap,
        )
        asn_info, rdap_info, info_sources, info_errors = info_collector.collect(asn)
        result.asn_info = asn_info
        result.rdap = rdap_info
        sources.extend(info_sources)
        errors.extend(info_errors)
        if asn_info:
            self.notifier.info(
                f"ASN {asn_str} — "
                f"Organization: {asn_info.organization or 'n/a'} | "
                f"Country: {asn_info.country or 'n/a'} | "
                f"Registry: {asn_info.registry or 'n/a'}"
            )

        # -- prefixes ---------------------------------------------------
        self.notifier.info(f"Collecting announced prefixes for {asn_str} ...")
        prefix_collector = PrefixCollector(self.bgp_service)
        prefixes, prefix_sources, prefix_errors = prefix_collector.collect(asn)
        result.ipv4_prefixes = [p for p in prefixes if p.version == 4]
        result.ipv6_prefixes = [p for p in prefixes if p.version == 6]
        result.stats = PrefixCollector.compute_stats(prefixes)
        sources.extend(prefix_sources)
        errors.extend(prefix_errors)
        if prefixes:
            self.notifier.info(
                f"Collected {len(result.ipv4_prefixes)} IPv4 and "
                f"{len(result.ipv6_prefixes)} IPv6 prefixes"
            )

        # -- optional: reverse DNS --------------------------------------
        if options.reverse_dns:
            self.notifier.info("Performing conservative reverse-DNS sampling ...")
            rdns_collector = ReverseDNSCollector(
                self.dns_service,
                sample_per_prefix=self.config.dns.sample_per_prefix,
                max_lookups=self.config.dns.max_lookups,
            )
            progress = self._rdns_progress(rdns_collector)
            rdns_records, rdns_sources, rdns_errors = rdns_collector.collect(
                result.ipv4_prefixes + result.ipv6_prefixes, progress=progress
            )
            result.reverse_dns = rdns_records
            sources.extend(rdns_sources)
            errors.extend(rdns_errors)
            resolved = sum(1 for r in rdns_records if r.ok)
            self.notifier.info(
                f"Reverse DNS: {resolved}/{len(rdns_records)} sampled addresses resolved"
            )
            if not rdns_records and not rdns_errors:
                notes.append("Reverse DNS produced no lookups (no prefixes or sample is zero).")

        # -- optional: domains -------------------------------------------
        domain_collector = DomainCollector(ct_service=self.ct_service if options.ct else None)
        domain_groups: list[list[DomainRecord]] = []
        if options.domains or options.ct:
            self.notifier.info("Correlating public domains (passive sources) ...")
        if options.domains:
            from_registration = DomainCollector.from_registration_data(asn_info, rdap_info)
            from_rdns = DomainCollector.from_reverse_dns(result.reverse_dns)
            domain_groups.extend([from_registration, from_rdns])
            if from_registration:
                self.notifier.info(
                    f"Domain correlation: {len(from_registration)} seed domain(s) from registration data"
                )
            if not result.reverse_dns:
                notes.append(
                    "Domain correlation is limited without reverse DNS "
                    "(add --reverse-dns to enrich with PTR-observed hostnames)."
                )

        # -- optional: certificate transparency ---------------------------
        if options.ct:
            seeds = [normalize_domain(s) for s in options.ct_seeds]
            seeds = [s for s in seeds if s]
            if not seeds:
                # derive seeds from registration data even without --domains
                seeds = [r.domain for g in domain_groups for r in g]
                if not seeds and asn_info:
                    seeds = [r.domain for r in DomainCollector.from_registration_data(asn_info, rdap_info)]
                seeds = list(dict.fromkeys(seeds))
            if not seeds:
                notes.append(
                    "CT enumeration needs seed domains (none derived from this run). "
                    "Provide one or more with --ct-domain."
                )
                self.notifier.warn("CT: no seed domains available; skipping")
            else:
                self.notifier.info(f"Querying Certificate Transparency for {len(seeds)} seed domain(s) ...")
                ct_domains, certificates, ct_sources, ct_errors = domain_collector.from_ct(seeds)
                domain_groups.append(ct_domains)
                result.certificates = certificates
                sources.extend(ct_sources)
                errors.extend(ct_errors)
                names: list[str] = []
                for cert in certificates:
                    names.extend(cert.dns_names)
                    if cert.common_name:
                        names.append(cert.common_name)
                from .validators import dedupe_strings

                result.ct_names = sorted(dedupe_strings(names))
                self.notifier.info(
                    f"CT: {len(certificates)} certificates, {len(result.ct_names)} unique names"
                )

        if domain_groups:
            result.domains = domain_collector.merge(domain_groups)

        # -- optional: range expansion ------------------------------------
        if options.expand and prefixes:
            result.expansions = [
                expand_prefix(record.prefix, options.max_hosts) for record in prefixes
            ]

        # -- finalize -------------------------------------------------------
        deduped_sources: list[SourceRecord] = []
        seen_sources: set[tuple[str, str, str]] = set()
        for source in sources:
            key = (source.provider, source.type, source.detail)
            if key in seen_sources:
                continue
            seen_sources.add(key)
            deduped_sources.append(source)
        result.sources = deduped_sources
        result.errors = errors
        result.notes = notes
        result.elapsed_seconds = time.perf_counter() - started
        return result

    # ------------------------------------------------------------------
    def _rdns_progress(self, collector: ReverseDNSCollector) -> Callable[[int, int], None]:
        """Build a progress callback that reports every ~10% of lookups."""
        last_reported = [-1]

        def progress(done: int, total: int) -> None:
            if total <= 0:
                return
            percent = int(done * 100 / total)
            if percent >= last_reported[0] + 10 or done == total:
                last_reported[0] = percent
                self.notifier.info(f"Reverse DNS progress: {done}/{total} lookups")

        return progress
