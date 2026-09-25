"""Reverse-DNS collector.

Reverse DNS over an entire announced space is impossible (and rude), so the
collector takes a **bounded, deterministic sample** per prefix (default: the
first two host addresses of each prefix) and caps the total number of
lookups per run. Both knobs are configurable.
"""
from __future__ import annotations

from ..models import PrefixRecord, ReverseDNSRecord, SourceRecord, utc_now_iso
from ..providers.dns import ReverseDNSService
from ..utils.logger import get_logger
from .prefixes import sample_ips

__all__ = ["ReverseDNSCollector"]

LOGGER = get_logger()


class ReverseDNSCollector:
    """Performs bounded reverse-DNS sampling over announced prefixes."""

    def __init__(
        self,
        dns: ReverseDNSService,
        sample_per_prefix: int = 2,
        max_lookups: int = 256,
    ) -> None:
        self.dns = dns
        self.sample_per_prefix = max(0, int(sample_per_prefix))
        self.max_lookups = max(0, int(max_lookups))

    # ------------------------------------------------------------------
    def select_targets(
        self, prefixes: list[PrefixRecord]
    ) -> list[tuple[PrefixRecord, str]]:
        """Choose the (prefix, ip) pairs to look up, honoring both limits."""
        targets: list[tuple[PrefixRecord, str]] = []
        seen_ips: set[str] = set()
        for record in prefixes:
            if len(targets) >= self.max_lookups:
                break
            for ip in sample_ips(record.prefix, self.sample_per_prefix):
                if ip in seen_ips:
                    continue
                if len(targets) >= self.max_lookups:
                    break
                seen_ips.add(ip)
                targets.append((record, ip))
        return targets

    # ------------------------------------------------------------------
    def collect(
        self, prefixes: list[PrefixRecord], progress: object | None = None
    ) -> tuple[list[ReverseDNSRecord], list[SourceRecord], list[str]]:
        """Run the reverse-DNS sampling.

        :returns: ``(records, sources, errors)``
        """
        if not prefixes:
            return [], [], []

        targets = self.select_targets(prefixes)
        if not targets:
            return [], [], ["Reverse DNS skipped: sample size or lookup cap is zero"]

        pairs = {ip: record.prefix for record, ip in targets}
        ips = [ip for _, ip in targets]

        try:
            records = self.dns.lookup_many(ips, progress=progress)
        except RuntimeError as exc:  # dnspython missing, resolver broken, etc.
            message = f"Reverse DNS unavailable: {exc}"
            LOGGER.warning(message)
            return [], [], [message]

        for record in records:
            record.prefix = pairs.get(record.ip)

        sources = [
            SourceRecord(
                provider="DNS",
                type="reverse DNS",
                retrieved_at=utc_now_iso(),
                detail=f"{len(records)} PTR lookups across {len(prefixes)} prefixes "
                f"({self.sample_per_prefix} per prefix, cap {self.max_lookups})",
            )
        ]
        return records, sources, []
