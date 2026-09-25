"""Prefix collection, statistics, expansion and safe IP sampling.

All CIDR handling goes through Python's standard :mod:`ipaddress` module.
Prefixes are validated, canonicalized (host bits zeroed), deduplicated and
sorted before use. IPv6 address space is never enumerated — only counted.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence

from ..models import (
    PrefixExpansion,
    PrefixRecord,
    PrefixStats,
    SourceRecord,
    humanize_big_number,
)
from ..providers.bgp import BGPService
from ..utils.logger import get_logger
from ..validators import InvalidCIDRError, parse_cidr

__all__ = ["PrefixCollector", "expand_prefix", "sample_ips"]

LOGGER = get_logger()


class PrefixCollector:
    """Collects and normalizes announced prefixes for an ASN."""

    def __init__(self, bgp: BGPService) -> None:
        self.bgp = bgp

    # ------------------------------------------------------------------
    def collect(
        self, asn: int
    ) -> tuple[list[PrefixRecord], list[SourceRecord], list[str]]:
        """Fetch, validate, deduplicate and sort announced prefixes.

        :returns: ``(records, sources, errors)`` — records are sorted IPv4
            first (numerically), then IPv6.
        """
        records, sources, errors = self.bgp.get_prefixes(asn)
        records = normalize_prefix_records(records)
        return records, sources, errors

    # ------------------------------------------------------------------
    @staticmethod
    def compute_stats(records: Sequence[PrefixRecord]) -> PrefixStats:
        """Compute aggregate statistics for a set of prefix records."""
        stats = PrefixStats()
        for record in records:
            network = parse_cidr(record.prefix)
            addresses = network.num_addresses
            if network.version == 4:
                stats.ipv4_count += 1
                stats.ipv4_addresses += addresses
                length = network.prefixlen
                stats.ipv4_distribution[length] = stats.ipv4_distribution.get(length, 0) + 1
                if stats.ipv4_min_prefixlen is None or length < stats.ipv4_min_prefixlen:
                    stats.ipv4_min_prefixlen = length
                if stats.ipv4_max_prefixlen is None or length > stats.ipv4_max_prefixlen:
                    stats.ipv4_max_prefixlen = length
            else:
                stats.ipv6_count += 1
                stats.ipv6_addresses += addresses
                length = network.prefixlen
                stats.ipv6_distribution[length] = stats.ipv6_distribution.get(length, 0) + 1
                if stats.ipv6_min_prefixlen is None or length < stats.ipv6_min_prefixlen:
                    stats.ipv6_min_prefixlen = length
                if stats.ipv6_max_prefixlen is None or length > stats.ipv6_max_prefixlen:
                    stats.ipv6_max_prefixlen = length
        stats.total_count = stats.ipv4_count + stats.ipv6_count
        return stats


def normalize_prefix_records(records: Iterable[PrefixRecord]) -> list[PrefixRecord]:
    """Validate, canonicalize, deduplicate and sort prefix records.

    Invalid prefixes are dropped (with a log entry) rather than crashing the
    run.
    """
    seen: set[str] = set()
    result: list[PrefixRecord] = []
    dropped = 0
    for record in records:
        try:
            network = parse_cidr(record.prefix)
        except InvalidCIDRError as exc:
            dropped += 1
            LOGGER.warning("Dropping invalid prefix %r: %s", record.prefix, exc)
            continue
        canonical = str(network)
        if canonical in seen:
            continue
        seen.add(canonical)
        result.append(
            PrefixRecord(
                prefix=canonical,
                version=network.version,
                confidence=record.confidence,
                source=record.source,
            )
        )
    result.sort(key=lambda r: (r.version, parse_cidr(r.prefix).network_address, r.prefix))
    if dropped:
        LOGGER.warning("Dropped %d invalid prefix records", dropped)
    return result


# --------------------------------------------------------------------------
# Range expansion
# --------------------------------------------------------------------------


def expand_prefix(prefix: str | ipaddress.IPv4Network | ipaddress.IPv6Network, max_hosts: int) -> PrefixExpansion:
    """Expand a CIDR prefix into a usable range description.

    Enumeration of individual addresses only happens when the usable host
    count is at or below *max_hosts* — otherwise ``addresses`` is ``None``
    and ``skipped_reason`` explains why. This makes accidental generation of
    millions of addresses impossible.

    For IPv6, "usable hosts" equals the total address count (IPv6 has no
    broadcast address); for IPv4 it is ``total − 2`` for prefixes longer
    than /30 (``/31`` and ``/32`` are treated as point-to-point/host).
    """
    if isinstance(prefix, str):
        network = parse_cidr(prefix)
    else:
        network = prefix

    total = network.num_addresses
    if network.version == 4:
        last_address = network.broadcast_address
        if network.prefixlen >= 31:
            usable = total
        else:
            usable = total - 2
    else:
        last_address = network[-1]
        usable = total

    first_host = network.network_address if network.prefixlen in (31, 32, 127, 128) else network.network_address + 1
    last_host = last_address if network.prefixlen in (31, 32, 127, 128) else last_address - 1

    addresses: list[str] | None = None
    skipped_reason: str | None = None
    if usable <= max_hosts:
        addresses = [str(address) for address in network]
    else:
        skipped_reason = (
            f"{humanize_big_number(usable)} addresses — enumeration skipped "
            f"because range exceeds --max-hosts ({max_hosts:,})"
        )

    return PrefixExpansion(
        prefix=str(network),
        ip_version=network.version,
        network=str(network.network_address),
        last_address=str(last_address),
        first_host=str(first_host),
        last_host=str(last_host),
        total_addresses=total,
        usable_hosts=usable,
        addresses=addresses,
        skipped_reason=skipped_reason,
    )


# --------------------------------------------------------------------------
# Safe IP sampling (used for reverse DNS)
# --------------------------------------------------------------------------


def sample_ips(
    prefix: str | ipaddress.IPv4Network | ipaddress.IPv6Network,
    sample_size: int,
) -> list[str]:
    """Deterministically sample addresses from a prefix.

    For prefixes with more than two addresses the sample is taken from the
    beginning of the *host* portion (network + 1, network + 2, ...) — a
    conservative, predictable choice that avoids hammering any single range.
    For tiny prefixes (``/31``, ``/32``, ``/127``, ``/128``) every address
    is returned.
    """
    if isinstance(prefix, str):
        network = parse_cidr(prefix)
    else:
        network = prefix
    if sample_size <= 0:
        return []
    total = network.num_addresses
    if total <= 2:
        return [str(address) for address in network]
    take = min(sample_size, total - 2)
    return [str(network.network_address + offset + 1) for offset in range(take)]
