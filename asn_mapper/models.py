"""Data models shared across ASN Asset Mapper.

All models are plain :mod:`dataclasses` with explicit ``to_dict()`` methods so
they serialize cleanly to the documented JSON schema. Confidence labels are
used to distinguish *registered* facts from *observed* or *inferred*
associations — see :class:`Confidence`.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

__all__ = [
    "APP_TOOL_NAME",
    "ASNInfo",
    "ASNResult",
    "BulkResult",
    "CTCertificate",
    "Confidence",
    "CONFIDENCE_RANK",
    "DomainRecord",
    "FailedASN",
    "PrefixExpansion",
    "PrefixRecord",
    "PrefixStats",
    "RDAPInfo",
    "ReverseDNSRecord",
    "SourceRecord",
    "utc_now_iso",
]

APP_TOOL_NAME = "asn-asset-mapper"


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (``...Z`` suffix)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Confidence(StrEnum):
    """Correlation confidence for a discovered asset.

    * ``DIRECT``     — registered or announced by the ASN itself (e.g. an
      announced BGP prefix, RIR registration data).
    * ``CORRELATED`` — publicly associated with the organization, but not
      registered under the ASN (e.g. Certificate Transparency names).
    * ``OBSERVED``   — observed in public data (e.g. PTR hostnames).
    * ``INFERRED``   — derived by heuristic (e.g. registrable domain of an
      organization website).
    * ``UNKNOWN``    — provenance could not be determined.
    """

    DIRECT = "DIRECT"
    CORRELATED = "CORRELATED"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


#: Sortable ranking used when merging duplicate records (higher wins).
CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.DIRECT: 4,
    Confidence.CORRELATED: 3,
    Confidence.OBSERVED: 2,
    Confidence.INFERRED: 1,
    Confidence.UNKNOWN: 0,
}


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------


@dataclass
class SourceRecord:
    """Provenance record for a collected dataset.

    Every dataset produced by the tool records *where* it came from and
    *when* it was retrieved so results stay reproducible and verifiable.
    """

    provider: str
    type: str  # e.g. "BGP", "RDAP", "DNS", "CT", "registration"
    retrieved_at: str = field(default_factory=utc_now_iso)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# ASN / registry information
# --------------------------------------------------------------------------


@dataclass
class ASNInfo:
    """Merged, high-level ASN registration/announcement metadata."""

    asn: int
    asn_str: str
    organization: str | None = None
    as_name: str | None = None
    country: str | None = None
    registry: str | None = None
    website: str | None = None
    description: str | None = None
    source: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RDAPInfo:
    """Structured RDAP (Registration Data Access Protocol) lookup result."""

    asn: str
    handle: str | None = None
    name: str | None = None
    organization: str | None = None
    country: str | None = None
    registry: str | None = None
    asn_type: str | None = None
    start_autnum: int | None = None
    end_autnum: int | None = None
    remarks: list[str] = field(default_factory=list)
    source: str = "RDAP"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Prefixes
# --------------------------------------------------------------------------


@dataclass
class PrefixRecord:
    """A single publicly announced IP prefix."""

    prefix: str  # canonical CIDR string
    version: int  # 4 or 6
    confidence: str = Confidence.DIRECT.value
    source: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PrefixStats:
    """Aggregated statistics over a set of prefixes."""

    ipv4_count: int = 0
    ipv6_count: int = 0
    total_count: int = 0
    ipv4_addresses: int = 0
    ipv6_addresses: int = 0  # exact big-int sum (may exceed 2^128 scale)
    ipv4_min_prefixlen: int | None = None
    ipv4_max_prefixlen: int | None = None
    ipv6_min_prefixlen: int | None = None
    ipv6_max_prefixlen: int | None = None
    ipv4_distribution: dict[int, int] = field(default_factory=dict)
    ipv6_distribution: dict[int, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Human-friendly representation of the (astronomically large) IPv6
        # space; the exact integer is kept as well for programmatic use.
        data["ipv6_addresses_human"] = humanize_big_number(self.ipv6_addresses)
        return data


def humanize_big_number(value: int) -> str:
    """Format a possibly astronomically large integer for humans.

    Small numbers use thousands separators; large ones use scientific
    notation (e.g. ``4.25×10^37``).
    """
    if value < 1_000_000_000_000:
        return f"{value:,}"
    exponent = value.bit_length() - 1
    mantissa = value / (2**exponent)
    return f"≈{mantissa:.2f}×2^{exponent}"


@dataclass
class PrefixExpansion:
    """Result of expanding a CIDR prefix into a usable range.

    ``addresses`` is ``None`` when the range exceeded the configured host
    limit — the tool never accidentally enumerates millions of addresses.
    """

    prefix: str
    ip_version: int
    network: str
    last_address: str  # broadcast for IPv4, last address for IPv6
    first_host: str
    last_host: str
    total_addresses: int
    usable_hosts: int
    addresses: list[str] | None = None
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Domains / hostnames
# --------------------------------------------------------------------------


@dataclass
class DomainRecord:
    """A domain or hostname correlated with the target ASN.

    Domains are always labeled with a :class:`Confidence` value and an
    evidence trail — the tool never claims definitive ownership.
    """

    domain: str
    confidence: str = Confidence.CORRELATED.value
    source: str = "unknown"
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReverseDNSRecord:
    """A single reverse-DNS (PTR) lookup result."""

    ip: str
    hostname: str | None = None
    prefix: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.hostname)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CTCertificate:
    """A certificate observed in Certificate Transparency logs."""

    common_name: str | None = None
    dns_names: list[str] = field(default_factory=list)
    organization: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    source: str = "crt.sh"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Result envelopes
# --------------------------------------------------------------------------


@dataclass
class FailedASN:
    """An ASN that could not be processed at all."""

    asn: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ASNResult:
    """Everything collected for a single ASN during one run."""

    asn: str
    timestamp: str = field(default_factory=utc_now_iso)
    asn_info: ASNInfo | None = None
    rdap: RDAPInfo | None = None
    ipv4_prefixes: list[PrefixRecord] = field(default_factory=list)
    ipv6_prefixes: list[PrefixRecord] = field(default_factory=list)
    stats: PrefixStats | None = None
    expansions: list[PrefixExpansion] = field(default_factory=list)
    reverse_dns: list[ReverseDNSRecord] = field(default_factory=list)
    domains: list[DomainRecord] = field(default_factory=list)
    ct_names: list[str] = field(default_factory=list)
    certificates: list[CTCertificate] = field(default_factory=list)
    sources: list[SourceRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    # -- convenience accessors ------------------------------------------
    @property
    def organization(self) -> str | None:
        if self.rdap and self.rdap.organization:
            return self.rdap.organization
        if self.asn_info:
            return self.asn_info.organization
        return None

    @property
    def country(self) -> str | None:
        if self.rdap and self.rdap.country:
            return self.rdap.country
        if self.asn_info:
            return self.asn_info.country
        return None

    @property
    def registry(self) -> str | None:
        if self.rdap and self.rdap.registry:
            return self.rdap.registry
        if self.asn_info:
            return self.asn_info.registry
        return None

    @property
    def prefix_count(self) -> dict[str, int]:
        return {
            "ipv4": len(self.ipv4_prefixes),
            "ipv6": len(self.ipv6_prefixes),
            "total": len(self.ipv4_prefixes) + len(self.ipv6_prefixes),
        }

    @property
    def successful(self) -> bool:
        """True when at least one data source produced usable results."""
        return bool(
            self.asn_info
            or self.rdap
            or self.ipv4_prefixes
            or self.ipv6_prefixes
            or self.domains
            or self.reverse_dns
            or self.ct_names
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the documented machine-readable JSON schema."""
        return {
            "asn": self.asn,
            "organization": self.organization,
            "country": self.country,
            "registry": self.registry,
            "asn_info": self.asn_info.to_dict() if self.asn_info else None,
            "rdap": self.rdap.to_dict() if self.rdap else None,
            "ipv4_prefixes": [p.prefix for p in self.ipv4_prefixes],
            "ipv6_prefixes": [p.prefix for p in self.ipv6_prefixes],
            "prefix_count": self.prefix_count,
            "prefix_stats": self.stats.to_dict() if self.stats else None,
            "prefix_details": [
                p.to_dict() for p in self.ipv4_prefixes + self.ipv6_prefixes
            ],
            "expanded_ranges": [e.to_dict() for e in self.expansions],
            "domains": [d.domain for d in self.domains],
            "domain_records": [d.to_dict() for d in self.domains],
            "reverse_dns": [r.to_dict() for r in self.reverse_dns],
            "ct_names": list(self.ct_names),
            "certificates": [c.to_dict() for c in self.certificates],
            "sources": [s.to_dict() for s in self.sources],
            "errors": list(self.errors),
            "notes": list(self.notes),
            "timestamp": self.timestamp,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


@dataclass
class BulkResult:
    """Aggregated result for a multi-ASN run."""

    results: list[ASNResult] = field(default_factory=list)
    failed: list[FailedASN] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)
    completed_in: float = 0.0

    @property
    def processed(self) -> int:
        return len(self.results) + len(self.failed)

    @property
    def successful(self) -> int:
        return len(self.results)

    @property
    def failure_count(self) -> int:
        return len(self.failed)

    def to_dict(self, single: bool = False) -> dict[str, Any]:
        """Serialize the run.

        :param single: when ``True`` and exactly one ASN succeeded, emit the
            bare per-ASN object (matching the documented JSON schema) instead
            of the bulk envelope.
        """
        if single and len(self.results) == 1 and not self.failed:
            return self.results[0].to_dict()
        return {
            "tool": APP_TOOL_NAME,
            "processed": self.processed,
            "successful": self.successful,
            "failed": self.failure_count,
            "started_at": self.started_at,
            "completed_in": round(self.completed_in, 3),
            "results": [r.to_dict() for r in self.results],
            "failed_asns": [f.to_dict() for f in self.failed],
        }
