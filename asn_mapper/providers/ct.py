"""Certificate Transparency (CT) providers.

CT enumeration is **passive**: the tool queries public CT log aggregators
(crt.sh by default) for certificates issued for seed domains. It never
contacts the target infrastructure.

Because CT logs are indexed by *domain* (not by ASN or IP), CT enumeration
requires seed domains. Seeds come from ``--ct-domain`` options or from
domains already correlated in the current run (e.g. the organization website
or hostnames observed via reverse DNS).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import CTCertificate, SourceRecord, utc_now_iso
from ..utils.networking import HttpClient, MalformedResponseError
from ..validators import normalize_domain

__all__ = ["CTProvider", "CTService", "CrtShProvider"]


class CTProvider(ABC):
    """Abstract base class for Certificate Transparency data sources."""

    name: str = "ct"

    def __init__(self, client: HttpClient) -> None:
        self.client = client

    @abstractmethod
    def search_domain(self, domain: str) -> list[CTCertificate]:
        """Return certificates observed in CT logs for *domain*."""


class CrtShProvider(CTProvider):
    """crt.sh — the public Certificate Transparency log aggregator.

    Note: crt.sh's JSON output exposes the issuer and DNS names but not the
    subject organization field, so :attr:`CTCertificate.organization` stays
    ``None`` for this provider.
    """

    name = "crt.sh"

    def __init__(self, client: HttpClient, url: str = "https://crt.sh/", timeout: float = 60.0) -> None:
        super().__init__(client)
        self.url = url
        self.timeout = timeout

    def search_domain(self, domain: str) -> list[CTCertificate]:
        normalized = normalize_domain(domain)
        if not normalized:
            return []
        payload = self.client.get_json(
            self.url,
            params={"q": f"%.{normalized}", "output": "json"},
            timeout=self.timeout,
            cache_namespace="ct",
        )
        return self.parse_entries(payload)

    @staticmethod
    def parse_entries(payload: Any) -> list[CTCertificate]:
        """Parse a crt.sh JSON payload into deduplicated certificates."""
        if not isinstance(payload, list):
            raise MalformedResponseError("crt.sh: payload is not a JSON array")
        certificates: list[CTCertificate] = []
        seen: set[tuple[Any, ...]] = set()
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            names: list[str] = []
            raw_names = entry.get("name_value")
            if isinstance(raw_names, str):
                names.extend(raw_names.split("\n"))
            common_name = str(entry.get("common_name") or "").strip() or None
            if common_name:
                names.append(common_name)
            normalized_names = sorted(
                {n for n in (normalize_domain(x) for x in names) if n}
            )
            if not normalized_names and not common_name:
                continue
            issuer = str(entry.get("issuer_name") or "").strip() or None
            key = (
                entry.get("serial_number"),
                common_name,
                tuple(normalized_names),
                str(entry.get("not_before") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            certificates.append(
                CTCertificate(
                    common_name=common_name,
                    dns_names=normalized_names,
                    organization=None,  # not exposed by crt.sh JSON output
                    issuer=issuer,
                    not_before=str(entry.get("not_before") or "") or None,
                    not_after=str(entry.get("not_after") or "") or None,
                    source="crt.sh",
                )
            )
        return certificates


class CTService:
    """Coordinates CT lookups across seed domains (one provider for now)."""

    def __init__(self, provider: CTProvider) -> None:
        self.provider = provider

    def collect(
        self, seed_domains: list[str]
    ) -> tuple[list[CTCertificate], list[SourceRecord], list[str]]:
        """Query CT logs for every seed domain.

        :returns: ``(certificates, sources, errors)`` — certificates are
            deduplicated and DNS names are normalized/lowercased.
        """
        certificates: list[CTCertificate] = []
        sources: list[SourceRecord] = []
        errors: list[str] = []
        seen: set[tuple[Any, ...]] = set()
        for seed in seed_domains:
            normalized = normalize_domain(seed)
            if not normalized:
                errors.append(f"CT: invalid seed domain {seed!r}")
                continue
            try:
                found = self.provider.search_domain(normalized)
            except Exception as exc:  # noqa: BLE001 — one bad seed must not abort
                errors.append(f"CT lookup failed for {normalized}: {exc}")
                continue
            sources.append(
                SourceRecord(
                    provider=self.provider.name,
                    type="CT",
                    retrieved_at=utc_now_iso(),
                    detail=f"{len(found)} certificates for {normalized}",
                )
            )
            for certificate in found:
                key = (
                    certificate.common_name,
                    tuple(certificate.dns_names),
                    certificate.issuer,
                    certificate.not_before,
                )
                if key in seen:
                    continue
                seen.add(key)
                certificates.append(certificate)
        return certificates, sources, errors
