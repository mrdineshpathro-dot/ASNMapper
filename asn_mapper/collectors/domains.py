"""Passive domain/hostname correlation.

This collector never guesses ownership. Every domain it emits carries a
:class:`~asn_mapper.models.Confidence` label and an evidence trail:

* **INFERRED** — registrable domain of the organization website found in
  registration data (heuristic link).
* **OBSERVED** — registrable domains extracted from PTR hostnames observed
  for IPs inside announced prefixes.
* **CORRELATED** — names observed in Certificate Transparency logs for a
  seed domain (the domain itself was linked through one of the above).

If reverse DNS was not requested, PTR-derived domains are simply absent —
the collector notes that in the result instead of inventing data.
"""
from __future__ import annotations

from ..models import (
    CONFIDENCE_RANK,
    ASNInfo,
    Confidence,
    CTCertificate,
    DomainRecord,
    RDAPInfo,
    ReverseDNSRecord,
    SourceRecord,
)
from ..providers.ct import CTService
from ..utils.logger import get_logger
from ..validators import normalize_domain, registrable_domain

__all__ = ["DomainCollector"]

LOGGER = get_logger()


class DomainCollector:
    """Correlates domains from passive public sources."""

    def __init__(self, ct_service: CTService | None = None) -> None:
        self.ct_service = ct_service

    # ------------------------------------------------------------------
    # Individual passive sources
    # ------------------------------------------------------------------
    @staticmethod
    def from_registration_data(
        asn_info: ASNInfo | None, rdap: RDAPInfo | None
    ) -> list[DomainRecord]:
        """Registrable domain of any website recorded in registration data."""
        records: list[DomainRecord] = []
        websites: list[str] = []
        if asn_info and asn_info.website:
            websites.append(asn_info.website)
        for remark in (rdap.remarks if rdap else []) or []:
            # remarks occasionally contain the org's site; cheap check for URLs
            if "http://" in remark or "https://" in remark:
                websites.append(remark)
        seen: set[str] = set()
        for website in websites:
            normalized = normalize_domain(website.removeprefix("https://").removeprefix("http://").split("/")[0])
            domain = registrable_domain(normalized or "")
            if not domain or domain in seen:
                continue
            seen.add(domain)
            records.append(
                DomainRecord(
                    domain=domain,
                    confidence=Confidence.INFERRED.value,
                    source="registration data (website)",
                    evidence=(
                        f"Website associated with AS{asn_info.asn} registration "
                        f"metadata; registrable domain of {website}"
                    )
                    if asn_info
                    else f"Registrable domain of {website}",
                )
            )
        return records

    @staticmethod
    def from_reverse_dns(records: list[ReverseDNSRecord]) -> list[DomainRecord]:
        """Registrable domains observed in PTR hostnames."""
        domains: list[DomainRecord] = []
        seen: dict[str, str] = {}
        for record in records:
            if not record.hostname:
                continue
            domain = registrable_domain(record.hostname)
            if not domain:
                continue
            evidence = (
                f"PTR {record.hostname} observed for {record.ip}"
                + (f" (in {record.prefix})" if record.prefix else "")
            )
            if domain in seen:
                seen[domain] += f"; {record.ip}"
                continue
            seen[domain] = record.ip
            domains.append(
                DomainRecord(
                    domain=domain,
                    confidence=Confidence.OBSERVED.value,
                    source="reverse DNS (PTR)",
                    evidence=evidence,
                )
            )
        # Append the extra IPs seen per domain to the evidence string.
        for entry in domains:
            entry.evidence = entry.evidence + f"; first seen via {seen[entry.domain]}"
        return domains

    def from_ct(
        self, seed_domains: list[str]
    ) -> tuple[list[DomainRecord], list[CTCertificate], list[SourceRecord], list[str]]:
        """Collect domains and certificates from Certificate Transparency.

        :returns: ``(domain_records, certificates, sources, errors)``
        """
        if not self.ct_service:
            return [], [], [], ["CT service not configured"]
        certificates, sources, errors = self.ct_service.collect(seed_domains)
        records: list[DomainRecord] = []
        seen: set[str] = set()
        for seed in seed_domains:
            seed_normalized = normalize_domain(seed)
            if not seed_normalized:
                continue
            if seed_normalized not in seen:
                seen.add(seed_normalized)
                records.append(
                    DomainRecord(
                        domain=seed_normalized,
                        confidence=Confidence.CORRELATED.value,
                        source="Certificate Transparency (crt.sh)",
                        evidence=f"Seed domain (CT enumeration performed for *.{seed_normalized})",
                    )
                )
        return records, certificates, sources, errors

    # ------------------------------------------------------------------
    def merge(self, record_groups: list[list[DomainRecord]]) -> list[DomainRecord]:
        """Deduplicate domain records, keeping the highest confidence label.

        Evidence from lower-confidence duplicates is appended so nothing is
        lost.
        """
        merged: dict[str, DomainRecord] = {}
        for group in record_groups:
            for record in group:
                domain = normalize_domain(record.domain)
                if not domain:
                    continue
                existing = merged.get(domain)
                if existing is None:
                    merged[domain] = DomainRecord(
                        domain=domain,
                        confidence=record.confidence,
                        source=record.source,
                        evidence=record.evidence,
                    )
                    continue
                incoming_rank = CONFIDENCE_RANK.get(Confidence(record.confidence), 0)
                existing_rank = CONFIDENCE_RANK.get(Confidence(existing.confidence), 0)
                if incoming_rank > existing_rank:
                    existing.confidence = record.confidence
                    if record.source not in existing.source:
                        existing.source += f"; {record.source}"
                if record.evidence and record.evidence not in existing.evidence:
                    existing.evidence += f" | {record.evidence}"
        # Sort: highest confidence first, then alphabetically.
        return sorted(
            merged.values(),
            key=lambda r: (-CONFIDENCE_RANK.get(Confidence(r.confidence), 0), r.domain),
        )
