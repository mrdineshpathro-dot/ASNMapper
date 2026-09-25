"""ASN metadata collector.

Merges two independent views of an ASN:

* **BGP provider metadata** (RIPEstat as-overview / BGPView) — the name the
  network announces under;
* **RDAP registration data** — the authoritative registry record.

RDAP wins for registration facts (organization, country, registry, handle);
BGP data fills gaps (website, alternate names). The distinction between
*registered* data and *observed* data is preserved via source strings.
"""
from __future__ import annotations

from ..models import ASNInfo, RDAPInfo, SourceRecord
from ..providers.bgp import BGPService
from ..providers.rdap import RDAPService
from ..validators import format_asn

__all__ = ["ASNInfoCollector"]


class ASNInfoCollector:
    """Collects and merges ASN metadata from BGP and RDAP sources."""

    def __init__(
        self,
        bgp: BGPService,
        rdap: RDAPService | None = None,
        include_rdap: bool = True,
    ) -> None:
        self.bgp = bgp
        self.rdap = rdap
        self.include_rdap = include_rdap and rdap is not None

    def collect(
        self, asn: int
    ) -> tuple[ASNInfo | None, RDAPInfo | None, list[SourceRecord], list[str]]:
        """Gather ASN metadata.

        :returns: ``(merged_asn_info, rdap_info, sources, errors)``
        """
        sources: list[SourceRecord] = []
        errors: list[str] = []

        bgp_info, bgp_sources, bgp_errors = self.bgp.get_asn_info(asn)
        sources.extend(bgp_sources)
        errors.extend(bgp_errors)

        rdap_info: RDAPInfo | None = None
        if self.include_rdap:
            rdap_info, rdap_sources, rdap_errors = self.rdap.lookup_asn(asn)  # type: ignore[union-attr]
            sources.extend(rdap_sources)
            errors.extend(rdap_errors)

        merged = self._merge(asn, bgp_info, rdap_info)
        return merged, rdap_info, sources, errors

    # ------------------------------------------------------------------
    @staticmethod
    def _merge(asn: int, bgp: ASNInfo | None, rdap: RDAPInfo | None) -> ASNInfo | None:
        """Merge BGP metadata with RDAP registration data (RDAP wins)."""
        if bgp is None and rdap is None:
            return None
        source_parts: list[str] = []
        if bgp and bgp.source and bgp.source != "unknown":
            source_parts.append(bgp.source)
        if rdap:
            source_parts.append(f"RDAP ({rdap.source})")

        organization = (rdap.organization if rdap else None) or (bgp.organization if bgp else None)
        as_name = (rdap.name if rdap else None) or (bgp.as_name if bgp else None)
        country = (rdap.country if rdap else None) or (bgp.country if bgp else None)
        registry = (rdap.registry if rdap else None) or (bgp.registry if bgp else None)
        website = bgp.website if bgp else None
        description = bgp.description if bgp else None

        return ASNInfo(
            asn=asn,
            asn_str=format_asn(asn),
            organization=organization,
            as_name=as_name,
            country=country,
            registry=registry,
            website=website,
            description=description,
            source=" + ".join(source_parts) or "unknown",
        )
