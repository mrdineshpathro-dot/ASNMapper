"""RDAP (Registration Data Access Protocol) providers.

RDAP is the modern, machine-readable replacement for WHOIS. The tool prefers
it over scraping legacy WHOIS pages.

Architecture::

    RegistryProvider (abstract)
    ├── RDAPBootstrapProvider  — rdap.org IANA bootstrap redirect (primary)
    └── RIRRdapProvider        — direct RIR endpoints (ARIN/RIPE/APNIC/
                                 LACNIC/AFRINIC) used as fallbacks

:class:`RDAPService` walks the chain and returns the first authoritative
answer, recording which registry answered.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from ..models import RDAPInfo, SourceRecord, utc_now_iso
from ..utils.cache import FileCache
from ..utils.logger import get_logger
from ..utils.networking import (
    HttpClient,
    MalformedResponseError,
    NetworkError,
    ProviderError,
    RateLimiter,
)
from ..validators import format_asn

__all__ = [
    "RDAPBootstrapProvider",
    "RDAPService",
    "RIRRdapProvider",
    "RegistryProvider",
    "build_rdap_service",
]

LOGGER = get_logger()

#: Maps RDAP endpoint hosts to the registry they serve.
_RDAP_HOSTS_TO_REGISTRY = {
    "rdap.arin.net": "ARIN",
    "rdap.db.ripe.net": "RIPE",
    "rdap.apnic.net": "APNIC",
    "rdap.lacnic.net": "LACNIC",
    "rdap.afrinic.net": "AFRINIC",
}


class RegistryProvider(ABC):
    """Abstract base class for ASN registration-data sources."""

    name: str = "registry"

    def __init__(self, client: HttpClient) -> None:
        self.client = client

    @abstractmethod
    def lookup_asn(self, asn: int) -> RDAPInfo:
        """Return RDAP registration information for *asn*."""


class RDAPBootstrapProvider(RegistryProvider):
    """Query ``rdap.org`` which redirects to the authoritative RIR RDAP."""

    name = "rdap.org"

    def __init__(self, client: HttpClient, bootstrap_url: str = "https://rdap.org") -> None:
        super().__init__(client)
        self.bootstrap_url = bootstrap_url.rstrip("/")

    def lookup_asn(self, asn: int) -> RDAPInfo:
        url = f"{self.bootstrap_url}/autnum/{asn}"
        response = self.client.get(url)
        if response.status_code == 404:
            raise ProviderError(f"RDAP: AS{asn} not found (rdap.org)")
        if not 200 <= response.status_code < 300:
            raise ProviderError(f"RDAP: HTTP {response.status_code} from {url}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise MalformedResponseError(f"RDAP: malformed JSON from {url}") from exc
        registry = registry_from_rdap_url(response.url) or "unknown"
        return parse_autnum_payload(payload, asn, registry=registry, source=self.name)


class RIRRdapProvider(RegistryProvider):
    """Query one specific RIR RDAP endpoint directly (fallback path)."""

    def __init__(self, client: HttpClient, registry: str, base_url: str) -> None:
        super().__init__(client)
        self.registry = registry
        self.base_url = base_url.rstrip("/")

    def lookup_asn(self, asn: int) -> RDAPInfo:
        url = f"{self.base_url}/autnum/{asn}"
        payload = self.client.get_json(url, cache_namespace="rdap")
        return parse_autnum_payload(payload, asn, registry=self.registry, source=f"RDAP {self.registry}")


def registry_from_rdap_url(url: str) -> str | None:
    """Infer the RIR name from the final (post-redirect) RDAP URL."""
    host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    return _RDAP_HOSTS_TO_REGISTRY.get(host)


# --------------------------------------------------------------------------
# RDAP payload parsing (pure functions — unit tested without network)
# --------------------------------------------------------------------------


def _vcard_value(vcard_array: Any, key: str) -> Any:
    """Extract a value from a jCard ``["vcard", [[key, {}, "text", value], ...]]``."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    for entry in vcard_array[1]:
        if isinstance(entry, list) and entry and str(entry[0]).lower() == key.lower():
            # ["fn", {}, "text", "Google LLC"]
            return entry[3] if len(entry) > 3 else None
    return None


def _vcard_flat(value: Any) -> str | None:
    """Flatten a jCard value that may be a scalar or a list of scalars."""
    if isinstance(value, (list, tuple)):
        parts = [str(v).strip() for v in value if str(v).strip()]
        return ", ".join(parts) or None
    if value is None:
        return None
    return str(value).strip() or None


def _parse_country(payload: dict[str, Any], entities: list[dict[str, Any]]) -> str | None:
    """Best-effort country extraction (top-level field or registrant vCard)."""
    country = payload.get("country")
    if isinstance(country, str) and country.strip():
        return country.strip().upper()[:2]
    for entity in entities:
        if "registrant" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            # jCard adr: [label?, pobox?, ext?, street?, city?, region?, postcode?, country?]
            adr = _vcard_value(vcard, "adr")
            if isinstance(adr, list) and adr:
                candidate = _vcard_flat(adr[-1])
                if candidate:
                    return candidate.upper()[:2]
            candidate = _vcard_flat(_vcard_value(vcard, "country"))
            if candidate:
                return candidate.upper()[:2]
    return None


def parse_autnum_payload(
    payload: Any,
    asn: int,
    registry: str | None = None,
    source: str = "RDAP",
) -> RDAPInfo:
    """Parse an RDAP ``autnum`` object into an :class:`RDAPInfo`.

    Tolerates missing fields — RDAP responses differ subtly between RIRs.
    """
    if not isinstance(payload, dict):
        raise MalformedResponseError("RDAP: autnum payload is not an object")
    asn_str = format_asn(asn)

    entities = [e for e in payload.get("entities") or [] if isinstance(e, dict)]
    organization: str | None = None
    for entity in entities:
        if "registrant" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            organization = (
                _vcard_flat(_vcard_value(vcard, "fn"))
                or _vcard_flat(_vcard_value(vcard, "org"))
                or organization
            )
            if organization:
                break

    remarks: list[str] = []
    for remark in payload.get("remarks") or []:
        if isinstance(remark, dict):
            for line in remark.get("description") or []:
                if isinstance(line, str) and line.strip():
                    remarks.append(line.strip())
                if len(remarks) >= 5:
                    break
        if len(remarks) >= 5:
            break

    start_autnum = payload.get("startAutnum")
    end_autnum = payload.get("endAutnum")
    return RDAPInfo(
        asn=asn_str,
        handle=str(payload.get("handle")) if payload.get("handle") is not None else None,
        name=str(payload.get("name")) if payload.get("name") else None,
        organization=organization,
        country=_parse_country(payload, entities),
        registry=registry,
        asn_type=str(payload.get("type")) if payload.get("type") else None,
        start_autnum=int(start_autnum) if isinstance(start_autnum, int) else None,
        end_autnum=int(end_autnum) if isinstance(end_autnum, int) else None,
        remarks=remarks,
        source=source,
    )


class RDAPService:
    """Coordinates RDAP providers with automatic fallback."""

    def __init__(self, providers: Sequence[RegistryProvider]) -> None:
        if not providers:
            raise ValueError("RDAPService requires at least one provider")
        self.providers: list[RegistryProvider] = list(providers)

    def lookup_asn(self, asn: int) -> tuple[RDAPInfo | None, list[SourceRecord], list[str]]:
        """Lookup ASN registration data with fallback.

        :returns: ``(rdap_info_or_None, sources, errors)``
        """
        errors: list[str] = []
        for index, provider in enumerate(self.providers):
            try:
                info = provider.lookup_asn(asn)
            except (ProviderError, NetworkError) as exc:
                message = str(exc)
                errors.append(f"{provider.name}: {message}")
                LOGGER.warning("RDAP provider %s failed: %s", provider.name, message)
                if index + 1 < len(self.providers):
                    LOGGER.info("RDAP: trying fallback provider %s", self.providers[index + 1].name)
                continue
            return info, [SourceRecord(provider=provider.name, type="registration", retrieved_at=utc_now_iso(), detail=f"AS{asn}")], errors
        return None, [], errors or [f"RDAP data unavailable for AS{asn}"]


def build_rdap_service(config: Any, cache: FileCache | None) -> RDAPService:
    """Construct an :class:`RDAPService` from the application configuration."""
    client = HttpClient(
        user_agent=config.user_agent,
        timeout=config.http.timeout,
        retries=config.http.retries,
        backoff_base=config.http.backoff_base,
        max_delay=config.http.max_delay,
        rate_limiter=RateLimiter(config.http.min_request_interval),
        cache=cache,
        verify_tls=config.http.verify_tls,
        pool_size=config.threads,
    )
    endpoints: dict[str, str] = dict(getattr(config.providers, "rdap_endpoints", {}) or {})
    endpoints.setdefault("bootstrap", config.providers.rdap_bootstrap_url)

    providers: list[RegistryProvider] = []
    for name in config.providers.rdap_order:
        key = str(name).strip().lower()
        url = endpoints.get(key)
        if not url:
            config.warnings.append(f"Unknown RDAP provider '{name}' (skipped)")
            continue
        if key == "bootstrap":
            providers.append(RDAPBootstrapProvider(client, url))
        else:
            providers.append(RIRRdapProvider(client, key.upper(), url))
    if not providers:
        providers.append(RDAPBootstrapProvider(client, config.providers.rdap_bootstrap_url))
    return RDAPService(providers)
