"""BGP prefix and ASN-metadata providers.

Architecture::

    BGPProvider (abstract)
    ├── RIPEStatProvider   — RIPEstat data API (primary)
    ├── BGPViewProvider    — BGPView public API (fallback)
    └── CustomProvider     — local JSON dataset (offline / air-gapped use)

:class:`BGPService` walks the configured provider list in order and falls
back automatically when a provider fails ("Primary provider failed, trying
fallback provider..."). Providers never raise for *empty* results — an ASN
with no announced prefixes is a valid answer.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from ..models import ASNInfo, PrefixRecord, SourceRecord, utc_now_iso
from ..utils.cache import FileCache
from ..utils.logger import get_logger
from ..utils.networking import (
    HttpClient,
    MalformedResponseError,
    NetworkError,
    ProviderError,
    RateLimiter,
)
from ..validators import InvalidCIDRError, format_asn, parse_cidr

__all__ = [
    "BGPProvider",
    "BGPService",
    "BGPViewProvider",
    "CustomProvider",
    "RIPEStatProvider",
    "build_bgp_service",
]

LOGGER = get_logger()

#: Callback invoked when a provider fails and a fallback is attempted.
FallbackNotifier = Callable[[str, str], None]  # (failed_provider, reason)

# Holder strings look like "GOOGLE, US" or "CLOUDFLARENET, US".
_HOLDER_COUNTRY_RE = re.compile(r"^(.*),\s*([A-Z]{2})$")


class BGPProvider(ABC):
    """Abstract base class for sources of BGP/ASN data."""

    name: str = "bgp"

    def __init__(self, client: HttpClient) -> None:
        self.client = client

    @abstractmethod
    def fetch_asn_info(self, asn: int) -> ASNInfo:
        """Return high-level ASN metadata for *asn*."""

    @abstractmethod
    def fetch_prefixes(self, asn: int) -> list[PrefixRecord]:
        """Return all prefixes announced by *asn* (may be empty)."""

    def source(self, detail: str = "") -> SourceRecord:
        return SourceRecord(provider=self.name, type="BGP", retrieved_at=utc_now_iso(), detail=detail)


class RIPEStatProvider(BGPProvider):
    """RIPEstat data API — the primary, highly reliable source."""

    name = "RIPEstat"

    def __init__(self, client: HttpClient, base_url: str = "https://stat.ripe.net/data") -> None:
        super().__init__(client)
        self.base_url = base_url.rstrip("/")

    # -- ASN metadata ----------------------------------------------------
    def fetch_asn_info(self, asn: int) -> ASNInfo:
        payload = self.client.get_json(
            f"{self.base_url}/as-overview/data.json",
            params={"resource": format_asn(asn)},
            cache_namespace="ripestat",
        )
        return self.parse_asn_overview(payload, asn)

    @staticmethod
    def parse_asn_overview(payload: Any, asn: int) -> ASNInfo:
        """Parse a RIPEstat ``as-overview`` payload into an :class:`ASNInfo`."""
        data = _extract_data(payload, "RIPEstat as-overview")
        holder = str(data.get("holder") or "").strip()
        organization: str | None = holder or None
        country: str | None = None
        match = _HOLDER_COUNTRY_RE.match(holder)
        if match:
            organization = match.group(1).strip(" ,-") or None
            country = match.group(2)
        return ASNInfo(
            asn=asn,
            asn_str=format_asn(asn),
            organization=organization,
            as_name=organization,
            country=country,
            source="RIPEstat",
        )

    # -- prefixes ----------------------------------------------------------
    def fetch_prefixes(self, asn: int) -> list[PrefixRecord]:
        payload = self.client.get_json(
            f"{self.base_url}/announced-prefixes/data.json",
            params={"resource": format_asn(asn)},
            cache_namespace="ripestat",
        )
        return self.parse_announced_prefixes(payload)

    @staticmethod
    def parse_announced_prefixes(payload: Any) -> list[PrefixRecord]:
        """Parse a RIPEstat ``announced-prefixes`` payload into prefix records."""
        data = _extract_data(payload, "RIPEstat announced-prefixes")
        raw_prefixes = data.get("prefixes") or []
        if not isinstance(raw_prefixes, list):
            raise MalformedResponseError("RIPEstat announced-prefixes: 'prefixes' is not a list")
        records: list[PrefixRecord] = []
        skipped = 0
        for item in raw_prefixes:
            if not isinstance(item, dict):
                skipped += 1
                continue
            raw = item.get("prefix")
            try:
                network = parse_cidr(str(raw))
            except InvalidCIDRError:
                skipped += 1
                continue
            records.append(
                PrefixRecord(
                    prefix=str(network),
                    version=network.version,
                    confidence="DIRECT",
                    source="RIPEstat",
                )
            )
        if skipped:
            LOGGER.warning("RIPEstat: skipped %d malformed prefix entries", skipped)
        return records


class BGPViewProvider(BGPProvider):
    """BGPView public API — used as an automatic fallback for RIPEstat."""

    name = "BGPView"

    def __init__(self, client: HttpClient, base_url: str = "https://api.bgpview.io") -> None:
        super().__init__(client)
        self.base_url = base_url.rstrip("/")

    # -- ASN metadata ----------------------------------------------------
    def fetch_asn_info(self, asn: int) -> ASNInfo:
        payload = self.client.get_json(
            f"{self.base_url}/asn/{asn}",
            cache_namespace="bgpview",
        )
        return self.parse_asn_lookup(payload, asn)

    @staticmethod
    def parse_asn_lookup(payload: Any, asn: int) -> ASNInfo:
        """Parse a BGPView ``/asn/{asn}`` payload into an :class:`ASNInfo`."""
        data = _extract_data(payload, "BGPView ASN lookup")
        if not isinstance(data, dict):
            raise MalformedResponseError("BGPView ASN lookup: 'data' is not an object")
        return ASNInfo(
            asn=asn,
            asn_str=format_asn(asn),
            organization=str(data.get("description_short") or data.get("name") or "").strip() or None,
            as_name=str(data.get("name") or "").strip() or None,
            country=str(data.get("country_code") or "").strip() or None,
            registry=str(data.get("rir") or "").strip().upper() or None,
            website=str(data.get("website") or "").strip() or None,
            source="BGPView",
        )

    # -- prefixes ----------------------------------------------------------
    def fetch_prefixes(self, asn: int) -> list[PrefixRecord]:
        payload = self.client.get_json(
            f"{self.base_url}/asn/{asn}/prefixes",
            cache_namespace="bgpview",
        )
        return self.parse_prefixes(payload)

    @staticmethod
    def parse_prefixes(payload: Any) -> list[PrefixRecord]:
        """Parse a BGPView ``/asn/{asn}/prefixes`` payload."""
        data = _extract_data(payload, "BGPView prefixes")
        records: list[PrefixRecord] = []
        skipped = 0
        for key in ("ipv4_prefixes", "ipv6_prefixes"):
            raw_list = data.get(key) or []
            if not isinstance(raw_list, list):
                raise MalformedResponseError(f"BGPView prefixes: '{key}' is not a list")
            for item in raw_list:
                if not isinstance(item, dict):
                    skipped += 1
                    continue
                raw = item.get("prefix")
                try:
                    network = parse_cidr(str(raw))
                except InvalidCIDRError:
                    skipped += 1
                    continue
                records.append(
                    PrefixRecord(
                        prefix=str(network),
                        version=network.version,
                        confidence="DIRECT",
                        source="BGPView",
                    )
                )
        if skipped:
            LOGGER.warning("BGPView: skipped %d malformed prefix entries", skipped)
        return records


class CustomProvider(BGPProvider):
    """Local JSON dataset provider — offline, air-gapped or demo use.

    Configure the dataset path via ``providers.custom_bgp_path`` in the
    config file or the ``AAM_CUSTOM_BGP_PATH`` environment variable. The
    expected file format is::

        {
          "AS15169": {
            "organization": "Google LLC",
            "as_name": "GOOGLE",
            "country": "US",
            "registry": "ARIN",
            "ipv4_prefixes": ["8.8.8.0/24"],
            "ipv6_prefixes": ["2001:4860::/32"]
          }
        }

    This provider is intentionally last in the default fallback chain: it is
    only consulted when the live providers are unavailable.
    """

    name = "Custom"

    def __init__(self, client: HttpClient, path: str | Path | None = None) -> None:
        super().__init__(client)
        self.path = Path(path) if path else None

    def _load_dataset(self) -> dict[str, Any]:
        if not self.path or not self.path.is_file():
            raise ProviderError(
                f"Custom BGP dataset not configured or missing "
                f"(set providers.custom_bgp_path or AAM_CUSTOM_BGP_PATH): {self.path}"
            )
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProviderError(f"Custom BGP dataset unreadable: {exc}") from exc
        if not isinstance(data, dict):
            raise ProviderError("Custom BGP dataset root must be an object")
        return data

    def _entry(self, asn: int) -> dict[str, Any]:
        dataset = self._load_dataset()
        entry = dataset.get(format_asn(asn)) or dataset.get(str(asn))
        if entry is None:
            raise ProviderError(f"AS{asn} not present in custom BGP dataset")
        if not isinstance(entry, dict):
            raise ProviderError(f"Custom BGP dataset entry for AS{asn} is malformed")
        return entry

    def fetch_asn_info(self, asn: int) -> ASNInfo:
        entry = self._entry(asn)
        return ASNInfo(
            asn=asn,
            asn_str=format_asn(asn),
            organization=entry.get("organization"),
            as_name=entry.get("as_name"),
            country=entry.get("country"),
            registry=entry.get("registry"),
            website=entry.get("website"),
            description=entry.get("description"),
            source=f"Custom dataset ({self.path.name})" if self.path else "Custom dataset",
        )

    def fetch_prefixes(self, asn: int) -> list[PrefixRecord]:
        entry = self._entry(asn)
        records: list[PrefixRecord] = []
        for key in ("ipv4_prefixes", "ipv6_prefixes"):
            for raw in entry.get(key) or []:
                network = parse_cidr(str(raw))
                records.append(
                    PrefixRecord(
                        prefix=str(network),
                        version=network.version,
                        confidence="DIRECT",
                        source=f"Custom dataset ({self.path.name})" if self.path else "Custom dataset",
                    )
                )
        return records


def _extract_data(payload: Any, context: str) -> dict[str, Any]:
    """Validate the common ``{"data": {...}}`` envelope used by RIPEstat/BGPView."""
    if not isinstance(payload, dict):
        raise MalformedResponseError(f"{context}: payload is not an object")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise MalformedResponseError(f"{context}: missing 'data' object")
    return data


class BGPService:
    """Coordinates BGP providers with automatic fallback.

    Each lookup walks the configured providers in order. The first provider
    that answers wins; failures are recorded (and optionally reported through
    a callback) before the next provider is tried.
    """

    def __init__(
        self,
        providers: Sequence[BGPProvider],
        on_provider_error: FallbackNotifier | None = None,
    ) -> None:
        if not providers:
            raise ValueError("BGPService requires at least one provider")
        self.providers: list[BGPProvider] = list(providers)
        self.on_provider_error = on_provider_error

    # ------------------------------------------------------------------
    def get_asn_info(self, asn: int) -> tuple[ASNInfo | None, list[SourceRecord], list[str]]:
        """Fetch ASN metadata with fallback.

        :returns: ``(info, sources, errors)`` — *errors* also includes
            per-provider failures that were recovered from by falling back.
        """
        errors: list[str] = []
        for index, provider in enumerate(self.providers):
            try:
                info = provider.fetch_asn_info(asn)
            except (ProviderError, NetworkError) as exc:
                errors.append(f"BGP provider {provider.name} unavailable: {exc}")
                self._report_failure(provider, index, str(exc))
                continue
            return info, [provider.source("ASN metadata")], errors
        errors.append(f"BGP metadata unavailable from all providers (AS{asn})")
        return None, [], errors

    def get_prefixes(self, asn: int) -> tuple[list[PrefixRecord], list[SourceRecord], list[str]]:
        """Fetch announced prefixes with fallback.

        :returns: ``(records, sources, errors)`` — *errors* also includes
            per-provider failures that were recovered from by falling back.
        """
        errors: list[str] = []
        for index, provider in enumerate(self.providers):
            try:
                records = provider.fetch_prefixes(asn)
            except (ProviderError, NetworkError) as exc:
                errors.append(f"BGP provider {provider.name} unavailable: {exc}")
                self._report_failure(provider, index, str(exc))
                continue
            return records, [provider.source(f"{len(records)} announced prefixes")], errors
        errors.append(f"Announced prefixes unavailable from all providers (AS{asn})")
        return [], [], errors

    # ------------------------------------------------------------------
    def _report_failure(self, provider: BGPProvider, index: int, reason: str) -> None:
        LOGGER.warning("BGP provider %s failed: %s", provider.name, reason)
        if self.on_provider_error:
            next_name = self.providers[index + 1].name if index + 1 < len(self.providers) else None
            self.on_provider_error(provider.name, reason if next_name is None else f"{reason}; trying {next_name}...")


#: Provider registry used by :func:`build_bgp_service`.
_PROVIDER_REGISTRY: dict[str, type[BGPProvider]] = {
    "ripestat": RIPEStatProvider,
    "bgpview": BGPViewProvider,
    "custom": CustomProvider,
}


def build_bgp_service(
    config: Any,
    cache: FileCache | None,
    on_provider_error: FallbackNotifier | None = None,
) -> BGPService:
    """Construct a :class:`BGPService` from the application configuration."""
    providers: list[BGPProvider] = []
    for name in config.providers.bgp_providers:
        cls = _PROVIDER_REGISTRY.get(str(name).strip().lower())
        if cls is None:
            config.warnings.append(f"Unknown BGP provider '{name}' (skipped)")
            continue
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
        if cls is CustomProvider:
            providers.append(CustomProvider(client, config.providers.custom_bgp_path or None))
        elif cls is RIPEStatProvider:
            providers.append(RIPEStatProvider(client, config.providers.ripestat_url))
        elif cls is BGPViewProvider:
            providers.append(BGPViewProvider(client, config.providers.bgpview_url))
    if not providers:
        # Guarantee at least one provider so the service is always usable.
        client = HttpClient(
            user_agent=config.user_agent,
            rate_limiter=RateLimiter(config.http.min_request_interval),
            cache=cache,
        )
        providers.append(RIPEStatProvider(client, config.providers.ripestat_url))
    return BGPService(providers, on_provider_error=on_provider_error)
