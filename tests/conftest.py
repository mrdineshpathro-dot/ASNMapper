"""Shared fixtures and fakes for the ASN Asset Mapper test suite.

No test in this suite touches the network: every provider is replaced with
a fake implementation backed by canned payloads.
"""
from __future__ import annotations

import pytest

from asn_mapper.config import AppConfig, CacheSettings, DnsSettings, HttpSettings
from asn_mapper.models import (
    ASNInfo,
    CTCertificate,
    PrefixRecord,
    RDAPInfo,
    ReverseDNSRecord,
)
from asn_mapper.providers.bgp import BGPProvider, BGPService
from asn_mapper.providers.ct import CTProvider, CTService
from asn_mapper.providers.rdap import RDAPService, RegistryProvider
from asn_mapper.utils.networking import ProviderError

# ---------------------------------------------------------------------------
# Realistic canned API payloads (shapes taken from the live services)
# ---------------------------------------------------------------------------

RIPE_AS_OVERVIEW = {
    "data": {
        "asn": "15169",
        "holder": "GOOGLE, US",
        "type": "asn",
        "block": {"resource": "autnum", "desc": "Autonomous System Number", "name": "asn"},
    },
    "query_starttime": "2026-09-25T00:00:00",
    "query_endtime": "2026-09-25T00:00:00",
    "messages": [],
    "datacall_name": "as-overview",
    "datacall_status": "supported",
}

RIPE_ANNOUNCED_PREFIXES = {
    "data": {
        "prefixes": [
            {"prefix": "8.8.8.0/24", "timelines": []},
            {"prefix": "8.8.4.0/24"},
            {"prefix": "34.64.0.0/10"},
            {"prefix": "2001:4860::/32"},
            {"prefix": "2607:f8b0::/32"},
            {"prefix": "definitely-not-a-prefix"},
            "not-even-a-dict",
        ],
        "query_starttime": "2026-09-25T00:00:00",
        "query_endtime": "2026-09-25T00:00:00",
    },
    "messages": [],
    "datacall_name": "announced-prefixes",
}

BGPVIEW_ASN = {
    "status": "ok",
    "data": {
        "asn": 15169,
        "name": "GOOGLE",
        "description_short": "Google LLC",
        "description_full": ["Google LLC"],
        "country_code": "US",
        "website": "https://about.google",
        "email_contacts": [],
        "abuse_contacts": [],
        "owner_address": ["1600 Amphitheatre Parkway", "Mountain View", "CA", "94043", "US"],
        "date_allocated": "2000-03-30",
        "rir": "ARIN",
    },
}

BGPVIEW_PREFIXES = {
    "status": "ok",
    "data": {
        "ipv4_prefixes": [
            {
                "prefix": "8.8.8.0/24",
                "ip": "8.8.8.0",
                "cidr": "24",
                "asn": {"asn": 15169, "description": "Google LLC", "name": "GOOGLE", "country_code": "US"},
                "name": "GOOGLE",
                "description": "Google LLC",
                "country": "US",
            }
        ],
        "ipv6_prefixes": [
            {
                "prefix": "2001:4860::/32",
                "ip": "2001:4860::",
                "cidr": "32",
                "asn": {"asn": 15169},
            }
        ],
    },
}

ARIN_RDAP_AUTNUM = {
    "objectClassName": "autnum",
    "handle": "AS15169",
    "startAutnum": 15169,
    "endAutnum": 15169,
    "name": "GOOGLE",
    "type": "DIRECT ALLOCATION",
    "country": "US",
    "remarks": [
        {"title": "Registration Comments", "description": ["Anycast usage."]},
    ],
    "entities": [
        {
            "handle": "GOGL",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Google LLC"],
                    ["org", {}, "text", "Google LLC"],
                    [
                        "adr",
                        {"label": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"},
                        "text",
                        ["", "", "1600 Amphitheatre Parkway", "Mountain View", "CA", "94043", "United States"],
                    ],
                ],
            ],
        }
    ],
    "port43": "whois.arin.net",
}

CRTSH_ENTRIES = [
    {
        "issuer_ca_id": 105484,
        "issuer_name": "C=US, O=Let's Encrypt, CN=E6",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com\nEXAMPLE.com",
        "id": 111,
        "entry_timestamp": "2026-01-02T00:00:00",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "serial_number": "00aabb",
    },
    {
        "issuer_ca_id": 105484,
        "issuer_name": "C=US, O=Let's Encrypt, CN=E6",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "id": 111,
        "entry_timestamp": "2026-01-02T00:00:00",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "serial_number": "00aabb",
    },
    {
        "issuer_ca_id": 105484,
        "issuer_name": "C=US, O=Let's Encrypt, CN=E6",
        "common_name": "api.example.com",
        "name_value": "api.example.com",
        "id": 222,
        "entry_timestamp": "2026-02-02T00:00:00",
        "not_before": "2026-02-01T00:00:00",
        "not_after": "2026-05-01T00:00:00",
        "serial_number": "00ccdd",
    },
]


# ---------------------------------------------------------------------------
# Fake providers / services
# ---------------------------------------------------------------------------


class FakeBGPProvider(BGPProvider):
    """In-memory BGP provider backed by a per-ASN dataset."""

    name = "FakeBGP"

    def __init__(self, data: dict[int, tuple[ASNInfo | None, list[PrefixRecord]]] | None = None,
                 error: Exception | None = None) -> None:
        self.data = data or {}
        self.error = error

    def fetch_asn_info(self, asn: int) -> ASNInfo:
        if self.error:
            raise self.error
        if asn not in self.data:
            raise ProviderError(f"AS{asn} not found")
        info, _ = self.data[asn]
        if info is None:
            raise ProviderError(f"AS{asn} has no metadata")
        return info

    def fetch_prefixes(self, asn: int) -> list[PrefixRecord]:
        if self.error:
            raise self.error
        if asn not in self.data:
            raise ProviderError(f"AS{asn} not found")
        return list(self.data[asn][1])


class FakeRegistryProvider(RegistryProvider):
    """In-memory RDAP provider."""

    name = "fake-rdap"

    def __init__(self, data: dict[int, RDAPInfo] | None = None, error: Exception | None = None) -> None:
        self.data = data or {}
        self.error = error

    def lookup_asn(self, asn: int) -> RDAPInfo:
        if self.error:
            raise self.error
        if asn not in self.data:
            raise ProviderError(f"AS{asn} not found")
        return self.data[asn]


class FakeDNSService:
    """Duck-typed replacement for ReverseDNSService (no network, no dnspython)."""

    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self.mapping = mapping or {}
        self.calls: list[str] = []

    def lookup(self, ip: str) -> ReverseDNSRecord:
        hostname = self.mapping.get(ip)
        return ReverseDNSRecord(ip=ip, hostname=hostname, error=None if hostname else "NXDOMAIN")

    def lookup_many(self, ips, progress=None) -> list[ReverseDNSRecord]:
        self.calls.extend(ips)
        records = [self.lookup(ip) for ip in ips]
        if progress is not None:
            progress(len(records), len(records))
        return records


class FakeCTProvider(CTProvider):
    """In-memory CT provider returning canned certificates per domain."""

    name = "fake-ct"

    def __init__(self, certs_by_domain: dict[str, list[CTCertificate]] | None = None) -> None:
        self.certs_by_domain = certs_by_domain or {}

    def search_domain(self, domain: str) -> list[CTCertificate]:
        return list(self.certs_by_domain.get(domain, []))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def config(tmp_path):
    """An AppConfig that never touches the network or the real cache dir."""
    return AppConfig(
        threads=4,
        http=HttpSettings(timeout=2.0, retries=1, backoff_base=0.0, max_delay=0.0, min_request_interval=0.0),
        dns=DnsSettings(timeout=1.0, retries=0, concurrency=4, sample_per_prefix=2, max_lookups=64),
        cache=CacheSettings(enabled=False, directory=tmp_path / "cache"),
    )


@pytest.fixture()
def google_asn_data():
    """Canonical fake dataset for AS15169."""
    return {
        15169: (
            ASNInfo(
                asn=15169,
                asn_str="AS15169",
                organization="Google LLC",
                as_name="GOOGLE",
                country="US",
                registry="ARIN",
                website="https://www.google.com",
                source="FakeBGP",
            ),
            [
                PrefixRecord(prefix="8.8.8.0/24", version=4, source="FakeBGP"),
                PrefixRecord(prefix="34.64.0.0/10", version=4, source="FakeBGP"),
                PrefixRecord(prefix="2001:4860::/32", version=6, source="FakeBGP"),
                PrefixRecord(prefix="2607:f8b0::/32", version=6, source="FakeBGP"),
            ],
        )
    }


@pytest.fixture()
def fake_bgp(google_asn_data):
    return BGPService([FakeBGPProvider(google_asn_data)])


@pytest.fixture()
def fake_rdap():
    info = RDAPInfo(
        asn="AS15169",
        handle="AS15169",
        name="GOOGLE",
        organization="Google LLC",
        country="US",
        registry="ARIN",
        asn_type="DIRECT ALLOCATION",
        start_autnum=15169,
        end_autnum=15169,
        remarks=["Anycast usage."],
        source="fake-rdap",
    )
    return RDAPService([FakeRegistryProvider({15169: info})])


@pytest.fixture()
def fake_dns():
    return FakeDNSService({"8.8.8.1": "dns.google", "8.8.8.2": "dns.google"})


@pytest.fixture()
def fake_ct():
    certs = [
        CTCertificate(
            common_name="example.com",
            dns_names=["example.com", "www.example.com", "api.example.com"],
            issuer="Fake CA",
            not_before="2026-01-01T00:00:00",
            not_after="2026-04-01T00:00:00",
        )
    ]
    return CTService(FakeCTProvider({"example.com": certs}))
