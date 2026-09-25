"""Tests for the API response parsers (RIPEstat, BGPView, RDAP, crt.sh).

All payloads are canned — no test performs network I/O.
"""
from __future__ import annotations

import pytest
from conftest import (
    ARIN_RDAP_AUTNUM,
    BGPVIEW_ASN,
    BGPVIEW_PREFIXES,
    CRTSH_ENTRIES,
    RIPE_ANNOUNCED_PREFIXES,
    RIPE_AS_OVERVIEW,
)

from asn_mapper.models import PrefixRecord
from asn_mapper.providers.bgp import (
    BGPViewProvider,
    CustomProvider,
    RIPEStatProvider,
)
from asn_mapper.providers.ct import CrtShProvider
from asn_mapper.providers.rdap import (
    parse_autnum_payload,
    registry_from_rdap_url,
)
from asn_mapper.utils.networking import MalformedResponseError, ProviderError

# ---------------------------------------------------------------------------
# RIPEstat
# ---------------------------------------------------------------------------


class TestRipestatParsers:
    def test_asn_overview(self):
        info = RIPEStatProvider.parse_asn_overview(RIPE_AS_OVERVIEW, 15169)
        assert info.asn_str == "AS15169"
        assert info.organization == "GOOGLE"
        assert info.country == "US"
        assert info.source == "RIPEstat"

    def test_asn_overview_without_country_suffix(self):
        payload = {"data": {"asn": "13335", "holder": "CLOUDFLARENET"}}
        info = RIPEStatProvider.parse_asn_overview(payload, 13335)
        assert info.organization == "CLOUDFLARENET"
        assert info.country is None

    def test_announced_prefixes_splits_versions(self):
        records = RIPEStatProvider.parse_announced_prefixes(RIPE_ANNOUNCED_PREFIXES)
        v4 = [r for r in records if r.version == 4]
        v6 = [r for r in records if r.version == 6]
        # input order preserved, invalid entries skipped
        assert [r.prefix for r in v4] == ["8.8.8.0/24", "8.8.4.0/24", "34.64.0.0/10"]
        assert [r.prefix for r in v6] == ["2001:4860::/32", "2607:f8b0::/32"]
        assert all(isinstance(r, PrefixRecord) for r in records)
        assert all(r.confidence == "DIRECT" for r in records)

    def test_announced_prefixes_empty(self):
        records = RIPEStatProvider.parse_announced_prefixes({"data": {"prefixes": []}})
        assert records == []

    @pytest.mark.parametrize(
        "payload",
        [
            None,
            [],
            {},
            {"data": None},
            {"data": "nope"},
            {"data": {"prefixes": "not-a-list"}},
        ],
    )
    def test_malformed_payloads(self, payload):
        with pytest.raises(MalformedResponseError):
            RIPEStatProvider.parse_announced_prefixes(payload)


# ---------------------------------------------------------------------------
# BGPView
# ---------------------------------------------------------------------------


class TestBGPViewParsers:
    def test_asn_lookup(self):
        info = BGPViewProvider.parse_asn_lookup(BGPVIEW_ASN, 15169)
        assert info.organization == "Google LLC"
        assert info.as_name == "GOOGLE"
        assert info.country == "US"
        assert info.registry == "ARIN"
        assert info.website == "https://about.google"

    def test_prefixes(self):
        records = BGPViewProvider.parse_prefixes(BGPVIEW_PREFIXES)
        assert [r.prefix for r in records] == ["8.8.8.0/24", "2001:4860::/32"]
        assert records[0].version == 4
        assert records[1].version == 6

    def test_missing_data_raises(self):
        with pytest.raises(MalformedResponseError):
            BGPViewProvider.parse_prefixes({"status": "error"})


# ---------------------------------------------------------------------------
# Custom (offline dataset) provider
# ---------------------------------------------------------------------------


class TestCustomProvider:
    def _make(self, tmp_path, dataset):
        path = tmp_path / "custom.json"
        path.write_text(__import__("json").dumps(dataset), encoding="utf-8")
        return CustomProvider(client=None, path=path)  # type: ignore[arg-type]

    def test_loads_dataset(self, tmp_path):
        provider = self._make(
            tmp_path,
            {
                "AS15169": {
                    "organization": "Google LLC",
                    "as_name": "GOOGLE",
                    "country": "US",
                    "registry": "ARIN",
                    "ipv4_prefixes": ["8.8.8.0/24"],
                    "ipv6_prefixes": ["2001:4860::/32"],
                }
            },
        )
        info = provider.fetch_asn_info(15169)
        assert info.organization == "Google LLC"
        prefixes = provider.fetch_prefixes(15169)
        assert [p.prefix for p in prefixes] == ["8.8.8.0/24", "2001:4860::/32"]

    def test_unknown_asn(self, tmp_path):
        provider = self._make(tmp_path, {"AS15169": {"ipv4_prefixes": []}})
        with pytest.raises(ProviderError):
            provider.fetch_asn_info(13335)

    def test_missing_path(self):
        provider = CustomProvider(client=None, path=None)  # type: ignore[arg-type]
        with pytest.raises(ProviderError):
            provider.fetch_asn_info(15169)


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------


class TestRdapParsing:
    def test_parse_arin_autnum(self):
        info = parse_autnum_payload(ARIN_RDAP_AUTNUM, 15169, registry="ARIN", source="rdap.org")
        assert info.handle == "AS15169"
        assert info.name == "GOOGLE"
        assert info.organization == "Google LLC"
        assert info.country == "US"
        assert info.registry == "ARIN"
        assert info.asn_type == "DIRECT ALLOCATION"
        assert info.start_autnum == 15169
        assert info.end_autnum == 15169
        assert "Anycast usage." in info.remarks

    def test_country_from_registrant_vcard(self):
        payload = {
            "handle": "AS13335",
            "name": "CLOUDFLARENET",
            "startAutnum": 13335,
            "endAutnum": 13335,
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Cloudflare, Inc."],
                            [
                                "adr",
                                {},
                                "text",
                                ["", "", "", "", "", "", "AU"],
                            ],
                        ],
                    ],
                }
            ],
        }
        info = parse_autnum_payload(payload, 13335, registry="APNIC", source="APNIC")
        assert info.country == "AU"
        assert info.organization == "Cloudflare, Inc."

    def test_minimal_payload(self):
        info = parse_autnum_payload({"handle": "AS1", "name": "TEST"}, 1)
        assert info.handle == "AS1"
        assert info.organization is None
        assert info.country is None

    def test_malformed_payload(self):
        with pytest.raises(MalformedResponseError):
            parse_autnum_payload(["not", "an", "object"], 15169)

    def test_registry_from_url(self):
        assert registry_from_rdap_url("https://rdap.arin.net/registry/autnum/15169") == "ARIN"
        assert registry_from_rdap_url("https://rdap.db.ripe.net/autnum/15169") == "RIPE"
        assert registry_from_rdap_url("https://example.org/autnum/1") is None


# ---------------------------------------------------------------------------
# crt.sh
# ---------------------------------------------------------------------------


class TestCrtShParser:
    def test_parse_entries(self):
        certificates = CrtShProvider.parse_entries(CRTSH_ENTRIES)
        # duplicate (same serial/common_name/names/not_before) collapsed
        assert len(certificates) == 2
        first = certificates[0]
        assert first.common_name == "example.com"
        assert first.dns_names == ["example.com", "www.example.com"]  # normalized + sorted
        assert first.issuer == "C=US, O=Let's Encrypt, CN=E6"
        assert first.not_before == "2026-01-01T00:00:00"
        assert first.not_after == "2026-04-01T00:00:00"

    def test_malformed_payload(self):
        with pytest.raises(MalformedResponseError):
            CrtShProvider.parse_entries({"not": "a list"})
