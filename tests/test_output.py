"""Tests for the JSON / CSV / TXT exporters."""
from __future__ import annotations

import csv
import io
import json

from asn_mapper.models import (
    ASNInfo,
    ASNResult,
    BulkResult,
    CTCertificate,
    DomainRecord,
    PrefixRecord,
    PrefixStats,
    RDAPInfo,
    ReverseDNSRecord,
)
from asn_mapper.output.csv import render_csv
from asn_mapper.output.json import render_json
from asn_mapper.output.txt import render_txt


def make_result(asn: str = "AS15169") -> ASNResult:
    return ASNResult(
        asn=asn,
        asn_info=ASNInfo(
            asn=15169,
            asn_str=asn,
            organization="Google LLC",
            as_name="GOOGLE",
            country="US",
            registry="ARIN",
            source="unit-test",
        ),
        rdap=RDAPInfo(
            asn=asn, handle=asn, name="GOOGLE", organization="Google LLC",
            country="US", registry="ARIN", source="test",
        ),
        ipv4_prefixes=[
            PrefixRecord(prefix="8.8.8.0/24", version=4, source="RIPEstat"),
            PrefixRecord(prefix="34.64.0.0/10", version=4, source="RIPEstat"),
        ],
        ipv6_prefixes=[PrefixRecord(prefix="2001:4860::/32", version=6, source="RIPEstat")],
        stats=PrefixStats(
            ipv4_count=2, ipv6_count=1, total_count=3,
            ipv4_addresses=256 + 4_194_304, ipv6_addresses=2**96,
        ),
        reverse_dns=[ReverseDNSRecord(ip="8.8.8.1", hostname="dns.google", prefix="8.8.8.0/24")],
        domains=[
            DomainRecord(domain="dns.google", confidence="OBSERVED", source="reverse DNS (PTR)",
                         evidence="PTR observed"),
        ],
        ct_names=["example.com", "api.example.com"],
        certificates=[CTCertificate(common_name="example.com", dns_names=["example.com"])],
        sources=[],
        errors=[],
    )


class TestJsonExport:
    def test_single_result_schema(self):
        bulk = BulkResult(results=[make_result()], failed=[])
        data = json.loads(render_json(bulk, single=True))
        # the documented schema keys
        for key in ("asn", "organization", "country", "registry", "ipv4_prefixes",
                    "ipv6_prefixes", "prefix_count", "domains", "reverse_dns",
                    "sources", "timestamp"):
            assert key in data, f"missing key: {key}"
        assert data["asn"] == "AS15169"
        assert data["organization"] == "Google LLC"
        assert data["prefix_count"] == {"ipv4": 2, "ipv6": 1, "total": 3}
        assert data["ipv4_prefixes"] == ["8.8.8.0/24", "34.64.0.0/10"]
        assert data["domains"] == ["dns.google"]
        assert data["reverse_dns"][0]["hostname"] == "dns.google"

    def test_bulk_envelope(self):
        results = [make_result("AS15169"), make_result("AS13335")]
        bulk = BulkResult(results=results, failed=[])
        data = json.loads(render_json(bulk, single=True))
        # multiple ASNs → envelope, not the bare object
        assert data["tool"] == "asn-asset-mapper"
        assert data["processed"] == 2
        assert data["successful"] == 2
        assert data["failed"] == 0
        assert len(data["results"]) == 2

    def test_failures_included(self):
        from asn_mapper.models import FailedASN

        bulk = BulkResult(results=[], failed=[FailedASN("AS1", "all providers failed")])
        data = json.loads(render_json(bulk, single=True))
        assert data["failed"] == 1
        assert data["failed_asns"][0]["asn"] == "AS1"

    def test_confidence_labels_present(self):
        data = json.loads(render_json(BulkResult(results=[make_result()]), single=True))
        assert data["domain_records"][0]["confidence"] == "OBSERVED"
        assert data["prefix_details"][0]["confidence"] == "DIRECT"

    def test_stats_serialized(self):
        data = json.loads(render_json(BulkResult(results=[make_result()]), single=True))
        stats = data["prefix_stats"]
        assert stats["ipv4_addresses"] == 256 + 4_194_304
        assert stats["ipv6_addresses_human"]


class TestCsvExport:
    def test_rows_and_header(self):
        bulk = BulkResult(results=[make_result()], failed=[])
        reader = csv.DictReader(io.StringIO(render_csv(bulk)))
        rows = list(reader)
        types = {row["record_type"] for row in rows}
        assert {"asn_info", "prefix", "domain", "reverse_dns", "certificate"} <= types
        prefix_rows = [row for row in rows if row["record_type"] == "prefix"]
        assert len(prefix_rows) == 3
        for row in prefix_rows:
            assert row["asn"] == "AS15169"
            assert row["confidence"] == "DIRECT"
        # IPv6 rows carry version 6 and (huge) address count as text
        v6 = next(row for row in prefix_rows if row["value"] == "2001:4860::/32")
        assert v6["ip_version"] == "6"
        assert v6["address_count"] == str(2**96)

    def test_failure_rows(self):
        from asn_mapper.models import FailedASN

        bulk = BulkResult(results=[], failed=[FailedASN("AS99", "boom")])
        rows = list(csv.DictReader(io.StringIO(render_csv(bulk))))
        assert rows[0]["record_type"] == "error"
        assert rows[0]["asn"] == "AS99"


class TestTxtExport:
    def test_contains_all_sections_and_every_prefix(self):
        result = make_result()
        result.ipv4_prefixes = [PrefixRecord(prefix=f"10.{i}.0.0/16", version=4) for i in range(80)]
        text = render_txt(BulkResult(results=[result]))
        for section in (
            "ASN ASSET MAPPER REPORT — AS15169",
            "RDAP Information",
            "IPv4 Prefixes",
            "IPv6 Prefixes",
            "Prefix Statistics",
            "Reverse DNS (sampled)",
            "Domains / Hostnames (Observed / Correlated)",
            "Certificate Transparency",
        ):
            assert section in text
        # the text export lists *every* prefix (no console truncation)
        assert "10.79.0.0/16" in text
        assert "8.8.8.1" in text and "dns.google" in text

    def test_bulk_summary_block(self):
        from asn_mapper.models import FailedASN

        results = [make_result("AS15169"), make_result("AS13335")]
        bulk = BulkResult(results=results, failed=[FailedASN("AS1", "nope")])
        text = render_txt(bulk)
        assert "Processed : 3" in text
        assert "Successful: 2" in text
        assert "Failed    : 1" in text
        assert "AS1: FAILED — nope" in text

    def test_expansion_rendered(self):
        from asn_mapper.collectors.prefixes import expand_prefix

        result = make_result()
        result.expansions = [expand_prefix("8.8.8.0/24", max_hosts=10_000)]
        text = render_txt(BulkResult(results=[result]))
        assert "Network    : 8.8.8.0" in text
        assert "Broadcast  : 8.8.8.255" in text
        assert "Hosts      : 254" in text

    def test_write_functions(self, tmp_path):
        from asn_mapper.output.csv import write_csv
        from asn_mapper.output.json import write_json
        from asn_mapper.output.txt import write_txt

        bulk = BulkResult(results=[make_result()])
        write_json(tmp_path / "out.json", bulk)
        write_csv(tmp_path / "out.csv", bulk)
        write_txt(tmp_path / "out.txt", bulk)
        assert json.loads((tmp_path / "out.json").read_text())["asn"] == "AS15169"
        assert (tmp_path / "out.csv").read_text().startswith("asn,record_type,value")
        assert "ASN ASSET MAPPER REPORT" in (tmp_path / "out.txt").read_text()
