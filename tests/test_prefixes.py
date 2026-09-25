"""Tests for prefix statistics, range expansion and safe IP sampling."""
from __future__ import annotations

import ipaddress

from asn_mapper.collectors.prefixes import (
    PrefixCollector,
    expand_prefix,
    normalize_prefix_records,
    sample_ips,
)
from asn_mapper.models import PrefixRecord


def record(prefix: str, source: str = "test") -> PrefixRecord:
    network = ipaddress.ip_network(prefix)
    return PrefixRecord(prefix=str(network), version=network.version, source=source)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class TestPrefixStats:
    def test_counts_and_totals(self):
        records = [
            record("8.8.8.0/24"),        # 256
            record("8.8.4.0/24"),        # 256
            record("34.64.0.0/10"),      # 4,194,304
            record("2001:4860::/32"),    # 2^96
            record("2607:f8b0::/32"),    # 2^96
        ]
        stats = PrefixCollector.compute_stats(records)
        assert stats.ipv4_count == 3
        assert stats.ipv6_count == 2
        assert stats.total_count == 5
        assert stats.ipv4_addresses == 256 + 256 + 4_194_304
        assert stats.ipv6_addresses == 2 * 2**96

    def test_min_max_prefixlen(self):
        stats = PrefixCollector.compute_stats(
            [record("8.8.8.0/24"), record("34.64.0.0/10"), record("8.8.4.0/22")]
        )
        assert stats.ipv4_min_prefixlen == 10
        assert stats.ipv4_max_prefixlen == 24
        assert stats.ipv6_min_prefixlen is None

    def test_distribution(self):
        stats = PrefixCollector.compute_stats(
            [record("8.8.8.0/24"), record("8.8.4.0/24"), record("34.64.0.0/10")]
        )
        assert stats.ipv4_distribution == {24: 2, 10: 1}
        assert stats.ipv6_distribution == {}

    def test_empty(self):
        stats = PrefixCollector.compute_stats([])
        assert stats.total_count == 0
        assert stats.ipv4_addresses == 0


# ---------------------------------------------------------------------------
# Normalization / deduplication
# ---------------------------------------------------------------------------


class TestNormalizePrefixRecords:
    def test_deduplicates_and_canonicalizes(self):
        records = [
            record("8.8.8.0/24"),
            PrefixRecord(prefix="8.8.8.1/24", version=4),  # host bits set
            record("8.8.8.0/24"),
        ]
        result = normalize_prefix_records(records)
        assert len(result) == 1
        assert result[0].prefix == "8.8.8.0/24"

    def test_sorts_v4_then_v6_numerically(self):
        result = normalize_prefix_records(
            [record("2001:4860::/32"), record("34.64.0.0/10"), record("8.8.8.0/24")]
        )
        assert [r.prefix for r in result] == ["8.8.8.0/24", "34.64.0.0/10", "2001:4860::/32"]

    def test_invalid_prefixes_dropped(self):
        result = normalize_prefix_records(
            [record("8.8.8.0/24"), PrefixRecord(prefix="999.0.0.0/8", version=4)]
        )
        assert [r.prefix for r in result] == ["8.8.8.0/24"]


# ---------------------------------------------------------------------------
# Range expansion
# ---------------------------------------------------------------------------


class TestExpandPrefix:
    def test_small_ipv4_enumerates(self):
        expansion = expand_prefix("8.8.8.0/24", max_hosts=1000)
        assert expansion.network == "8.8.8.0"
        assert expansion.last_address == "8.8.8.255"
        assert expansion.first_host == "8.8.8.1"
        assert expansion.last_host == "8.8.8.254"
        assert expansion.usable_hosts == 254
        assert expansion.total_addresses == 256
        assert expansion.addresses is not None
        assert len(expansion.addresses) == 256
        assert expansion.skipped_reason is None

    def test_large_ipv4_skips_enumeration(self):
        expansion = expand_prefix("34.64.0.0/10", max_hosts=10_000)
        assert expansion.last_address == "34.127.255.255"
        assert expansion.usable_hosts == 4_194_302
        assert expansion.addresses is None
        assert expansion.skipped_reason is not None
        assert "4,194,302" in expansion.skipped_reason

    def test_boundary_max_hosts_exact(self):
        # exactly at the limit → enumerate
        expansion = expand_prefix("192.168.0.0/24", max_hosts=254)
        assert expansion.addresses is not None
        # one below the limit → skip
        expansion = expand_prefix("192.168.0.0/24", max_hosts=253)
        assert expansion.addresses is None

    def test_ipv6_never_enumerates_by_default(self):
        expansion = expand_prefix("2001:4860::/32", max_hosts=10_000)
        assert expansion.total_addresses == 2**96
        assert expansion.usable_hosts == 2**96
        assert expansion.addresses is None
        assert expansion.skipped_reason is not None

    def test_tiny_ipv6_enumerates(self):
        expansion = expand_prefix("2001:db8::/126", max_hosts=100)
        assert expansion.total_addresses == 4
        assert expansion.addresses == ["2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"]

    def test_point_to_point_and_host_routes(self):
        p2p = expand_prefix("10.0.0.0/31", max_hosts=100)
        assert p2p.usable_hosts == 2
        assert p2p.first_host == "10.0.0.0"
        assert p2p.last_host == "10.0.0.1"
        host = expand_prefix("10.0.0.7/32", max_hosts=100)
        assert host.usable_hosts == 1
        assert host.first_host == "10.0.0.7"
        assert host.last_host == "10.0.0.7"


# ---------------------------------------------------------------------------
# Safe IP sampling
# ---------------------------------------------------------------------------


class TestSampleIps:
    def test_samples_host_portion(self):
        assert sample_ips("8.8.8.0/24", 2) == ["8.8.8.1", "8.8.8.2"]

    def test_sample_zero(self):
        assert sample_ips("8.8.8.0/24", 0) == []

    def test_tiny_prefix_returns_all(self):
        assert sample_ips("10.0.0.0/31", 5) == ["10.0.0.0", "10.0.0.1"]
        assert sample_ips("10.0.0.5/32", 5) == ["10.0.0.5"]

    def test_sample_capped_by_prefix_size(self):
        assert sample_ips("10.0.0.0/30", 10) == ["10.0.0.1", "10.0.0.2"]

    def test_ipv6_sampling(self):
        assert sample_ips("2001:db8::/64", 1) == ["2001:db8::1"]


# ---------------------------------------------------------------------------
# Collector integration (with a fake BGP service)
# ---------------------------------------------------------------------------


class TestPrefixCollector:
    def test_collect_normalizes(self, fake_bgp):
        collector = PrefixCollector(fake_bgp)
        records, sources, errors = collector.collect(15169)
        prefixes = [r.prefix for r in records]
        assert "8.8.8.0/24" in prefixes
        assert "34.64.0.0/10" in prefixes
        assert "2001:4860::/32" in prefixes
        assert not errors
        assert sources and sources[0].provider == "FakeBGP"

    def test_collect_unknown_asn(self, fake_bgp):
        collector = PrefixCollector(fake_bgp)
        records, sources, errors = collector.collect(64512)
        assert records == []
        assert errors  # all providers failed → error recorded
