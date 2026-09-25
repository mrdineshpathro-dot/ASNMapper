"""Tests for ASN validation, CIDR parsing and domain normalization."""
from __future__ import annotations

import pytest

from asn_mapper.validators import (
    InvalidASNError,
    InvalidCIDRError,
    canonical_prefix,
    dedupe_strings,
    format_asn,
    is_private_asn,
    is_valid_asn,
    normalize_asn,
    normalize_domain,
    parse_asn_arguments,
    parse_cidr,
    registrable_domain,
)

# ---------------------------------------------------------------------------
# ASN validation & normalization
# ---------------------------------------------------------------------------


class TestAsnValidation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("AS15169", 15169),
            ("as15169", 15169),
            ("15169", 15169),
            ("  AS15169  ", 15169),
            ("AS16509", 16509),
            (13335, 13335),
            ("as013335", 13335),  # leading zero tolerated
            ("AS4294967294", 4_294_967_294),
        ],
    )
    def test_normalize_asn_valid(self, raw, expected):
        assert normalize_asn(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "AS",
            "google",
            "AS-15169",
            "AS15.169",
            "banana",
            "AS99999999999",  # > 32-bit
            "0",
            "AS0",
            "AS65535",
            "AS4294967295",
            "-5",
            True,
            None,
        ],
    )
    def test_normalize_asn_invalid(self, raw):
        with pytest.raises(InvalidASNError):
            normalize_asn(raw)

    def test_is_valid_asn(self):
        assert is_valid_asn("AS15169") is True
        assert is_valid_asn("not-an-asn") is False
        assert is_valid_asn("AS65535") is False  # reserved

    def test_format_asn(self):
        assert format_asn(15169) == "AS15169"
        assert format_asn(0) == "AS0"
        assert format_asn(4_294_967_295) == "AS4294967295"

    def test_private_asn_detection(self):
        assert is_private_asn(64512) is True
        assert is_private_asn(65534) is True
        assert is_private_asn(4200000000) is True
        assert is_private_asn(15169) is False
        assert is_private_asn(64511) is False

    def test_parse_asn_arguments_mixed(self):
        valid, errors = parse_asn_arguments(["AS15169,AS16509", "13335", "bogus", "AS0"])
        assert valid == [15169, 16509, 13335]
        assert len(errors) == 2

    def test_parse_asn_arguments_deduplicates(self):
        valid, errors = parse_asn_arguments(["AS15169", "as15169", "15169"])
        assert valid == [15169]
        assert errors == []

    def test_parse_asn_arguments_semicolons_and_empty(self):
        valid, errors = parse_asn_arguments(["AS15169;AS13335", "", ","])
        assert valid == [15169, 13335]
        assert errors == []


# ---------------------------------------------------------------------------
# CIDR parsing
# ---------------------------------------------------------------------------


class TestCidrParsing:
    def test_parse_ipv4(self):
        network = parse_cidr("8.8.8.0/24")
        assert network.version == 4
        assert str(network) == "8.8.8.0/24"
        assert network.num_addresses == 256

    def test_parse_ipv6(self):
        network = parse_cidr("2001:4860::/32")
        assert network.version == 6
        assert network.num_addresses == 2**96

    def test_host_bits_are_zeroed(self):
        assert canonical_prefix("8.8.8.1/24") == "8.8.8.0/24"
        assert canonical_prefix("2607:f8b0:4001:1::5/32") == "2607:f8b0::/32"

    @pytest.mark.parametrize(
        "bad",
        ["", "banana", "999.1.1.1/24", "8.8.8.0/33", "2001:4860::/129", None, "10.0.0.0/"],
    )
    def test_invalid_cidr(self, bad):
        with pytest.raises(InvalidCIDRError):
            parse_cidr(bad)

    def test_canonical_prefix(self):
        assert canonical_prefix("34.64.0.0/10") == "34.64.0.0/10"
        assert canonical_prefix(" 8.8.8.0/24 ") == "8.8.8.0/24"


# ---------------------------------------------------------------------------
# Domain normalization
# ---------------------------------------------------------------------------


class TestDomainNormalization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Example.COM", "example.com"),
            ("Mail.Example.COM.", "mail.example.com"),
            ("  api.example.com  ", "api.example.com"),
            ("xn--nxasmq6b.example", "xn--nxasmq6b.example"),
        ],
    )
    def test_normalize_domain(self, raw, expected):
        assert normalize_domain(raw) == expected

    @pytest.mark.parametrize("bad", ["", ".", "-bad.com", "a..b", "a" * 300 + ".com", None, "bad host"])
    def test_normalize_domain_invalid(self, bad):
        assert normalize_domain(bad) is None

    def test_registrable_domain(self):
        assert registrable_domain("mail.example.com") == "example.com"
        assert registrable_domain("a.b.c.example.co.uk") == "example.co.uk"
        assert registrable_domain("example.co.uk") == "example.co.uk"  # registrable itself
        assert registrable_domain("co.uk") is None  # the public suffix alone
        assert registrable_domain("localhost") is None
        assert registrable_domain("8.8.8.8") is None

    def test_dedupe_strings(self):
        values = ["Example.COM", "example.com", "EXAMPLE.com", "other.com"]
        assert dedupe_strings(values) == ["Example.COM", "other.com"]
        assert dedupe_strings(["A", "a"], case_sensitive=True) == ["A", "a"]
