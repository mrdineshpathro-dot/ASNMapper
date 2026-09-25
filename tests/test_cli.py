"""Tests for the CLI: argument parsing, exit codes, exports and filters.

The engine is replaced with one wired to fake providers (no network).
"""
from __future__ import annotations

import json

import pytest
from conftest import (
    FakeBGPProvider,
    FakeCTProvider,
    FakeDNSService,
    FakeRegistryProvider,
)

import asn_mapper.cli as cli_module
from asn_mapper.cli import build_parser, main
from asn_mapper.core import MapperEngine
from asn_mapper.models import CTCertificate, RDAPInfo
from asn_mapper.providers.bgp import BGPService
from asn_mapper.providers.ct import CTService
from asn_mapper.providers.rdap import RDAPService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path, monkeypatch):
    """Keep logs/outputs out of the repository while tests run."""
    monkeypatch.chdir(tmp_path)
    yield tmp_path


@pytest.fixture()
def fake_engine(config, google_asn_data):
    """An engine wired entirely to in-memory fakes."""
    return MapperEngine(
        config=config,
        bgp_service=BGPService([FakeBGPProvider(google_asn_data)]),
        rdap_service=RDAPService(
            [
                FakeRegistryProvider(
                    {
                        15169: RDAPInfo(
                            asn="AS15169",
                            handle="AS15169",
                            name="GOOGLE",
                            organization="Google LLC",
                            country="US",
                            registry="ARIN",
                            source="fake-rdap",
                        )
                    }
                )
            ]
        ),
        dns_service=FakeDNSService({"8.8.8.1": "dns.google", "8.8.8.2": "dns.google"}),
        ct_service=CTService(
            FakeCTProvider(
                {
                    "example.com": [
                        CTCertificate(
                            common_name="example.com",
                            dns_names=["example.com", "api.example.com"],
                            issuer="Fake CA",
                        )
                    ]
                }
            )
        ),
    )


@pytest.fixture(autouse=True)
def patched_engine(monkeypatch, fake_engine):
    """Replace engine construction in the CLI with the fake-wired engine."""
    monkeypatch.setattr(cli_module, "build_engine", lambda config, ui, cache=None: fake_engine)
    return fake_engine


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class TestArgumentParsing:
    def test_version(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "ASN Asset Mapper 1.0.0" in out
        assert "Mr Dinesh Pathro" in out

    def test_format_flags_mutually_exclusive(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--json", "--csv", "AS15169"])
        assert excinfo.value.code == 2

    def test_quiet_verbose_exclusive(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--quiet", "--verbose", "AS15169"])
        assert excinfo.value.code == 2

    def test_unknown_option(self):
        with pytest.raises(SystemExit) as excinfo:
            main(["--frobnicate", "AS15169"])
        assert excinfo.value.code == 2

    def test_help_lists_examples(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "examples:" in out
        assert "AS15169" in out

    def test_parser_accepts_all_documented_options(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "AS15169", "AS16509", "--json", "-o", "out.json", "--domains", "--ct",
                "--ct-domain", "example.com", "--reverse-dns", "--rdap", "--bgp",
                "--expand", "--max-hosts", "500", "--prefixes-only", "--ipv4-only",
                "--threads", "5", "--timeout", "9", "--retries", "1", "--dns-sample", "3",
                "--summary", "--no-color", "--cache-ttl", "60", "--no-cache",
            ]
        )
        assert args.asns == ["AS15169", "AS16509"]
        assert args.format == "json"
        assert args.output == "out.json"
        assert args.ct_domains == ["example.com"]
        assert args.max_hosts == 500
        assert args.dns_sample == 3


# ---------------------------------------------------------------------------
# Target handling & exit codes
# ---------------------------------------------------------------------------


class TestTargetsAndExitCodes:
    def test_invalid_asn_exits_1(self, capsys):
        assert main(["not-an-asn"]) == 1
        err = capsys.readouterr().err
        assert "Invalid ASN" in err

    def test_no_target_exits_1(self, capsys):
        assert main([]) == 1
        err = capsys.readouterr().err
        assert "No valid ASN supplied" in err

    def test_mixed_validity_processes_valid(self, capsys):
        assert main(["AS15169", "nope"]) == 0
        err = capsys.readouterr().err
        assert "Invalid ASN format" in err

    def test_comma_separated(self, capsys):
        # engine fake only knows AS15169; AS13335 yields an empty-ish result
        assert main(["AS15169,AS13335", "--quiet"]) == 0

    def test_input_file(self, capsys, isolated_cwd):
        (isolated_cwd / "asns.txt").write_text(
            "# comment\nAS15169\n\n15169\n", encoding="utf-8"
        )
        assert main(["--input", "asns.txt", "--quiet"]) == 0

    def test_missing_input_file(self, capsys):
        assert main(["--input", "does-not-exist.txt"]) == 1


# ---------------------------------------------------------------------------
# Output modes
# ---------------------------------------------------------------------------


class TestOutputModes:
    def test_human_report(self, capsys):
        assert main(["AS15169", "--no-color"]) == 0
        out = capsys.readouterr().out
        assert "RESULTS — AS15169" in out
        assert "Organization" in out and "Google LLC" in out
        assert "IPv4 Prefixes" in out
        assert "Prefix Statistics" in out
        assert "8.8.8.0/24" in out

    def test_json_stdout_is_clean(self, capsys):
        assert main(["AS15169", "--json"]) == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)  # stdout must be pure JSON
        assert data["asn"] == "AS15169"
        assert data["prefix_count"]["total"] == 4
        # progress goes to stderr, not stdout
        assert "[+]" in captured.err

    def test_json_file_export(self, capsys, isolated_cwd):
        assert main(["AS15169", "--json", "-o", "results.json"]) == 0
        data = json.loads((isolated_cwd / "results.json").read_text())
        assert data["asn"] == "AS15169"
        err = capsys.readouterr().err
        assert "saved to results.json" in err

    def test_csv_file_export(self, capsys, isolated_cwd):
        assert main(["AS15169", "--csv", "-o", "prefixes.csv"]) == 0
        text = (isolated_cwd / "prefixes.csv").read_text()
        assert text.splitlines()[0].startswith("asn,record_type,value")
        assert "8.8.8.0/24" in text

    def test_txt_stdout(self, capsys):
        assert main(["AS15169", "--txt"]) == 0
        out = capsys.readouterr().out
        assert "ASN ASSET MAPPER REPORT — AS15169" in out
        assert "RDAP Information" in out

    def test_prefixes_only_ipv4(self, capsys):
        assert main(["AS15169", "--prefixes-only", "--ipv4-only"]) == 0
        out = capsys.readouterr().out.strip().splitlines()
        assert out == ["8.8.8.0/24", "34.64.0.0/10"]

    def test_prefixes_only_ipv6(self, capsys):
        assert main(["AS15169", "--prefixes-only", "--ipv6-only"]) == 0
        out = capsys.readouterr().out.strip().splitlines()
        assert out == ["2001:4860::/32", "2607:f8b0::/32"]

    def test_ipv4_only_json_recomputes_stats(self, capsys):
        assert main(["AS15169", "--ipv4-only", "--json"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["prefix_count"] == {"ipv4": 2, "ipv6": 0, "total": 2}
        assert data["ipv6_prefixes"] == []
        assert data["prefix_stats"]["ipv4_addresses"] == 256 + 4_194_304

    def test_summary_mode(self, capsys):
        assert main(["AS15169", "--summary", "--no-color"]) == 0
        out = capsys.readouterr().out
        assert "ASN Summary" in out
        assert "IPv4 Prefixes" in out

    def test_reverse_dns_and_domains(self, capsys):
        assert main(["AS15169", "--reverse-dns", "--domains", "--no-color"]) == 0
        out = capsys.readouterr().out
        assert "Reverse DNS (sampled)" in out
        assert "dns.google" in out
        assert "Domains / Hostnames" in out

    def test_ct_mode(self, capsys):
        assert main(["AS15169", "--ct", "--ct-domain", "example.com", "--no-color"]) == 0
        out = capsys.readouterr().out
        assert "Certificate Transparency" in out
        assert "api.example.com" in out

    def test_expand_in_json(self, capsys):
        assert main(["AS15169", "--expand", "--max-hosts", "1000", "--json"]) == 0
        data = json.loads(capsys.readouterr().out)
        ranges = {e["prefix"]: e for e in data["expanded_ranges"]}
        assert ranges["8.8.8.0/24"]["addresses"] is not None
        assert ranges["34.64.0.0/10"]["addresses"] is None
        assert "skipped" in ranges["34.64.0.0/10"]["skipped_reason"].lower()

    def test_bulk_summary_line(self, capsys):
        assert main(["AS15169,AS13335", "--quiet"]) == 0
        err = capsys.readouterr().err
        assert "Processed: 2 ASNs" in err

    def test_quiet_suppresses_progress(self, capsys):
        assert main(["AS15169", "--quiet"]) == 0
        captured = capsys.readouterr()
        assert "[+]" not in captured.err
        assert "RESULTS — AS15169" in captured.out


# ---------------------------------------------------------------------------
# Configuration plumbing
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_print_config_redacts_keys(self, capsys, monkeypatch):
        monkeypatch.setenv("BGPVIEW_API_KEY", "super-secret-value")
        assert main(["--print-config"]) == 0
        out = capsys.readouterr().out
        assert "super-secret-value" not in out
        assert "bgpview" in out

    def test_custom_config_file(self, capsys, isolated_cwd):
        (isolated_cwd / "cfg.yaml").write_text(
            "http:\n  timeout: 7\n", encoding="utf-8"
        )
        assert main(["--config", "cfg.yaml", "--print-config"]) == 0
        out = capsys.readouterr().out
        assert "7" in out

    def test_cli_overrides_config(self, capsys):
        assert main(["--timeout", "42", "--print-config"]) == 0
        out = capsys.readouterr().out
        assert "42.0" in out
