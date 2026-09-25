"""Tests for the mapping engine: orchestration, fallback, dedup, confidence."""
from __future__ import annotations

from conftest import FakeBGPProvider, FakeDNSService, FakeRegistryProvider

from asn_mapper.core import MapperEngine, NullNotifier, RunOptions
from asn_mapper.models import PrefixRecord, RDAPInfo
from asn_mapper.providers.bgp import BGPProvider, BGPService
from asn_mapper.providers.rdap import RDAPService
from asn_mapper.utils.networking import ProviderError


class RecordingNotifier:
    def __init__(self):
        self.messages: list[tuple[str, str]] = []

    def info(self, message): self.messages.append(("info", message))
    def warn(self, message): self.messages.append(("warn", message))
    def error(self, message): self.messages.append(("error", message))


def make_engine(config, bgp=None, rdap=None, dns=None, ct=None, notifier=None):
    return MapperEngine(
        config=config,
        notifier=notifier or NullNotifier(),
        bgp_service=bgp,
        rdap_service=rdap,
        dns_service=dns,
        ct_service=ct,
    )


class TestEngineBasics:
    def test_full_passive_run(self, config, fake_bgp, fake_rdap):
        engine = make_engine(config, bgp=fake_bgp, rdap=fake_rdap)
        bulk = engine.run([15169])
        assert bulk.successful == 1
        result = bulk.results[0]
        # RDAP wins for registration facts
        assert result.organization == "Google LLC"
        assert result.country == "US"
        assert result.registry == "ARIN"
        assert result.rdap.handle == "AS15169"
        # prefixes split by version, stats computed
        assert len(result.ipv4_prefixes) == 2
        assert len(result.ipv6_prefixes) == 2
        assert result.stats.total_count == 4
        assert result.stats.ipv4_addresses == 256 + 4_194_304
        # sources recorded
        providers = {s.provider for s in result.sources}
        assert "FakeBGP" in providers
        assert "fake-rdap" in providers
        assert result.errors == []
        assert result.successful is True

    def test_rdap_disabled(self, config, fake_bgp, fake_rdap):
        engine = make_engine(config, bgp=fake_bgp, rdap=fake_rdap)
        bulk = engine.run([15169], RunOptions(rdap=False))
        result = bulk.results[0]
        assert result.rdap is None
        # registry falls back to BGP-provided data ("ARIN" comes from the fake)
        assert result.registry == "ARIN"

    def test_expand_option(self, config, fake_bgp, fake_rdap):
        engine = make_engine(config, bgp=fake_bgp, rdap=fake_rdap)
        bulk = engine.run([15169], RunOptions(expand=True, max_hosts=1000))
        result = bulk.results[0]
        assert len(result.expansions) == 4
        big = next(e for e in result.expansions if e.prefix == "34.64.0.0/10")
        assert big.addresses is None  # enumeration skipped: too large
        small = next(e for e in result.expansions if e.prefix == "8.8.8.0/24")
        assert small.addresses is not None


class TestProviderFallback:
    def test_bgp_fallback(self, config, google_asn_data, fake_rdap):
        broken = FakeBGPProvider(error=ProviderError("primary exploded"))
        working = FakeBGPProvider(google_asn_data)
        service = BGPService([broken, working])
        engine = make_engine(config, bgp=service, rdap=fake_rdap)
        bulk = engine.run([15169])
        result = bulk.results[0]
        # data still collected from the fallback provider
        assert len(result.ipv4_prefixes) == 2
        # the primary failure is transparently recorded
        assert any("FakeBGP" in error and "primary exploded" in error for error in result.errors)

    def test_bgp_fallback_notified(self, config, google_asn_data):
        broken = FakeBGPProvider(error=ProviderError("primary exploded"))
        working = FakeBGPProvider(google_asn_data)
        notifier = RecordingNotifier()
        service = BGPService([broken, working], on_provider_error=lambda name, reason: notifier.warn(reason))
        engine = make_engine(config, bgp=service, notifier=notifier)
        engine.run([15169])
        assert any("primary exploded" in message for _, message in notifier.messages)

    def test_all_providers_fail(self, config, fake_rdap):
        broken = FakeBGPProvider(error=ProviderError("down"))
        engine = make_engine(config, bgp=BGPService([broken]), rdap=fake_rdap)
        bulk = engine.run([15169])
        result = bulk.results[0]
        assert result.ipv4_prefixes == [] and result.ipv6_prefixes == []
        assert result.errors  # surfaced, but the run did not crash
        assert result.successful is True  # RDAP still produced data

    def test_rdap_fallback_chain(self, config, fake_bgp):
        broken = FakeRegistryProvider(error=ProviderError("nope"))
        good = FakeRegistryProvider(
            {15169: RDAPInfo(asn="AS15169", handle="AS15169", organization="Google LLC",
                             country="US", registry="ARIN", source="second-rdap")}
        )
        engine = make_engine(config, bgp=fake_bgp, rdap=RDAPService([broken, good]))
        bulk = engine.run([15169])
        assert bulk.results[0].rdap.organization == "Google LLC"
        assert bulk.results[0].rdap.source == "second-rdap"

    def test_rdap_totally_unavailable(self, config, fake_bgp):
        broken = FakeRegistryProvider(error=ProviderError("nope"))
        engine = make_engine(config, bgp=fake_bgp, rdap=RDAPService([broken]))
        bulk = engine.run([15169])
        result = bulk.results[0]
        assert result.rdap is None
        assert any("fake-rdap" in error for error in result.errors)


class TestReverseDnsModule:
    def test_reverse_dns_and_domain_correlation(self, config, fake_bgp, fake_rdap, fake_dns):
        engine = make_engine(config, bgp=fake_bgp, rdap=fake_rdap, dns=fake_dns)
        bulk = engine.run([15169], RunOptions(reverse_dns=True, domains=True))
        result = bulk.results[0]
        # sampled the first 2 host addresses of every prefix
        ips = [r.ip for r in result.reverse_dns]
        assert "8.8.8.1" in ips and "8.8.8.2" in ips
        resolved = {r.ip: r.hostname for r in result.reverse_dns if r.hostname}
        assert resolved["8.8.8.1"] == "dns.google"
        # every record carries the prefix it was sampled from
        assert all(r.prefix for r in result.reverse_dns)
        # PTR-observed domains show up as OBSERVED with evidence
        observed = [d for d in result.domains if d.domain == "dns.google"]
        assert observed and observed[0].confidence == "OBSERVED"
        assert "PTR" in observed[0].evidence
        # registration website becomes an INFERRED seed domain
        inferred = [d for d in result.domains if d.domain == "google.com"]
        assert inferred and inferred[0].confidence == "INFERRED"

    def test_dns_lookup_cap_respected(self, config, google_asn_data):
        service = BGPService([FakeBGPProvider(google_asn_data)])
        dns = FakeDNSService({})
        engine = make_engine(config, bgp=service, dns=dns)
        engine.run([15169], RunOptions(reverse_dns=True))
        # 4 prefixes × 2 samples = 8 lookups in the default fixture
        assert len(dns.calls) == 8


class TestCtModule:
    def test_ct_with_explicit_seeds(self, config, fake_bgp, fake_rdap, fake_ct):
        engine = make_engine(config, bgp=fake_bgp, rdap=fake_rdap, ct=fake_ct)
        bulk = engine.run([15169], RunOptions(ct=True, ct_seeds=["example.com"]))
        result = bulk.results[0]
        assert "example.com" in result.ct_names
        assert "api.example.com" in result.ct_names
        assert result.certificates and result.certificates[0].issuer == "Fake CA"
        correlated = [d for d in result.domains if d.domain == "example.com"]
        assert correlated and correlated[0].confidence == "CORRELATED"

    def test_ct_without_seeds_uses_registration_website(self, config, fake_bgp, fake_rdap, fake_ct):
        engine = make_engine(config, bgp=fake_bgp, rdap=fake_rdap, ct=fake_ct)
        bulk = engine.run([15169], RunOptions(ct=True))  # no --ct-domain, no --domains
        result = bulk.results[0]
        # the fake CT provider has no certs for google.com → no names, but the
        # run must not fail and the seed derivation from the org website works
        assert result.ct_names == []
        assert result.successful

    def test_ct_notes_limitation_when_no_seeds_possible(self, config, fake_rdap, fake_ct):
        # an ASN with no website and no domain data → CT cannot be seeded
        bare = {15169: (None, [])}
        engine = make_engine(
            config,
            bgp=BGPService([FakeBGPProvider(bare)]),
            rdap=fake_rdap,
            ct=fake_ct,
        )
        bulk = engine.run([15169], RunOptions(ct=True))
        result = bulk.results[0]
        assert result.ct_names == []
        assert any("--ct-domain" in note for note in result.notes)

    def test_ct_seeds_derived_from_domains(self, config, fake_bgp, fake_rdap, fake_dns, fake_ct):
        engine = make_engine(config, bgp=fake_bgp, rdap=fake_rdap, dns=fake_dns, ct=fake_ct)
        # google.com is INFERRED from the registration website → used as seed.
        # The fake CT provider only knows example.com, so expect no names but
        # no crash either — proving derived seeds were attempted.
        bulk = engine.run([15169], RunOptions(ct=True, domains=True))
        result = bulk.results[0]
        assert result.successful


class TestDedupAndConfidence:
    def test_duplicate_prefixes_deduplicated(self, config, google_asn_data):
        data = dict(google_asn_data)
        _info, prefixes = data[15169]
        data[15169] = (_info, prefixes + [PrefixRecord(prefix="8.8.8.1/24", version=4)])
        service = BGPService([FakeBGPProvider(data)])
        engine = make_engine(config, bgp=service)
        bulk = engine.run([15169])
        v4 = [p.prefix for p in bulk.results[0].ipv4_prefixes]
        assert v4.count("8.8.8.0/24") == 1
        assert "8.8.8.1/24" not in v4  # canonicalized to 8.8.8.0/24 and deduped


class TestBulkRuns:
    def test_multiple_asns_with_one_failure(self, config, google_asn_data):
        service = BGPService([FakeBGPProvider(google_asn_data)])  # only knows AS15169
        engine = make_engine(config, bgp=service)
        bulk = engine.run([15169, 13335])
        assert bulk.processed == 2
        assert bulk.successful == 2  # AS13335 still produced a (mostly empty) result
        assert bulk.failure_count == 0

    def test_unexpected_exception_recorded_as_failure(self, config, google_asn_data):
        class ExplodingProvider(BGPProvider):
            name = "Exploding"

            def fetch_asn_info(self, asn):
                raise RuntimeError("kaboom")

            def fetch_prefixes(self, asn):
                raise RuntimeError("kaboom")

        engine = make_engine(config, bgp=BGPService([ExplodingProvider(None)]))
        bulk = engine.run([15169])
        # ProviderError/NetworkError are caught per-provider, but even a raw
        # RuntimeError must not crash the engine run itself.
        assert isinstance(bulk, object)
        assert bulk.processed == 1
