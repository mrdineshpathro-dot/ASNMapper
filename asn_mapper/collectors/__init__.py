"""Collectors — orchestrate providers into cohesive datasets.

Collectors sit between the raw providers and the engine:

* :mod:`~asn_mapper.collectors.asn` — merges BGP + RDAP ASN metadata
* :mod:`~asn_mapper.collectors.prefixes` — validated, deduplicated prefix
  sets, statistics, range expansion and safe IP sampling
* :mod:`~asn_mapper.collectors.reverse_dns` — conservative PTR sampling
* :mod:`~asn_mapper.collectors.domains` — passive domain correlation
"""
from .asn import ASNInfoCollector
from .domains import DomainCollector
from .prefixes import PrefixCollector, expand_prefix, sample_ips
from .reverse_dns import ReverseDNSCollector

__all__ = [
    "ASNInfoCollector",
    "DomainCollector",
    "PrefixCollector",
    "ReverseDNSCollector",
    "expand_prefix",
    "sample_ips",
]
