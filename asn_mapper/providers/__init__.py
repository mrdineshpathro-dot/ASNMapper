"""Data providers (pluggable public-data sources).

Each provider family is implemented behind an abstract base class so new
sources can be added without touching the collection logic:

* :class:`~asn_mapper.providers.bgp.BGPProvider` — announced prefixes +
  ASN metadata (RIPEstat, BGPView, local/custom datasets)
* :class:`~asn_mapper.providers.rdap.RegistryProvider` — RIR registration
  data via RDAP (rdap.org bootstrap + direct RIR endpoints)
* :class:`~asn_mapper.providers.ct.CTProvider` — Certificate Transparency
  log lookups (crt.sh)
* :class:`~asn_mapper.providers.dns.ReverseDNSService` — conservative PTR
  lookups via dnspython
"""
from .bgp import (
    BGPProvider,
    BGPService,
    BGPViewProvider,
    CustomProvider,
    RIPEStatProvider,
    build_bgp_service,
)
from .ct import CrtShProvider, CTProvider, CTService
from .dns import ReverseDNSService
from .rdap import (
    RDAPBootstrapProvider,
    RDAPService,
    RegistryProvider,
    RIRRdapProvider,
    build_rdap_service,
)

__all__ = [
    "BGPProvider",
    "BGPService",
    "BGPViewProvider",
    "CTProvider",
    "CTService",
    "CustomProvider",
    "CrtShProvider",
    "RDAPBootstrapProvider",
    "RDAPService",
    "RIPEStatProvider",
    "RIRRdapProvider",
    "RegistryProvider",
    "ReverseDNSService",
    "build_bgp_service",
    "build_rdap_service",
]
