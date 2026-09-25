"""ASN Asset Mapper — map the public network footprint of an ASN.

A passive ASN and public network asset mapping tool for defensive security
research, asset inventory, and network intelligence. The tool collects
publicly available information (BGP announcements, RIR registration data via
RDAP, Certificate Transparency logs, and reverse DNS) for one or more
Autonomous System Numbers and produces structured, exportable reports.

.. important::
   ASN Asset Mapper is a **passive** intelligence tool. It performs no port
   scanning, vulnerability testing, exploitation, or any form of intrusive
   probing. Use it only for authorized security research and asset inventory.

:copyright: (c) 2026 Mr Dinesh Pathro
:license: MIT, see the LICENSE file for details.
"""
from __future__ import annotations

__title__ = "ASN Asset Mapper"
__package_name__ = "asn-asset-mapper"
__version__ = "1.0.0"
__tagline__ = "Map the Public Network Footprint of an ASN"
__author__ = "Mr Dinesh Pathro"
__author_github__ = "mrdineshpathro-dot"
__homepage__ = "https://github.com/mrdineshpathro-dot/ASNMapper"
__donate__ = "https://buymeacoffee.com/mrdineshpathro"
__license__ = "MIT"

#: Default HTTP User-Agent used for every outbound request.
USER_AGENT = f"ASN-Asset-Mapper/{__version__} (+{__homepage__})"

__all__ = [
    "__author__",
    "__author_github__",
    "__donate__",
    "__homepage__",
    "__license__",
    "__package_name__",
    "__tagline__",
    "__title__",
    "__version__",
    "USER_AGENT",
]
