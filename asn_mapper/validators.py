"""Input validation and normalization helpers.

This module contains pure functions (no I/O) that validate and normalize:

* ASN numbers (``AS15169``, ``as15169``, ``15169`` ...)
* CIDR prefixes (IPv4 and IPv6) via the standard :mod:`ipaddress` module
* Domains and hostnames

Everything here is intentionally side-effect free so it can be unit tested
without network access.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

__all__ = [
    "InvalidASNError",
    "InvalidCIDRError",
    "InvalidDomainError",
    "MAX_ASN",
    "PRIVATE_16BIT_ASN_RANGE",
    "PRIVATE_32BIT_ASN_RANGE",
    "RESERVED_ASNS",
    "canonical_prefix",
    "dedupe_strings",
    "format_asn",
    "is_valid_asn",
    "is_private_asn",
    "normalize_asn",
    "normalize_domain",
    "parse_asn_arguments",
    "parse_cidr",
    "registrable_domain",
]

IPAddressNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ValidationError(ValueError):
    """Base class for all validation errors raised by this package."""


class InvalidASNError(ValidationError):
    """Raised when an ASN cannot be parsed or is outside the valid range."""


class InvalidCIDRError(ValidationError):
    """Raised when a value cannot be parsed as an IPv4/IPv6 CIDR prefix."""


class InvalidDomainError(ValidationError):
    """Raised when a value cannot be parsed as a domain/hostname."""


# --------------------------------------------------------------------------
# ASN handling
# --------------------------------------------------------------------------

#: Largest valid 32-bit ASN.
MAX_ASN = 4_294_967_295

#: Private/document 16-bit ASN range (RFC 6996).
PRIVATE_16BIT_ASN_RANGE = (64_512, 65_534)

#: Private 32-bit ASN range (RFC 6996).
PRIVATE_32BIT_ASN_RANGE = (4_200_000_000, 4_294_967_294)

#: ASNs that are reserved and never allocated.
RESERVED_ASNS = frozenset({0, 65_535, 4_294_967_295})

_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)


def normalize_asn(value: str | int) -> int:
    """Normalize an ASN value into an ``int``.

    Accepts formats such as ``"AS15169"``, ``"as15169"``, ``"15169"``,
    ``" AS15169 "`` or the plain integer ``15169``.

    :param value: raw ASN value
    :returns: the ASN as an integer (e.g. ``15169``)
    :raises InvalidASNError: if the value is not a valid public ASN number
    """
    if isinstance(value, bool):  # bool is an int subclass — reject explicitly
        raise InvalidASNError(f"Invalid ASN: {value!r}")
    if isinstance(value, int):
        number = value
    else:
        text = str(value).strip().upper().replace(" ", "")
        match = _ASN_RE.match(text)
        if not match:
            raise InvalidASNError(f"Invalid ASN format: {value!r}")
        number = int(match.group(1))
    if number < 1 or number > MAX_ASN or number in RESERVED_ASNS:
        raise InvalidASNError(
            f"Invalid ASN: AS{number} is outside the global unicast ASN range"
            f" (AS1–AS{MAX_ASN}, excluding reserved values)"
        )
    return number


def is_valid_asn(value: str | int) -> bool:
    """Return ``True`` when *value* is a syntactically valid ASN."""
    try:
        normalize_asn(value)
    except InvalidASNError:
        return False
    return True


def format_asn(number: int) -> str:
    """Format an ASN integer as the canonical ``AS15169`` string."""
    return f"AS{int(number)}"


def is_private_asn(number: int) -> bool:
    """Return ``True`` for private-use ASN ranges (RFC 6996)."""
    return (
        PRIVATE_16BIT_ASN_RANGE[0] <= number <= PRIVATE_16BIT_ASN_RANGE[1]
        or PRIVATE_32BIT_ASN_RANGE[0] <= number <= PRIVATE_32BIT_ASN_RANGE[1]
    )


def parse_asn_arguments(values: Iterable[str]) -> tuple[list[int], list[str]]:
    """Parse CLI ASN arguments (space- and comma-separated).

    :param values: raw argument strings, e.g. ``["AS15169,AS16509", "13335"]``
    :returns: tuple of ``(valid_asns, errors)`` where *errors* contains a
        human readable message for every rejected token.
    """
    valid: list[int] = []
    errors: list[str] = []
    seen: set[int] = set()
    for chunk in values:
        for token in str(chunk).replace(";", ",").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                asn = normalize_asn(token)
            except InvalidASNError as exc:
                errors.append(str(exc))
                continue
            if asn not in seen:
                seen.add(asn)
                valid.append(asn)
    return valid, errors


# --------------------------------------------------------------------------
# CIDR / prefix handling
# --------------------------------------------------------------------------


def parse_cidr(value: str) -> IPAddressNetwork:
    """Parse and canonicalize a CIDR prefix.

    Host bits are silently zeroed (``8.8.8.1/24`` → ``8.8.8.0/24``) because
    BGP data sources occasionally return non-canonical strings.

    :param value: prefix string, e.g. ``"2001:4860::/32"``
    :returns: a canonical :class:`ipaddress.IPv4Network` /
        :class:`ipaddress.IPv6Network`
    :raises InvalidCIDRError: if the value cannot be parsed
    """
    if not isinstance(value, str) or not value.strip():
        raise InvalidCIDRError("Invalid CIDR: empty value")
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise InvalidCIDRError(f"Invalid CIDR {value!r}: {exc}") from exc
    return network


def canonical_prefix(value: str) -> str:
    """Return the canonical string form of a CIDR prefix."""
    return str(parse_cidr(value))


# --------------------------------------------------------------------------
# Domain / hostname handling
# --------------------------------------------------------------------------

#: Roughly RFC-1123 compliant hostname pattern.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$",
    re.IGNORECASE,
)

#: Common public suffixes that use a second-level registration rule.
#: This is a deliberate, dependency-free approximation of the Public
#: Suffix List — it covers the vast majority of real-world hostnames.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "com.br", "net.br", "org.br", "gov.br",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "com.mx", "org.mx", "net.mx",
        "co.in", "net.in", "org.in", "firm.in", "gen.in", "ac.in", "edu.in", "gov.in",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
        "com.tr", "net.tr", "org.tr", "gov.tr",
        "com.ar", "net.ar", "org.ar", "gov.ar",
        "com.co", "net.co", "org.co", "gov.co", "edu.co",
        "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
        "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
        "com.my", "net.my", "org.my", "gov.my", "edu.my",
        "co.za", "net.za", "org.za", "web.za", "gov.za",
        "com.ru", "net.ru", "org.ru",
        "co.il", "org.il", "net.il", "gov.il", "ac.il",
        "com.pl", "net.pl", "org.pl",
        "co.id", "or.id", "web.id", "ac.id", "go.id",
        "com.ph", "net.ph", "org.ph",
        "com.vn", "net.vn", "org.vn",
        "com.ua", "net.ua", "org.ua",
        "com.sa", "net.sa", "org.sa",
        "com.pk", "net.pk", "org.pk",
        "com.eg", "net.eg", "org.eg",
        "com.ng", "net.ng", "org.ng",
        "com.ke", "co.ke", "or.ke",
        "co.th", "in.th", "or.th", "ac.th", "go.th",
        "com.ec", "net.ec", "org.ec",
        "com.pe", "net.pe", "org.pe",
        "com.ve", "net.ve", "org.ve",
        "com.cl", "net.cl", "org.cl",
        "gob.pe", "gob.mx", "gob.ar",
    }
)


def normalize_domain(value: str) -> str | None:
    """Normalize a domain/hostname for comparison and display.

    Performs case folding, whitespace stripping, and trailing-dot removal so
    that ``Example.COM``, ``example.com.`` and ``example.com`` compare equal.

    :param value: raw hostname
    :returns: the normalized hostname, or ``None`` when clearly invalid
    """
    if not isinstance(value, str):
        return None
    text = value.strip().rstrip(".").lower()
    if not text or len(text) > 253:
        return None
    if not _DOMAIN_RE.match(text):
        return None
    return text


def registrable_domain(hostname: str) -> str | None:
    """Return the best-effort registrable (eTLD+1) domain of a hostname.

    Uses a small built-in list of multi-label public suffixes (``co.uk``,
    ``com.au``, ...) instead of pulling in a Public Suffix List dependency.
    For single-label hostnames (``localhost``) or IP addresses, ``None`` is
    returned.

    :param hostname: a hostname such as ``mail.example.co.uk``
    :returns: e.g. ``example.co.uk`` or ``None``
    """
    normalized = normalize_domain(hostname)
    if not normalized:
        return None
    # Reject bare IP addresses.
    try:
        ipaddress.ip_address(normalized)
        return None
    except ValueError:
        pass
    labels = normalized.split(".")
    if len(labels) < 2:
        return None
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    if last_two in MULTI_LABEL_SUFFIXES:
        return None
    return last_two


def dedupe_strings(values: Iterable[str], case_sensitive: bool = False) -> list[str]:
    """Deduplicate strings while preserving first-seen order.

    :param values: iterable of strings
    :param case_sensitive: when ``False`` (default) comparison is case-folded
        but the first-seen original casing is kept
    """
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        key = value if case_sensitive else value.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result
