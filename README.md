# ASN Asset Mapper

**Map the Public Network Footprint of an ASN**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-pytest-brightgreen.svg)](#testing)
[![Passive Only](https://img.shields.io/badge/design-passive--only-informational.svg)](#responsible-use)

A passive ASN and public network asset mapping tool for **defensive security research**,
asset inventory, and network intelligence.

ASN Asset Mapper takes an Autonomous System Number (e.g. `AS15169`, `AS13335`, `AS16509`)
and retrieves publicly available information about it: announced IPv4/IPv6 prefixes, RIR
registration data (RDAP), correlated domains and hostnames, reverse-DNS observations, and
Certificate Transparency names — then exports everything as JSON, CSV, or a clean
human-readable report.

> **Defensive tooling.** ASN Asset Mapper collects **only publicly available data** using
> passive lookups. It performs **no** port scanning, vulnerability scanning, exploitation,
> credential attacks, brute force, intrusive probing, or rate-limit bypass. Use it for
> authorized security research, asset inventory, and reconnaissance on infrastructure you
> are authorized to assess.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [CLI Options](#cli-options)
- [Examples](#examples)
- [Output Examples](#output-examples)
- [JSON Schema](#json-schema)
- [Architecture](#architecture)
- [Supported Data Sources](#supported-data-sources)
- [Data Confidence Labels](#data-confidence-labels)
- [Caching](#caching)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Responsible Use](#responsible-use)
- [License](#license)
- [Author](#author)

---

## Features

- **ASN input flexibility** — `AS15169`, `as15169`, `15169`, comma-separated lists, multiple
  arguments, or bulk files (`--input asns.txt`).
- **ASN information** — organization, AS name, country, registry/RIR, website, and BGP
  metadata, clearly separated into *registered* vs *announced* vs *inferred* data.
- **IP prefix mapping** — all publicly announced IPv4/IPv6 prefixes, validated and
  canonicalized with Python's standard `ipaddress` module.
- **Prefix statistics** — counts, approximate IPv4 address totals, IPv6 space size (never
  enumerated), min/max prefix lengths, and prefix-length distributions.
- **Safe IP range expansion** — `--expand` converts CIDRs to network/broadcast/host ranges
  and refuses to enumerate beyond `--max-hosts` (default 10,000).
- **Reverse DNS** — conservative, bounded PTR sampling with timeouts, retries, caching,
  and thread-pool limits (`--reverse-dns`).
- **Domain correlation** — passive hostname/domain discovery from registration data,
  reverse DNS, and Certificate Transparency (`--domains`, `--ct`).
- **Certificate Transparency** — CT log enumeration via crt.sh with issuer, validity
  dates, and deduplicated DNS names.
- **Provider fallback** — RIPEstat → BGPView → local dataset, with automatic retry,
  exponential backoff, and HTTP 429 / `Retry-After` handling.
- **RDAP support** — modern RDAP lookups (rdap.org bootstrap + all five RIR endpoints)
  instead of scraping legacy WHOIS.
- **Multiple output formats** — rich terminal report, JSON, CSV, plain text; export to
  file with `-o`.
- **Deduplication & normalization** — prefixes, hostnames, and domains are canonicalized
  (`Example.COM` → `example.com`) and deduplicated everywhere.
- **Source attribution** — every dataset records provider, type, and retrieval time for
  reproducibility.
- **Local caching** — `~/.cache/asn-asset-mapper/` with TTL, `--no-cache` and
  `--cache-ttl` controls.
- **Configuration** — YAML config file, `AAM_*` environment variables, and API keys via
  `*_API_KEY` env vars (never hardcoded, never logged).

## Requirements

- Python **3.11** or newer
- Network access to the public APIs listed under [Supported Data Sources](#supported-data-sources)

Runtime dependencies (installed automatically):

| Package     | Purpose                                            |
|-------------|----------------------------------------------------|
| `requests`  | HTTP client with connection pooling                |
| `rich`      | Terminal UI (tables, panels, colors)               |
| `dnspython` | Reverse-DNS (PTR) lookups                          |
| `PyYAML`    | Configuration file parsing (optional at runtime)   |

## Installation

### From source (recommended)

```bash
git clone https://github.com/mrdineshpathro-dot/ASNMapper.git
cd ASNMapper

python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Run without installing (from the repository root):

```bash
python asn_mapper.py AS15169
```

### As a package (adds the `asn-mapper` command)

```bash
pip install .          # or: pip install -e . for development
asn-mapper --version
```

## Quick Start

```bash
# Basic passive map of Google's ASN
asn-mapper AS15169

# Everything at once, exported as JSON
asn-mapper AS15169 --rdap --bgp --domains --reverse-dns --json -o results.json

# Cloudflare IPv4 prefixes only, pipe-friendly
asn-mapper AS13335 --prefixes-only --ipv4-only

# Bulk process a list of ASNs
asn-mapper --input asns.txt --summary
```

## Usage

```
asn-mapper [OPTIONS] ASN...
```

ASNs may be given as `AS15169`, `as15169`, or `15169`, separated by spaces or commas.
Multiple ASNs produce combined results with a bulk summary (`Processed / Successful /
Failed`).

With `--input FILE`, the file should contain one ASN per line (blank lines and `#`
comments are ignored):

```text
# asns.txt
AS15169
AS16509
AS13335
```

Progress messages go to **stderr** and reports go to **stdout**, so piping works:

```bash
asn-mapper AS15169 --json | jq '.prefix_count'
asn-mapper AS13335 --prefixes-only --ipv4-only | grep /24
```

## CLI Options

```
targets:
  -i, --input FILE        file with one ASN per line

formats:
  --json                  machine-readable JSON (schema below)
  --csv                   CSV, one row per record (prefixes, domains, ...)
  --txt                   plain-text report (lists every prefix)
  -o, --output FILE       write to FILE (format inferred from extension)

data collection:
  --rdap / --no-rdap      include RDAP registration data      (default: on)
  --bgp / --no-bgp        include BGP announced prefixes      (default: on)
  --domains               passive domain/hostname correlation
  --ct                    Certificate Transparency enumeration
  --ct-domain DOMAIN      seed domain for CT (repeatable / comma-separated)
  --reverse-dns           conservative reverse-DNS (PTR) sampling

prefix options:
  --prefixes-only         print only the prefix list (pipe-friendly)
  --ipv4-only             restrict output to IPv4 prefixes
  --ipv6-only             restrict output to IPv6 prefixes
  --expand                expand prefixes into network/broadcast/host ranges
  --max-hosts NUMBER      enumeration cap for --expand (default 10000)

performance & politeness:
  --threads NUMBER        worker threads for reverse DNS (default 10)
  --timeout SECONDS       HTTP/DNS timeout (default 15)
  --retries NUMBER        retries for transient failures (default 3)
  --dns-sample NUMBER     reverse-DNS samples per prefix (default 2)

output control:
  --summary               compact summary instead of the full report
  --no-color              disable colored output
  --quiet                 suppress progress output
  --verbose               verbose logging (also writes asn_mapper.log)

configuration & caching:
  --config FILE           config file (default ~/.config/asn-asset-mapper/config.yaml)
  --print-config          print the effective configuration and exit
  --no-cache              disable the response cache
  --cache-ttl SECONDS     cache time-to-live (default 86400)
  --log-file FILE         log file (default asn_mapper.log)

  -h, --help              show help (with examples)
  -v, --version           show version and author information
```

## Examples

```bash
# Single ASN, human-readable report
asn-mapper AS15169

# Multiple ASNs (spaces or commas)
asn-mapper AS15169 AS396982 AS16509
asn-mapper AS15169,AS16509

# JSON export
asn-mapper AS15169 --json -o results.json

# CSV export of prefixes
asn-mapper AS15169 --csv -o prefixes.csv

# Plain-text report to a file
asn-mapper AS15169 --txt -o report.txt

# Bare prefix lists (ideal for firewall/allowlist generation)
asn-mapper AS15169 --prefixes-only
asn-mapper AS15169 --prefixes-only --ipv4-only
asn-mapper AS15169 --prefixes-only --ipv6-only

# Full passive intelligence gathering
asn-mapper AS15169 --rdap --bgp --domains --reverse-dns --json -o results.json

# Certificate Transparency with explicit seed domains
asn-mapper AS15169 --ct --ct-domain google.com --ct-domain googlecloud.com

# Range expansion with a strict enumeration cap
asn-mapper AS15169 --expand --max-hosts 1000

# Bulk processing with a summary
asn-mapper --input examples/asns.txt --summary

# More aggressive (but still bounded) reverse-DNS sampling
asn-mapper AS16509 --reverse-dns --dns-sample 5 --threads 20
```

### Offline / air-gapped use

A `Custom` BGP provider can read a local JSON dataset (last in the fallback chain):

```bash
export AAM_CUSTOM_BGP_PATH=examples/custom-bgp.json
asn-mapper AS15169 --no-rdap
```

Dataset format (see [`examples/custom-bgp.json`](examples/custom-bgp.json)):

```json
{
  "AS15169": {
    "organization": "Google LLC",
    "as_name": "GOOGLE",
    "country": "US",
    "registry": "ARIN",
    "ipv4_prefixes": ["8.8.8.0/24"],
    "ipv6_prefixes": ["2001:4860::/32"]
  }
}
```

## Output Examples

A real terminal session (generated with the offline example dataset — see
[`examples/sample-output.txt`](examples/sample-output.txt)):

```text
╭────────────────────────────────────────────╮
│              ASN ASSET MAPPER              │
╰────────────────────────────────────────────╯
   Map the Public Network Footprint of an ASN · v1.0.0 · by Mr Dinesh Pathro

[+] Target ASN : AS15169
[+] Fetching ASN information for AS15169 ...
[+] ASN AS15169 — Organization: Google LLC | Country: US | Registry: ARIN
[+] Collecting announced prefixes for AS15169 ...
[+] Collected 38 IPv4 and 11 IPv6 prefixes
[✓] AS15169: 38 IPv4 / 11 IPv6 prefixes
──────────────────────────────────────────────────────────────
RESULTS — AS15169
──────────────────────────────────────────────────────────────
Target ASN    AS15169
Organization  Google LLC
AS Name       GOOGLE
Country       US
Registry      ARIN
Website       https://www.google.com

IPv4 Prefixes
-------------
8.8.4.0/24        8.8.8.0/24        8.34.208.0/20     8.35.192.0/20
23.236.48.0/20    23.251.128.0/19   34.0.0.0/15       34.2.0.0/16
34.64.0.0/10      35.184.0.0/13     35.192.0.0/14     ...

IPv6 Prefixes
-------------
2001:4860::/32  2404:6800::/32  2404:f340::/32  2600:1900::/28
2606:40::/32    2607:f8b0::/32  ...

Prefix Statistics
-----------------
IPv4 Prefixes               38
IPv6 Prefixes               11
Total                       49
IPv4 Addresses represented  6,490,880
IPv6 Address space          ≈1.50×2^100 addresses
IPv4 prefix lengths         /10 – /24
IPv6 prefix lengths         /28 – /40

Sources
-------
Custom  BGP  2026-09-25T10:00:00Z  ASN metadata
Custom  BGP  2026-09-25T10:00:00Z  49 announced prefixes

Completed in 0.00s
```

Prefix expansion (`--expand --max-hosts 300`):

```text
IP Range Expansion
------------------
34.64.0.0/10
  Network     34.64.0.0
  Broadcast   34.127.255.255
  First host  34.64.0.1
  Last host   34.127.255.254
  Hosts       4,194,302
  4,194,302 addresses — enumeration skipped because range exceeds --max-hosts (300)

8.8.8.0/24
  Network     8.8.8.0
  Broadcast   8.8.8.255
  First host  8.8.8.1
  Last host   8.8.8.254
  Hosts       254
  8.8.8.0, 8.8.8.1, 8.8.8.2, ... (256 total)
```

Bulk summary (`--input examples/asns.txt --summary`):

```text
Processed: 3 ASNs | Successful: 3 | Failed: 0
```

More generated examples: [`examples/example.json`](examples/example.json),
[`examples/sample-bulk-summary.txt`](examples/sample-bulk-summary.txt).

## JSON Schema

`--json` emits this schema for a single ASN (multiple ASNs are wrapped in a bulk
envelope with `tool`, `processed`, `successful`, `failed`, `results[]`, and
`failed_asns[]`). A complete real example lives in
[`examples/example.json`](examples/example.json).

```json
{
  "asn": "AS15169",
  "organization": "Google LLC",
  "country": "US",
  "registry": "ARIN",
  "asn_info": { "asn": 15169, "asn_str": "AS15169", "as_name": "GOOGLE", "...": "..." },
  "rdap": { "handle": "AS15169", "name": "GOOGLE", "registry": "ARIN", "...": "..." },
  "ipv4_prefixes": ["8.8.8.0/24", "34.64.0.0/10"],
  "ipv6_prefixes": ["2001:4860::/32", "2607:f8b0::/32"],
  "prefix_count": { "ipv4": 250, "ipv6": 50, "total": 300 },
  "prefix_stats": { "ipv4_addresses": 8932864, "ipv6_addresses_human": "≈...", "...": "..." },
  "expanded_ranges": [],
  "domains": ["example.com"],
  "domain_records": [
    { "domain": "example.com", "confidence": "CORRELATED", "source": "...", "evidence": "..." }
  ],
  "reverse_dns": [ { "ip": "8.8.8.1", "hostname": "dns.google", "prefix": "8.8.8.0/24" } ],
  "ct_names": ["api.example.com", "example.com"],
  "certificates": [
    { "common_name": "example.com", "dns_names": ["example.com"],
      "issuer": "C=US, O=Let's Encrypt, CN=E6",
      "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00" }
  ],
  "sources": [
    { "provider": "RIPEstat", "type": "BGP", "retrieved_at": "2026-09-25T10:00:00Z" },
    { "provider": "rdap.org", "type": "registration", "retrieved_at": "2026-09-25T10:00:02Z" }
  ],
  "errors": [],
  "notes": [],
  "timestamp": "2026-09-25T10:00:00Z",
  "elapsed_seconds": 4.21
}
```

CSV columns: `asn, record_type, value, ip_version, prefix_length, address_count,
confidence, source, evidence` — `record_type` is one of `asn_info`, `prefix`,
`domain`, `reverse_dns`, `certificate`, `error`.

## Architecture

```
asn_mapper/
├── cli.py               # argument parsing, orchestration, exit codes
├── core.py              # MapperEngine — runs collectors per ASN, merges results
├── config.py            # AppConfig: defaults ← YAML ← env (AAM_*) ← CLI
├── models.py            # dataclasses + JSON schema serialization
├── validators.py        # ASN/CIDR/domain validation & normalization (pure functions)
│
├── providers/           # pluggable public-data sources (with fallback)
│   ├── bgp.py           #   BGPProvider → RIPEStat | BGPView | Custom (local dataset)
│   ├── rdap.py          #   RegistryProvider → rdap.org bootstrap | 5 × RIR RDAP
│   ├── ct.py            #   CTProvider → crt.sh
│   └── dns.py           #   ReverseDNSService (dnspython, cached, bounded threads)
│
├── collectors/          # orchestration of providers into datasets
│   ├── asn.py           #   merges BGP metadata + RDAP registration data
│   ├── prefixes.py      #   validation, dedup, statistics, expansion, sampling
│   ├── reverse_dns.py   #   bounded PTR sampling across prefixes
│   └── domains.py       #   passive correlation + confidence labelling
│
├── output/
│   ├── console.py       #   rich terminal UI (progress → stderr, report → stdout)
│   ├── json.py          #   JSON export (single object or bulk envelope)
│   ├── csv.py           #   streaming CSV export
│   └── txt.py           #   complete plain-text report
│
└── utils/
    ├── cache.py         #   thread-safe on-disk TTL cache
    ├── logger.py        #   structured logging → asn_mapper.log
    └── networking.py    #   HttpClient: retries, backoff, 429/Retry-After,
                         #   rate limiting, User-Agent, pooling, response cache
```

**Design principles**

- *Passive by default* — every optional module is opt-in; nothing contacts the target.
- *Provider abstraction* — each data family has an abstract base class; new sources are a
  new class + one registry entry. Failures cascade to fallbacks, never to the user.
- *Pure validators* — validation/normalization is side-effect free and fully unit tested.
- *No global mutable state* — the engine receives an injected config/cache/notifier.
- *Honest data* — every record carries a confidence label and evidence trail.

## Supported Data Sources

| Source                    | Type            | Key required | Used for                                |
|---------------------------|-----------------|--------------|-----------------------------------------|
| [RIPEstat](https://stat.ripe.net/docs/data_api) | BGP | No  | Announced prefixes, ASN holder (primary) |
| [BGPView](https://bgpview.io/)                  | BGP | No  | Prefixes + ASN metadata (fallback)       |
| Local JSON dataset        | BGP             | No           | Offline/air-gapped fallback              |
| [rdap.org](https://rdap.org) + RIR RDAP endpoints | RDAP | No | Registration data (org, country, handle) |
| [crt.sh](https://crt.sh)  | CT logs        | No           | Certificate names (needs seed domains)   |
| System DNS resolvers      | DNS             | No           | Reverse-DNS (PTR) sampling               |

Optional providers that require API keys are wired through environment variables only
(see [Configuration](#configuration)) — the tool never hardcodes secrets and never logs
key values.

## Data Confidence Labels

The tool **never** claims that every discovered asset belongs to the organization.
Every domain/asset record is labelled:

| Label        | Meaning                                                        |
|--------------|----------------------------------------------------------------|
| `DIRECT`     | Registered or announced by the ASN itself (BGP announcements, RDAP registration) |
| `CORRELATED` | Publicly associated with the organization (e.g. CT log names for a seed domain) |
| `OBSERVED`   | Observed in public data (e.g. PTR hostnames for IPs inside announced prefixes) |
| `INFERRED`   | Derived by heuristic (e.g. registrable domain of the org website) |
| `UNKNOWN`    | Provenance could not be determined                             |

Evidence strings explain *why* each record was included (see `domain_records[].evidence`
in the JSON export).

## Caching

All API responses and DNS lookups are cached under `~/.cache/asn-asset-mapper/`:

- default TTL: 24 hours (`--cache-ttl`, config `cache.ttl`, env `AAM_CACHE_TTL`)
- disable entirely with `--no-cache` (or `AAM_NO_CACHE=1`, or `cache.enabled: false`)
- negative DNS answers use a shorter TTL (default 1h) so transient failures self-heal
- expired entries are removed automatically; entries are keyed by namespace + URL

## Configuration

Precedence: **defaults ← `~/.config/asn-asset-mapper/config.yaml` ← environment ← CLI**.

1. YAML file (see [`examples/config.example.yaml`](examples/config.example.yaml) for all
   options with defaults) — pass a custom path with `--config FILE`. Without PyYAML
   installed, a flat `section.key: value` syntax is still supported.
2. Environment variables — `AAM_TIMEOUT`, `AAM_RETRIES`, `AAM_THREADS`,
   `AAM_USER_AGENT`, `AAM_CACHE_TTL`, `AAM_CACHE_DIR`, `AAM_NO_CACHE`,
   `AAM_DNS_TIMEOUT`, `AAM_DNS_SAMPLE`, `AAM_DNS_MAX`, `AAM_MIN_INTERVAL`,
   `AAM_CUSTOM_BGP_PATH`, and more (see [`.env.example`](.env.example)).
3. API keys for optional providers come from `*_API_KEY` variables (e.g.
   `BGPVIEW_API_KEY`) and are never printed or logged. Run `--print-config` to inspect
   the effective configuration (keys are redacted).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `[!] BGP provider RIPEstat unavailable ... trying BGPView` | Normal fallback behaviour — one provider was slow or rate-limited; the next one is used automatically. |
| `HTTP 429 (rate limited)` | The provider is throttling you. The tool backs off and honours `Retry-After`; wait, or raise `--timeout`/lower concurrency. Wipe the cache if a poisoned entry is suspected. |
| `No valid ASN supplied` | ASNs must look like `AS15169` / `15169` (1–4294967295, excluding reserved values). |
| `RDAP: AS… not found` | The ASN exists in the global registry data or it is private (64xxx / 42xxxxxxxxx ranges are not routable). |
| Empty prefix list | The ASN may not announce anything (e.g. content-only ASNs), or all providers failed — check the `errors` array in JSON output. |
| `CT: no seed domains available` | CT logs are domain-indexed. Pass `--ct-domain example.com` or run with `--domains --reverse-dns` so seeds can be derived. |
| Reverse DNS all `(NXDOMAIN)` | Many networks simply have no PTR records; increase coverage with `--dns-sample`. |
| DNS/`dnspython` errors | Ensure `dnspython` is installed and the system resolver works (`resolv.conf`), or set `dns.nameservers` in the config. |
| Colors leak into piped output | Use `--no-color`; `rich` also auto-disables color on non-TTY streams. |

## Development

```bash
git clone https://github.com/mrdineshpathro-dot/ASNMapper.git
cd ASNMapper
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .          # editable install for development
```

Project conventions:

- Python 3.11+, type hints, PEP 8 (line length 110), docstrings on public APIs
- `from __future__ import annotations` throughout
- No network calls in tests — every provider is faked
- `ruff check asn_mapper tests` for linting

## Testing

```bash
python -m pytest
# or with coverage
python -m pytest --cov=asn_mapper --cov-report=term-missing
```

The suite (170+ tests) covers: ASN validation/normalization, CIDR parsing and IPv4/IPv6
calculations, prefix statistics, range expansion and enumeration caps, safe IP sampling,
every provider response parser (including malformed payloads), retry/backoff/429
handling, response caching and TTL expiry, provider fallback, engine orchestration,
confidence labelling, deduplication, JSON/CSV/TXT exports, and the full CLI
(arguments, exit codes, filters, file exports).

## Roadmap

- [ ] RIPEstat full-text search and peering data
- [ ] Historical BGP (announced/withdrawn) timeline view
- [ ] Additional CT sources (e.g. Censys/Microsoft APIs with user-provided keys)
- [ ] RPKI/ROA validation status per prefix
- [ ] HTML report export
- [ ] `--asn-name` lookup (resolve an organization name to candidate ASNs)
- [ ] Async HTTP transport for very large bulk runs

Contributions are welcome — open an issue first to discuss scope.

## Responsible Use

This tool is intended **exclusively** for:

- authorized security research
- defensive asset inventory and attack-surface management
- network intelligence on infrastructure you own or are authorized to assess

It must not be used to support unauthorized access, harassment, or any illegal activity.
The tool performs passive collection of public data only — but even passive intelligence
must respect the law, provider terms of service, and the rights of the organizations
being researched. You are responsible for compliance with the rules that apply to you.

## License

Released under the [MIT License](LICENSE) — © 2026 Mr Dinesh Pathro.

## Author

**Mr Dinesh Pathro** — [GitHub: mrdineshpathro-dot](https://github.com/mrdineshpathro-dot)

☕ Support / Donate: <https://buymeacoffee.com/mrdineshpathro>
