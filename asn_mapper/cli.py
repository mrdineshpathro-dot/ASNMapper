"""Command-line interface for ASN Asset Mapper.

Preferred syntax::

    asn-mapper [OPTIONS] ASN...

Examples::

    asn-mapper AS15169
    asn-mapper AS15169 AS396982 AS16509 --json -o results.json
    asn-mapper AS15169,AS16509 --summary
    asn-mapper --input asns.txt --csv -o prefixes.csv
    asn-mapper AS15169 --rdap --bgp --domains --reverse-dns
    asn-mapper AS15169 --prefixes-only --ipv4-only
    asn-mapper AS15169 --ct --ct-domain google.com

The default workflow is **passive-only**: public BGP announcements and RDAP
registration data. Every optional module (reverse DNS, domain correlation,
CT enumeration) must be requested explicitly.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import (
    __author__,
    __author_github__,
    __donate__,
    __homepage__,
    __tagline__,
    __title__,
    __version__,
)
from . import config as config_module
from .config import AppConfig, load_config
from .core import MapperEngine, RunOptions
from .models import BulkResult
from .output import csv as csv_out
from .output import json as json_out
from .output import txt as txt_out
from .output.console import ConsoleUI
from .utils.cache import FileCache
from .utils.logger import setup_logging
from .validators import InvalidASNError, parse_asn_arguments

__all__ = ["build_parser", "main"]

_EPILOG = """\
examples:
  %(prog)s AS15169                              map a single ASN (human report)
  %(prog)s AS15169 AS396982 AS16509             map multiple ASNs
  %(prog)s AS15169,AS16509                      comma-separated input
  %(prog)s --input asns.txt --summary           bulk processing from a file
  %(prog)s AS15169 --json -o results.json       JSON export to a file
  %(prog)s AS15169 --csv -o prefixes.csv        CSV export to a file
  %(prog)s AS15169 --txt                        plain-text report
  %(prog)s AS15169 --prefixes-only --ipv4-only  bare prefix list (pipe-friendly)
  %(prog)s AS15169 --rdap --bgp --domains --json -o results.json
  %(prog)s AS15169 --reverse-dns --dns-sample 5 conservative PTR sampling
  %(prog)s AS15169 --ct --ct-domain example.com Certificate Transparency

documentation:
  https://github.com/mrdineshpathro-dot/ASNMapper

responsible use:
  This tool performs passive collection of publicly available data only.
  Use it exclusively for authorized security research and asset inventory.
"""


def _version_string() -> str:
    return (
        f"{__title__} {__version__}\n"
        f"{__tagline__}\n"
        f"Author : {__author__} (https://github.com/{__author_github__})\n"
        f"License: MIT · {__homepage__}\n"
        f"Support: {__donate__}"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (exported for tests)."""
    parser = argparse.ArgumentParser(
        prog="asn-mapper",
        description=(
            f"{__title__} — {__tagline__}. Collects passive, publicly available "
            "ASN intelligence: announced prefixes, RDAP registration data, "
            "correlated domains and reverse DNS."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "asns",
        nargs="*",
        metavar="ASN",
        help="one or more ASNs (AS15169, as15169 or 15169; commas allowed)",
    )

    targets = parser.add_argument_group("targets")
    targets.add_argument(
        "-i", "--input",
        metavar="FILE",
        help="file with one ASN per line (# comments and blank lines ignored)",
    )

    formats = parser.add_mutually_exclusive_group()
    formats.add_argument("--json", dest="format", action="store_const", const="json",
                         help="output machine-readable JSON (see JSON schema in README)")
    formats.add_argument("--csv", dest="format", action="store_const", const="csv",
                         help="output CSV (one row per record)")
    formats.add_argument("--txt", dest="format", action="store_const", const="txt",
                         help="output plain-text report (full prefix lists)")
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="write the export to FILE (format inferred from extension if not given)",
    )

    data = parser.add_argument_group("data collection")
    data.add_argument("--rdap", dest="rdap", action="store_true", default=None,
                      help="include RDAP registration data (default: on)")
    data.add_argument("--no-rdap", dest="rdap", action="store_false",
                      help="skip RDAP registration data")
    data.add_argument("--bgp", dest="bgp", action="store_true", default=None,
                      help="include BGP announced prefixes (default: on)")
    data.add_argument("--no-bgp", dest="bgp", action="store_false",
                      help="skip BGP prefix collection")
    data.add_argument("--domains", action="store_true",
                      help="passive domain/hostname correlation (registration + PTR data)")
    data.add_argument("--ct", action="store_true",
                      help="Certificate Transparency enumeration (needs seed domains)")
    data.add_argument("--ct-domain", dest="ct_domains", metavar="DOMAIN", action="append", default=[],
                      help="seed domain for CT enumeration (repeatable, commas allowed)")
    data.add_argument("--reverse-dns", action="store_true",
                      help="conservative reverse-DNS (PTR) sampling of announced prefixes")

    prefixes = parser.add_argument_group("prefix options")
    prefixes.add_argument("--prefixes-only", action="store_true",
                          help="print only the prefix list (pipe-friendly)")
    prefixes.add_argument("--ipv4-only", action="store_true", help="restrict output to IPv4 prefixes")
    prefixes.add_argument("--ipv6-only", action="store_true", help="restrict output to IPv6 prefixes")
    prefixes.add_argument("--expand", action="store_true",
                          help="expand prefixes into network/broadcast/host ranges")
    prefixes.add_argument("--max-hosts", type=int, metavar="NUMBER", default=None,
                          help="maximum addresses to enumerate with --expand (default 10000)")

    tuning = parser.add_argument_group("performance & politeness")
    tuning.add_argument("--threads", type=int, metavar="NUMBER", default=None,
                        help="worker threads for reverse DNS (default 10)")
    tuning.add_argument("--timeout", type=float, metavar="SECONDS", default=None,
                        help="HTTP/DNS timeout in seconds (default 15)")
    tuning.add_argument("--retries", type=int, metavar="NUMBER", default=None,
                        help="retries for transient failures (default 3)")
    tuning.add_argument("--dns-sample", type=int, metavar="NUMBER", default=None,
                        help="reverse-DNS samples per prefix (default 2, conservative)")

    display = parser.add_argument_group("output control")
    display.add_argument("--summary", action="store_true",
                         help="compact summary instead of the full report")
    display.add_argument("--no-color", action="store_true", help="disable colored output")
    display.add_argument("--quiet", action="store_true", help="suppress progress output")
    display.add_argument("--verbose", action="store_true", help="verbose logging (also see --quiet)")

    system = parser.add_argument_group("configuration & caching")
    system.add_argument("--config", metavar="FILE",
                        help=f"config file (default: {config_module.DEFAULT_CONFIG_PATH})")
    system.add_argument("--print-config", action="store_true",
                        help="print the effective configuration and exit")
    system.add_argument("--no-cache", action="store_true", help="disable the response cache")
    system.add_argument("--cache-ttl", type=int, metavar="SECONDS", default=None,
                        help="cache time-to-live (default 86400)")
    system.add_argument("--log-file", metavar="FILE", default=None,
                        help="log file (default asn_mapper.log)")

    parser.add_argument("-v", "--version", action="version", version=_version_string(),
                        help="show version and author information and exit")

    return parser


def _apply_cli_overrides(args: argparse.Namespace, config: AppConfig) -> None:
    """Fold CLI options into the loaded configuration."""
    overrides: dict[str, object] = {}
    if args.timeout is not None:
        overrides["http.timeout"] = args.timeout
        overrides["dns.timeout"] = args.timeout
    if args.retries is not None:
        overrides["http.retries"] = args.retries
        overrides["dns.retries"] = args.retries
    if args.threads is not None:
        overrides["threads"] = args.threads
        overrides["dns.concurrency"] = max(1, args.threads)
    if args.dns_sample is not None:
        overrides["dns.sample_per_prefix"] = max(0, args.dns_sample)
    if args.cache_ttl is not None:
        overrides["cache.ttl"] = args.cache_ttl
    if args.max_hosts is not None:
        overrides["output.max_expand_hosts"] = args.max_hosts
    config.apply_cli_overrides(overrides)
    if args.no_cache:
        config.cache.enabled = False


def _collect_target_asns(args: argparse.Namespace) -> tuple[list[int], list[str]]:
    """Merge positional ASNs with ``--input`` file contents."""
    tokens: list[str] = list(args.asns)
    if args.input:
        try:
            text = Path(args.input).read_text(encoding="utf-8")
        except OSError as exc:
            raise InvalidASNError(f"cannot read --input file {args.input}: {exc}") from exc
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                tokens.extend(part for part in line.replace(",", " ").split() if part)
    return parse_asn_arguments(tokens)


def _infer_format(args: argparse.Namespace) -> str:
    """Resolve the output format, inferring from -o extension when needed."""
    if args.format:
        return args.format
    if args.output:
        suffix = Path(args.output).suffix.lower()
        if suffix == ".json":
            return "json"
        if suffix == ".csv":
            return "csv"
        if suffix in {".txt", ".text", ".log"}:
            return "txt"
    return "human"


def _filter_results(bulk: BulkResult, ipv4_only: bool, ipv6_only: bool) -> BulkResult:
    """Apply --ipv4-only/--ipv6-only filtering (recomputes statistics)."""
    if not (ipv4_only or ipv6_only):
        return bulk
    from .collectors.prefixes import PrefixCollector

    for result in bulk.results:
        if ipv4_only:
            result.ipv6_prefixes = []
        if ipv6_only:
            result.ipv4_prefixes = []
        result.stats = PrefixCollector.compute_stats(result.ipv4_prefixes + result.ipv6_prefixes)
        if result.expansions:
            keep = {p.prefix for p in result.ipv4_prefixes + result.ipv6_prefixes}
            result.expansions = [e for e in result.expansions if e.prefix in keep]
    return bulk


def _render_prefixes_only(bulk: BulkResult) -> str:
    lines: list[str] = []
    for result in bulk.results:
        lines.extend(record.prefix for record in result.ipv4_prefixes + result.ipv6_prefixes)
    for failure in bulk.failed:
        print(f"[!] {failure.asn}: FAILED — {failure.reason}", file=sys.stderr)
    return "\n".join(lines)


def _export(bulk: BulkResult, fmt: str, path: str, ui: ConsoleUI, config: AppConfig) -> None:
    """Write results to *path* in the requested format."""
    if fmt == "json":
        json_out.write_json(path, bulk, indent=config.output.json_indent)
    elif fmt == "csv":
        csv_out.write_csv(path, bulk)
    else:  # txt / human
        txt_out.write_txt(path, bulk)
    ui.print_saved(path)


def _emit(bulk: BulkResult, fmt: str, ui: ConsoleUI, config: AppConfig, args: argparse.Namespace) -> None:
    """Print the results to stdout in the requested format."""
    if fmt == "json":
        print(json_out.render_json(bulk, indent=config.output.json_indent))
    elif fmt == "csv":
        print(csv_out.render_csv(bulk), end="")
    elif fmt == "txt":
        print(txt_out.render_txt(bulk), end="")
    else:
        ui.render_bulk(bulk, summary_only=args.summary)


def build_engine(config: AppConfig, ui: ConsoleUI, cache: FileCache | None = None) -> MapperEngine:
    """Construct the mapping engine (separate function — used by tests)."""
    return MapperEngine(config=config, notifier=ui, cache=cache)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")

    # ------------------------------------------------------------------
    # Configuration & logging
    # ------------------------------------------------------------------
    try:
        config = load_config(path=args.config)
    except Exception as exc:  # noqa: BLE001 — config must never crash the CLI
        print(f"[x] Failed to load configuration: {exc}", file=sys.stderr)
        return 1

    if args.no_color:
        import os

        os.environ["NO_COLOR"] = "1"

    _apply_cli_overrides(args, config)
    setup_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file or config.logging.file)

    ui = ConsoleUI(config, no_color=args.no_color, quiet=args.quiet)

    if args.print_config:
        ui.report.print_json(__import__("json").dumps(config.to_dict(), default=str))
        return 0

    for warning in config.warnings:
        ui.warn(f"config: {warning}")

    # ------------------------------------------------------------------
    # Target resolution
    # ------------------------------------------------------------------
    try:
        asns, invalid = _collect_target_asns(args)
    except InvalidASNError as exc:
        ui.error(str(exc))
        return 1

    for message in invalid:
        ui.warn(message)

    if not asns:
        ui.error(
            "No valid ASN supplied. Provide ASNs as arguments (e.g. "
            "asn-mapper AS15169) or a file via --input asns.txt."
        )
        return 1

    ui.banner()
    if len(asns) == 1:
        ui.info(f"Target ASN : AS{asns[0]}")
    else:
        ui.info(f"Target ASNs: {', '.join(f'AS{a}' for a in asns)}")

    # ------------------------------------------------------------------
    # Run the engine
    # ------------------------------------------------------------------
    engine = build_engine(config, ui)
    options = RunOptions(
        rdap=True if args.rdap is None else args.rdap,
        bgp=True if args.bgp is None else args.bgp,
        reverse_dns=args.reverse_dns,
        domains=args.domains,
        ct=args.ct,
        ct_seeds=args.ct_domains,
        expand=args.expand,
        max_hosts=config.output.max_expand_hosts,
    )
    try:
        bulk = engine.run(asns, options)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130

    try:
        bulk = _filter_results(bulk, args.ipv4_only, args.ipv6_only)

        for result in bulk.results:
            parts = [
                f"{result.asn}: {len(result.ipv4_prefixes)} IPv4 / "
                f"{len(result.ipv6_prefixes)} IPv6 prefixes"
            ]
            if result.domains:
                parts.append(f"{len(result.domains)} domains")
            if result.ct_names:
                parts.append(f"{len(result.ct_names)} CT names")
            ui.ok(" · ".join(parts))
        for failure in bulk.failed:
            ui.error(f"{failure.asn}: {failure.reason}")

        # ------------------------------------------------------------------
        # Output
        # ------------------------------------------------------------------
        fmt = _infer_format(args)
        if args.prefixes_only:
            text = _render_prefixes_only(bulk)
            if args.output:
                Path(args.output).write_text(text + "\n", encoding="utf-8")
                ui.print_saved(args.output)
            else:
                print(text)
        elif args.output:
            _export(bulk, fmt, args.output, ui, config)
        elif bulk.results or bulk.failed:
            _emit(bulk, fmt, ui, config, args)

        if bulk.processed > 1:
            # Bulk summary is essential output — shown even in --quiet mode.
            ui.summary_line(
                f"Processed: {bulk.processed} ASNs | "
                f"Successful: {bulk.successful} | Failed: {bulk.failure_count}"
            )
        ui.completed(bulk.completed_in)
    except Exception as exc:  # noqa: BLE001 — never dump a raw traceback on users
        import traceback

        traceback.print_exc(file=sys.stderr)
        ui.error(f"Unexpected error while rendering results: {exc.__class__.__name__}: {exc}")
        return 1

    # Exit code: success only when at least one ASN produced results.
    return 0 if bulk.results else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
