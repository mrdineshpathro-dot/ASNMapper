"""Application configuration.

Precedence (lowest → highest):

1. Built-in defaults (this module).
2. Optional YAML config file — ``~/.config/asn-asset-mapper/config.yaml``
   by default, overridable with ``--config``.
3. Environment variables (``AAM_*`` plus ``*_API_KEY``).
4. Command-line options (applied by :mod:`asn_mapper.cli`).

The YAML loader uses PyYAML when available and transparently falls back to a
small flat ``section.key: value`` parser, keeping the dependency optional.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

from . import USER_AGENT

__all__ = [
    "AppConfig",
    "CacheSettings",
    "DnsSettings",
    "HttpSettings",
    "LoggingSettings",
    "OutputSettings",
    "ProviderSettings",
    "DEFAULT_CONFIG_PATH",
    "load_config",
]

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "asn-asset-mapper" / "config.yaml"

#: Mapping of environment variable → (dataclass field path, type).
_ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "AAM_TIMEOUT": ("http.timeout", "float"),
    "AAM_RETRIES": ("http.retries", "int"),
    "AAM_BACKOFF": ("http.backoff_base", "float"),
    "AAM_MIN_INTERVAL": ("http.min_request_interval", "float"),
    "AAM_THREADS": ("threads", "int"),
    "AAM_USER_AGENT": ("user_agent", "str"),
    "AAM_CACHE_TTL": ("cache.ttl", "int"),
    "AAM_CACHE_DIR": ("cache.directory", "path"),
    "AAM_NO_CACHE": ("cache.enabled", "bool_inverted"),
    "AAM_DNS_TIMEOUT": ("dns.timeout", "float"),
    "AAM_DNS_RETRIES": ("dns.retries", "int"),
    "AAM_DNS_SAMPLE": ("dns.sample_per_prefix", "int"),
    "AAM_DNS_MAX": ("dns.max_lookups", "int"),
    "AAM_CUSTOM_BGP_PATH": ("providers.custom_bgp_path", "str"),
    "AAM_CRT_SH_URL": ("providers.crt_sh_url", "str"),
    "AAM_RIPESTAT_URL": ("providers.ripestat_url", "str"),
    "AAM_BGPVIEW_URL": ("providers.bgpview_url", "str"),
    "AAM_RDAP_BOOTSTRAP_URL": ("providers.rdap_bootstrap_url", "str"),
    "AAM_LOG_FILE": ("logging.file", "str"),
}


@dataclass
class HttpSettings:
    """Outbound HTTP behaviour (timeouts, retries, politeness)."""

    timeout: float = 15.0
    retries: int = 3
    backoff_base: float = 1.0  # seconds; attempt N sleeps base * 2**(N-1)
    max_delay: float = 30.0
    min_request_interval: float = 0.5  # rate-limiting per provider
    verify_tls: bool = True


@dataclass
class ProviderSettings:
    """Data provider endpoints and ordering.

    All API URLs live here (never scattered through the code base). The
    ``bgp_providers`` list defines the fallback order used by the BGP
    service.
    """

    bgp_providers: list[str] = field(default_factory=lambda: ["ripestat", "bgpview", "custom"])
    rdap_order: list[str] = field(
        default_factory=lambda: ["bootstrap", "arin", "ripe", "apnic", "lacnic", "afrinic"]
    )
    rdap_endpoints: dict[str, str] = field(
        default_factory=lambda: {
            "bootstrap": "https://rdap.org",
            "arin": "https://rdap.arin.net/registry",
            "ripe": "https://rdap.db.ripe.net",
            "apnic": "https://rdap.apnic.net",
            "lacnic": "https://rdap.lacnic.net/rdap",
            "afrinic": "https://rdap.afrinic.net/rdap",
        }
    )
    ripestat_url: str = "https://stat.ripe.net/data"
    bgpview_url: str = "https://api.bgpview.io"
    crt_sh_url: str = "https://crt.sh/"
    ct_timeout: float = 60.0
    rdap_bootstrap_url: str = "https://rdap.org"
    custom_bgp_path: str = ""


@dataclass
class DnsSettings:
    """Conservative reverse-DNS behaviour."""

    timeout: float = 4.0
    retries: int = 2
    concurrency: int = 10
    sample_per_prefix: int = 2
    max_lookups: int = 256
    nameservers: list[str] = field(default_factory=list)
    negative_cache_ttl: int = 3600


@dataclass
class CacheSettings:
    """Local response cache (``~/.cache/asn-asset-mapper`` by default)."""

    enabled: bool = True
    ttl: int = 86_400
    directory: Path = field(default_factory=lambda: Path.home() / ".cache" / "asn-asset-mapper")


@dataclass
class OutputSettings:
    """Presentation limits for the human-readable report."""

    max_prefix_display: int = 50
    max_domains_display: int = 50
    max_reverse_display: int = 50
    max_expand_display: int = 20
    max_expand_hosts: int = 10_000  # never enumerate beyond this
    json_indent: int = 2


@dataclass
class LoggingSettings:
    """Structured logging target."""

    file: str = "asn_mapper.log"


@dataclass
class AppConfig:
    """Root configuration object for the whole application."""

    user_agent: str = USER_AGENT
    threads: int = 10
    http: HttpSettings = field(default_factory=HttpSettings)
    providers: ProviderSettings = field(default_factory=ProviderSettings)
    dns: DnsSettings = field(default_factory=DnsSettings)
    cache: CacheSettings = field(default_factory=CacheSettings)
    output: OutputSettings = field(default_factory=OutputSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    #: Optional API keys, populated from ``*_API_KEY`` environment variables.
    #: Values are never logged or written to output.
    api_keys: dict[str, str] = field(default_factory=dict)
    #: Non-fatal problems noticed while loading configuration.
    warnings: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    def to_dict(self, redact_secrets: bool = True) -> dict[str, Any]:
        """Return the effective configuration as a plain dict.

        API key values are redacted by default so the dump is safe to print.
        """
        data = asdict(self)
        if redact_secrets and self.api_keys:
            data["api_keys"] = {k: "***redacted***" for k in self.api_keys}
        return data

    def apply_cli_overrides(self, overrides: Mapping[str, Any]) -> None:
        """Apply command-line option overrides (``{"http.timeout": 30}``)."""
        for path, value in overrides.items():
            if value is None:
                continue
            _assign_path(self, path, value)


# --------------------------------------------------------------------------
# Loading & merging
# --------------------------------------------------------------------------


def load_config(
    path: str | Path | None = None,
    use_env: bool = True,
    config_path_default: Path = DEFAULT_CONFIG_PATH,
) -> AppConfig:
    """Load an :class:`AppConfig` from defaults + YAML file + environment.

    Missing files are not an error — defaults are used silently.
    """
    config = AppConfig()
    config_path = Path(path) if path else config_path_default
    if config_path.is_file():
        try:
            mapping = _load_yaml_file(config_path)
        except Exception as exc:  # noqa: BLE001 - malformed config must not crash
            config.warnings.append(f"Could not parse config file {config_path}: {exc}")
        else:
            _apply_mapping(config, mapping, source=str(config_path))
    if use_env:
        _apply_env(config)
    return config


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Parse a YAML config file; falls back to a flat parser without PyYAML."""
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return _parse_flat_config(text)
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("config file root must be a mapping")
    return data


def _parse_flat_config(text: str) -> dict[str, Any]:
    """Minimal fallback parser: ``section.key: value`` lines, ``#`` comments."""
    result: dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not key:
            continue
        node: dict[str, Any] = result
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})  # type: ignore[assignment]
            if not isinstance(node, dict):
                break
        if isinstance(node, dict):
            node[parts[-1]] = _coerce_scalar(value)
    return result


def _coerce_scalar(value: str) -> Any:
    """Best-effort conversion of a scalar config value."""
    text = value.strip().strip("'\"")
    lowered = text.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none", "~", ""}:
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [item.strip().strip("'\"") for item in inner.split(",") if item.strip()]
    return text


def _apply_mapping(config: AppConfig, mapping: Mapping[str, Any], source: str = "config") -> None:
    """Recursively apply a nested mapping onto the dataclass tree."""
    for key, value in mapping.items():
        if value is None:
            continue
        if isinstance(value, Mapping):
            current = getattr(config, key, None)
            if is_dataclass(current) and not isinstance(current, type):
                _apply_mapping(current, value, source)  # type: ignore[arg-type]
                continue
            config.warnings.append(f"[{source}] ignored unknown section '{key}'")
            continue
        _assign_path(config, str(key), value, source=source)


def _assign_path(obj: Any, path: str, value: Any, source: str = "cli") -> None:
    """Assign ``value`` at a dotted path such as ``http.timeout``."""
    parts = path.split(".")
    node = obj
    for part in parts[:-1]:
        candidate = getattr(node, part, None)
        if candidate is None:
            return
        node = candidate
    leaf = parts[-1]
    if not hasattr(node, leaf):
        if isinstance(getattr(obj, "warnings", None), list):
            obj.warnings.append(f"[{source}] ignored unknown setting '{path}'")
        return
    current = getattr(node, leaf)
    try:
        setattr(node, leaf, _coerce_to_type(value, current, leaf))
    except (TypeError, ValueError) as exc:
        if isinstance(getattr(obj, "warnings", None), list):
            obj.warnings.append(f"[{source}] invalid value for '{path}': {exc}")


def _coerce_to_type(value: Any, current: Any, leaf: str) -> Any:
    if isinstance(current, bool) or current is None and isinstance(value, bool):
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "yes", "on", "1"}:
                return True
            if lowered in {"false", "no", "off", "0"}:
                return False
            raise ValueError(f"not a boolean: {value!r}")
        return bool(value)
    if isinstance(current, int) and not isinstance(current, bool):
        return int(value)
    if isinstance(current, float):
        return float(value)
    if isinstance(current, Path):
        return Path(str(value))
    if isinstance(current, list):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return list(value)
    if isinstance(current, str):
        return str(value)
    return value


def _apply_env(config: AppConfig) -> None:
    """Apply ``AAM_*`` overrides and harvest ``*_API_KEY`` variables."""
    for env_name, (path, _kind) in _ENV_OVERRIDES.items():
        raw = os.environ.get(env_name)
        if raw is None or raw == "":
            continue
        if path == "cache.enabled":  # bool_inverted
            lowered = raw.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                config.cache.enabled = False
            continue
        if path == "cache.directory":
            config.cache.directory = Path(raw)
            continue
        try:
            _assign_path(config, path, raw, source="env")
        except (TypeError, ValueError):
            config.warnings.append(f"[env] invalid value for {env_name}: {raw!r}")

    for env_name, raw in os.environ.items():
        if env_name.endswith("_API_KEY") and raw.strip():
            config.api_keys[env_name[:-len("_API_KEY")].lower()] = raw


def dataclass_fields_names(obj: Any) -> list[str]:
    """Return the field names of a dataclass instance (helper)."""
    return [f.name for f in fields(obj)] if is_dataclass(obj) and not isinstance(obj, type) else []
