"""Structured logging for ASN Asset Mapper.

A ``DEBUG``-level file handler always writes to ``asn_mapper.log`` (created
lazily in the current working directory). Console output only appears when
``--verbose`` is used, and ``--quiet`` silences everything but the file log.

The logger deliberately never receives API keys or other secrets.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

__all__ = ["get_logger", "setup_logging"]

LOGGER_NAME = "asn_mapper"
_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def setup_logging(
    verbose: bool = False,
    quiet: bool = False,
    log_file: str | Path = "asn_mapper.log",
) -> logging.Logger:
    """Configure and return the application logger.

    :param verbose: also mirror log records to stderr (DEBUG level)
    :param quiet: disable the console mirror even when *verbose* is set
    :param log_file: destination log file (lazy — created on first record)
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Idempotently reset handlers (important for tests and repeated calls).
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - defensive
            pass

    file_handler = logging.FileHandler(Path(log_file), encoding="utf-8", delay=True)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(file_handler)

    if verbose and not quiet:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
        logger.addHandler(console_handler)

    return logger


def get_logger() -> logging.Logger:
    """Return the application logger without reconfiguring it."""
    return logging.getLogger(LOGGER_NAME)
