#!/usr/bin/env python3
"""ASN Asset Mapper — standalone entry point.

Allows running the tool from a source checkout without installing it::

    python asn_mapper.py AS15169

For the full console command, install the package::

    pip install .
    asn-mapper AS15169
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root (the directory containing this file) is importable
# when the script is executed directly from a fresh checkout.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from asn_mapper.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
