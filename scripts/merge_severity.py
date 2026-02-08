"""Merge min_severity override into a SecureScan config file.

Usage: python scripts/merge_severity.py <source_config_or_empty> <output_path> <min_severity>
"""

import sys
from pathlib import Path

import yaml

source = Path(sys.argv[1]) if sys.argv[1] else None
target = Path(sys.argv[2])
min_severity = sys.argv[3]

data = {}
if source is not None and source.exists():
    try:
        loaded = yaml.safe_load(source.read_text(encoding="utf-8"))
    except Exception:
        loaded = {}
    if isinstance(loaded, dict):
        data = loaded

data["min_severity"] = min_severity
target.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
