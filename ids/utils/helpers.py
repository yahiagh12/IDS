"""Small utility helpers used across the project."""
from typing import Any, Dict


def safe_get(d: Dict[str, Any], *keys, default=None):
    for k in keys:
        if k in d:
            return d[k]
    return default
