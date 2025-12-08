"""Simple runtime configuration for detectors.

Config is persisted to `ids/config.json` so GUI changes survive restarts.
Backends and detectors read values from this module.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict

_DEFAULTS: Dict[str, Any] = {
    'simple_rate': {'window': 0.5, 'threshold': 10},
    'syn_flood': {'window': 1.0, 'threshold': 50},
    'udp_flood': {'window': 1.0, 'threshold': 50},
    'queue_maxsize': 5000,
}

_cfg: Dict[str, Any] = {}

_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.json'))


def load():
    global _cfg
    if os.path.exists(_path):
        try:
            with open(_path, 'r') as f:
                _cfg = json.load(f)
        except Exception:
            _cfg = dict(_DEFAULTS)
    else:
        _cfg = dict(_DEFAULTS)


def save():
    try:
        with open(_path, 'w') as f:
            json.dump(_cfg, f, indent=2)
        return True
    except Exception:
        return False


def get(section: str, default=None):
    return _cfg.get(section, _DEFAULTS.get(section, default))


def set_section(section: str, value: Dict[str, Any]):
    _cfg[section] = value


# initialize
load()
