"""Packet normalization / parsing helpers.

Provides a small `normalize_packet()` helper that converts backend-specific
packet dictionaries into the canonical packet shape used across the pipeline.
"""
from typing import Any, Dict


def normalize_packet(pkt: Dict[str, Any]) -> Dict[str, Any]:
    """Return a normalized packet dict with canonical keys.

    Canonical keys: `timestamp`, `src_ip`, `dst_ip`, `protocol`, `length`, `summary`.
    This implementation is conservative: it extracts common fields if present
    and falls back to best-effort defaults.
    """
    out: Dict[str, Any] = {}
    # timestamp
    out['timestamp'] = pkt.get('timestamp') or pkt.get('time') or pkt.get('ts')

    # src / dst
    out['src_ip'] = pkt.get('src_ip') or pkt.get('src') or pkt.get('source')
    out['dst_ip'] = pkt.get('dst_ip') or pkt.get('dst') or pkt.get('destination')

    # protocol
    proto = pkt.get('protocol') or pkt.get('proto')
    if isinstance(proto, bytes):
        try:
            proto = proto.decode('utf-8', errors='ignore')
        except Exception:
            proto = str(proto)
    out['protocol'] = proto or pkt.get('layer') or 'UNKNOWN'

    # length
    out['length'] = pkt.get('length') or pkt.get('len') or pkt.get('size') or 0

    # summary
    out['summary'] = pkt.get('summary') or pkt.get('info') or str(pkt)

    # Remove port fields
    out.pop('src_port', None)
    out.pop('dst_port', None)

    # include original packet for downstream analysis if needed
    out['_raw'] = pkt
    return out
