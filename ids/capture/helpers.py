"""Small helpers shared by capture backends.

Provide a single place to build the canonical packet dictionary so backends
produce consistent fields with minimal duplicated code.
"""
from datetime import datetime
from typing import Any, Dict, Optional


def make_packet_dict(src: str, dst: str, proto: str, length: int, summary: str = "", raw: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "protocol": proto,
        "length": length,
        "summary": summary,
        "_raw": raw or {},
    }
