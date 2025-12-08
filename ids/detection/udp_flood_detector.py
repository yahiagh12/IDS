"""Detector for UDP flood: counts UDP packets per source within a short window.

Emits a finding with rich context (src/dst/protocol/ports/count/window).
"""
from __future__ import annotations

import time
from collections import deque, defaultdict
from typing import Dict, Any, List


class UdpFloodDetector:
    def __init__(self, window_seconds: float = 0.5, threshold: int = 10):
        # trigger when threshold packets in window_seconds
        self.window = window_seconds
        self.threshold = threshold
        self._hist = defaultdict(deque)

    def analyze(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        proto = (packet.get('protocol') or '').upper()
        if proto != 'UDP':
            return findings

        src = packet.get('src_ip') or packet.get('src')
        if not src:
            return findings

        now = time.time()
        dq = self._hist[src]
        dq.append(now)
        # expire old timestamps
        while dq and (now - dq[0]) > self.window:
            dq.popleft()

        if len(dq) >= self.threshold:
            dst = packet.get('dst_ip') or packet.get('dst')
            findings.append({
                'type': 'udp_flood',
                'attack_type': 'udp_flood',
                'protocol': 'UDP',
                'src_ip': src,
                'dst_ip': dst,
                'count': len(dq),
                'window': self.window,
                'message': f'UDP flood suspected from {src} to {dst} — {len(dq)} UDPs in {self.window}s'
            })
            dq.clear()

        return findings
