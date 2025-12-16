"""Detector for SYN flood: counts SYN packets per source within a short window."""
from __future__ import annotations

import time
from collections import deque, defaultdict
from typing import Dict, Any, List


class SynFloodDetector:
    def __init__(self, window_seconds: float = 0.5, threshold: int = 10):
        # be more sensitive by default: 10 SYNs in 0.5s
        self.window = window_seconds
        self.threshold = threshold
        self._hist = defaultdict(deque)

    def analyze(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        proto = (packet.get('protocol') or '').upper()
        if proto != 'TCP':
            return findings

        src = packet.get('src_ip')
        if not src:
            return findings
        now = time.time()
        dq = self._hist[src]
        dq.append(now)
        while dq and (now - dq[0]) > self.window:
            dq.popleft()

        if len(dq) >= self.threshold:
            dst = packet.get('dst_ip') or packet.get('dst')
            findings.append({
                'type': 'syn_flood',
                'attack_type': 'syn_flood',
                'protocol': 'TCP',
                'src_ip': src,
                'dst_ip': dst,
                'count': len(dq),
                'window': self.window,
                'message': f'SYN flood suspected from {src} to {dst} — {len(dq)} SYNs in {self.window}s'
            })
            dq.clear()
        return findings
