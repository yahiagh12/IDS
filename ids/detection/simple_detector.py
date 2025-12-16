"""A simple detector that looks for high packet rates from the same source.

This detector maintains a short sliding window of timestamps per source IP
and emits a finding if a threshold is exceeded.
"""
from __future__ import annotations

import time
from collections import deque, defaultdict
from typing import Any, Dict, List


class SimpleRateDetector:
    def __init__(self, window_seconds: float = 0.5, threshold: int = 10):
        # default: 10 events in 0.5s triggers
        self.window = window_seconds
        self.threshold = threshold
        # map src_ip -> deque[timestamps]
        self._history = defaultdict(deque)

    def analyze(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        try:
            src = packet.get('src_ip') or packet.get('src', 'Unknown Source')
            dst = packet.get('dst_ip') or packet.get('dst', 'Unknown Destination')
            proto = (packet.get('protocol') or 'Unknown Protocol').upper()

            now = time.time()
            dq = self._history[src]
            dq.append(now)
            # drop old
            while dq and (now - dq[0]) > self.window:
                dq.popleft()

            if len(dq) >= self.threshold:
                attack_type = self._determine_attack_type(proto)
                findings.append({
                    'type': 'rate_limit',
                    'attack_type': attack_type,
                    'protocol': proto,
                    'src_ip': src or 'Unknown Source',
                    'dst_ip': dst or 'Unknown Destination',
                    'count': len(dq),
                    'window': self.window,
                    'message': f'High {proto} packet rate detected from {src or "Unknown Source"} to {dst or "Unknown Destination"} '
                               f'({len(dq)} packets in {self.window}s)'
                })
                # clear to avoid duplicate alerts immediately
                dq.clear()
        except Exception as e:
            print(f"Error in SimpleRateDetector: {e}")
        return findings

    def _determine_attack_type(self, protocol: str) -> str:
        """Determine the attack type based on the protocol."""
        if protocol == 'TCP':
            return 'syn_flood'  # General TCP flood (often SYN flood)
        elif protocol == 'UDP':
            return 'udp_flood'
        elif protocol == 'ICMP':
            return 'icmp_flood'
        else:
            return 'packet_flood'
