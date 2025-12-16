"""Detect XMAS and NULL scans by TCP flags.

XMAS: FIN/PSH/URG set. NULL: no flags set.
"""
from __future__ import annotations

from typing import Dict, Any, List
from collections import defaultdict
import time


class XmasNullScanDetector:
    def __init__(self):
        self._scan_history = defaultdict(list)
        self.window = 5  # Track scans within 5 seconds

    def analyze(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        proto = (packet.get('protocol') or '').upper()
        if proto != 'TCP':
            return findings

        src_ip = packet.get('src_ip')
        if not src_ip:
            return findings

        # Try to determine TCP flags from packet summary or raw data
        tcp_flags = self._extract_tcp_flags(packet)
        
        if tcp_flags is None:
            return findings
        
        # Detect XMAS scan (FIN=1, PSH=1, URG=1)
        is_xmas = all([
            tcp_flags.get('FIN', False),
            tcp_flags.get('PSH', False),
            tcp_flags.get('URG', False)
        ])
        
        # Detect NULL scan (no flags set)
        is_null = not any(tcp_flags.values())
        
        if is_xmas or is_null:
            scan_type = 'xmas_scan' if is_xmas else 'null_scan'
            dst_ip = packet.get('dst_ip')
            
            # Track this scan
            now = time.time()
            self._scan_history[src_ip].append({
                'type': scan_type,
                'time': now,
                'dst_ip': dst_ip
            })
            
            # Clean old entries
            self._scan_history[src_ip] = [
                s for s in self._scan_history[src_ip]
                if now - s['time'] < self.window
            ]
            
            findings.append({
                'type': scan_type,
                'attack_type': scan_type,
                'protocol': 'TCP',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'tcp_flags': tcp_flags,
                'message': f'{scan_type.replace("_", " ").upper()} detected from {src_ip} to {dst_ip}'
            })
        
        return findings

    def _extract_tcp_flags(self, packet: Dict[str, Any]) -> Dict[str, bool]:
        """Extract TCP flags from packet."""
        tcp_flags = {
            'SYN': False, 'ACK': False, 'FIN': False,
            'RST': False, 'PSH': False, 'URG': False
        }
        
        # Try to extract from summary string if available
        summary = packet.get('summary', '').upper()
        if 'SYN' in summary:
            tcp_flags['SYN'] = True
        if 'ACK' in summary:
            tcp_flags['ACK'] = True
        if 'FIN' in summary:
            tcp_flags['FIN'] = True
        if 'RST' in summary:
            tcp_flags['RST'] = True
        if 'PSH' in summary:
            tcp_flags['PSH'] = True
        if 'URG' in summary:
            tcp_flags['URG'] = True
        
        # Check raw packet data if available
        raw = packet.get('_raw', {})
        if raw:
            if 'flags' in raw:
                flags = raw['flags']
                tcp_flags['SYN'] = bool(flags & 0x02)
                tcp_flags['ACK'] = bool(flags & 0x10)
                tcp_flags['FIN'] = bool(flags & 0x01)
                tcp_flags['RST'] = bool(flags & 0x04)
                tcp_flags['PSH'] = bool(flags & 0x08)
                tcp_flags['URG'] = bool(flags & 0x20)
        
        return tcp_flags
