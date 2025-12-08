"""Basic ARP spoofing detector placeholder.

This detector looks for rapid changes in mapping between IP and MAC seen on
the network — implemented as a simple learning table for demonstration.
"""
from __future__ import annotations

from typing import Dict, Any, List
from collections import defaultdict


class ArpSpoofDetector:
    def __init__(self):
        self._mapping = defaultdict(set)

    def analyze(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        proto = (packet.get('protocol') or '').upper()
        if proto != 'ARP':
            return findings

        raw = packet.get('_raw', {})
        ip = raw.get('arp_psrc') or raw.get('sender_ip') or raw.get('arp_ip')
        mac = raw.get('arp_hwsrc') or raw.get('sender_mac') or raw.get('hwsrc')
        if not ip or not mac:
            return findings

        macs = self._mapping[ip]
        if macs and mac not in macs:
            findings.append({
                'type': 'arp_spoof',
                'attack_type': 'arp_spoof',
                'protocol': 'ARP',
                'src_ip': ip,
                'new_mac': mac,
                'old_macs': list(macs),
                'message': f'IP {ip} now seen from new MAC {mac} (previous: {list(macs)})'
            })
            macs.add(mac)
        else:
            macs.add(mac)

        return findings
