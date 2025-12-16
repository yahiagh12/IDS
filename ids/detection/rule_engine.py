"""Rule engine to manage rule-based detectors and rules.

This is a simple registry that allows loading detectors by name and
providing a single entrypoint used by the detection engine if desired.
"""
from typing import List

from ids.detection.syn_flood_detector import SynFloodDetector
from ids.detection.udp_flood_detector import UdpFloodDetector
from ids.detection.arp_spoof_detector import ArpSpoofDetector
from ids.detection.xmas_null_scan_detector import XmasNullScanDetector
from ids.utils import config as cfg


def default_detectors() -> List:
    # read configured windows/thresholds for syn/udp
    syn_cfg = cfg.get('syn_flood') or {}
    udp_cfg = cfg.get('udp_flood') or {}

    return [
        SynFloodDetector(window_seconds=float(syn_cfg.get('window', 0.5)), threshold=int(syn_cfg.get('threshold', 10))),
        UdpFloodDetector(window_seconds=float(udp_cfg.get('window', 0.5)), threshold=int(udp_cfg.get('threshold', 10))),
        ArpSpoofDetector(),
        XmasNullScanDetector(),
    ]
