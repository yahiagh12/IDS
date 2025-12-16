"""Detection engine core (fixed).

Provides a small framework for detectors to analyze packet dictionaries and
emit findings. Detectors implement a simple `analyze(packet)` API.
"""
from __future__ import annotations

import threading
import logging
import json
import os
from typing import Any, Dict, List, Optional
from datetime import datetime

from ids.detection.simple_detector import SimpleRateDetector
from ids.detection.rule_engine import default_detectors
from ids.utils import config as cfg
from ids.utils.normalization import normalize_field_name, normalize_operator, is_ip_in_cidr

logger = logging.getLogger(__name__)

# Find rules.json in config folder or current directory
def get_rules_file():
    """Locate rules.json file."""
    # Try config/ folder first (after restructuring)
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "rules.json")
    if os.path.exists(config_path):
        return config_path
    # Fall back to root directory (for backward compatibility)
    root_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules.json")
    if os.path.exists(root_path):
        return root_path
    # Default to current directory
    return "rules.json"

RULES_FILE = get_rules_file()


def load_rules():
    """Load rules from the configuration file."""
    rules_file = get_rules_file()
    if not os.path.exists(rules_file):
        logger.warning(f"Rules file not found at {rules_file}")
        return []
    with open(rules_file, "r") as file:
        return json.load(file)


class DetectionEngine:
    """Manages detectors and dispatches packets to them, with rule support."""

    def __init__(self) -> None:
        self.detectors = []
        self.enabled_detectors = {}  # Maps detector class name to enabled state
        
        # register default detectors
        sr_cfg = cfg.get('simple_rate') or {}
        self.register_detector(
            SimpleRateDetector(
                window_seconds=float(sr_cfg.get('window', 0.5)),
                threshold=int(sr_cfg.get('threshold', 10))
            )
        )
        for d in default_detectors():
            self.register_detector(d)

        self.rules = load_rules()
        self.packet_queue: List[Dict[str, Any]] = []
        self._lock = threading.Lock()  # protect packet_queue
        logger.debug("DetectionEngine initialized with %d rules", len(self.rules))
        logger.info("Loaded rules: %s", self.rules)

    def register_detector(self, detector) -> None:
        self.detectors.append(detector)
        # By default, all detectors are enabled
        detector_name = detector.__class__.__name__
        self.enabled_detectors[detector_name] = True
    
    def set_detector_enabled(self, detector_name: str, enabled: bool) -> None:
        """Enable or disable a detector by class name."""
        self.enabled_detectors[detector_name] = enabled
    
    def get_enabled_detectors_map(self) -> Dict[str, bool]:
        """Get the map of detectors and their enabled states."""
        return self.enabled_detectors.copy()

    def analyze(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run all enabled detectors on the packet and collect findings.

        Each detector returns zero or more findings (dicts) describing alerts.
        """
        logger.debug("Packet received for analysis: %s", packet)
        logger.debug("Current detector states: %s", self.enabled_detectors)
        findings: List[Dict[str, Any]] = []
        for d in self.detectors:
            detector_name = d.__class__.__name__
            # Check if detector is enabled
            if not self.enabled_detectors.get(detector_name, True):
                logger.debug("Skipping disabled detector: %s", detector_name)
                continue
            
            logger.debug("Running detector: %s", detector_name)
            try:
                res = d.analyze(packet)
                if res:
                    for finding in res:
                        # Ensure all required fields are present in the finding
                        finding.setdefault('time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                        finding.setdefault('type', 'unknown')
                        finding.setdefault('attack_type', 'unknown')
                        finding.setdefault('protocol', packet.get('protocol', 'unknown'))
                        finding.setdefault('src_ip', packet.get('src_ip', 'unknown'))
                        finding.setdefault('dst_ip', packet.get('dst_ip', 'unknown'))
                        finding.setdefault('src_port', packet.get('src_port'))
                        finding.setdefault('dst_port', packet.get('dst_port'))
                        finding.setdefault('count', 0)
                        finding.setdefault('message', 'No details available')
                    findings.extend(res)
            except Exception as e:
                logger.exception('Detector %s failed: %s', d.__class__.__name__, e)
        return findings

    def _packet_matches_rule(self, packet: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Evaluate a single rule against a single packet."""
        raw_field = rule.get("field")
        operator = normalize_operator(rule.get("operator"))
        value = rule.get("value")
        field = normalize_field_name(raw_field)

        logger.debug("Evaluating rule: field=%s (raw=%s), operator=%s, value=%s", field, raw_field, operator, value)
        logger.debug("Packet keys available: %s", list(packet.keys()))
        logger.debug("Packet value for field '%s': %s", field, packet.get(field))

        pkt_value = packet.get(field)

        # handle missing packet values
        if pkt_value is None:
            logger.debug("Field '%s' not found in packet. Rule does not match.", field)
            return False

        try:
            if operator == "equals":
                match = str(pkt_value).lower() == str(value).lower()
            elif operator == "not_equals":
                match = str(pkt_value) != str(value)
            elif operator == "greater_than":
                match = float(pkt_value) > float(value)
            elif operator == "less_than":
                match = float(pkt_value) < float(value)
            elif operator == "contains":
                match = str(value) in str(pkt_value)
            elif operator == "cidr":
                match = is_ip_in_cidr(str(pkt_value), str(value))
            elif operator == "in_list":
                # Split the value string by comma to get list of allowed values
                allowed_values = [v.strip() for v in str(value).split(',')]
                match = str(pkt_value) in allowed_values
            else:
                logger.debug("Unknown operator '%s'. Rule does not match.", operator)
                return False

            logger.debug("Rule match result: %s (comparing '%s' with '%s')", match, pkt_value, value)
            return match
        except Exception as e:
            logger.exception("Error evaluating rule: %s", e)
            return False

    def apply_rules(self):
        """Apply loaded rules to all packets currently in the queue.

        NOTE: Prefer calling rules on each packet as it arrives (see analyze_packet).
        This method will examine the queue and mark / drop / log items according to rules.
        """
        logger.info("Applying %d rules to %d queued packets", len(self.rules), len(self.packet_queue))

        with self._lock:
            # build new queue of packets that survive 'Drop Packet'
            new_queue = []
            for packet in list(self.packet_queue):
                dropped = False
                for rule in self.rules:
                    try:
                        if self._packet_matches_rule(packet, rule):
                            action = rule.get("action", "").strip()
                            logger.info("Rule '%s' matched packet %s -> action=%s", rule.get("operation_name") or rule.get("field"), packet, action)
                            if action.lower() == "drop packet" or action.lower() == "drop":
                                dropped = True
                                break
                            if action.lower() == "log":
                                packet.setdefault("log", True)
                            if action.lower() == "alert":
                                # set a flag and also emit immediate alert log
                                packet.setdefault("alert", True)
                                logger.warning("Alert triggered by rule '%s' for packet: %s", rule.get("operation_name"), packet)
                    except Exception as e:
                        logger.exception("Failed to evaluate rule %s on packet %s: %s", rule, packet, e)
                if not dropped:
                    new_queue.append(packet)
                else:
                    logger.info("Packet dropped by rule: %s", packet)
            # replace queue atomically
            self.packet_queue = new_queue

    def reload_rules(self):
        """Reload rules from the configuration file and apply them."""
        self.rules = load_rules()
        self.apply_rules()

    def _map_rule_to_attack_type(self, rule: Dict[str, Any], packet: Dict[str, Any]) -> str:
        """Map a rule to a specific attack type name."""
        rule_name = rule.get("name", "").lower()
        field = rule.get("field", "").lower()
        operator = rule.get("operator", "").lower()
        protocol = packet.get('protocol', '').upper()
        
        # Map rule names to attack types
        if 'large' in rule_name and 'packet' in rule_name:
            if '5000' in rule_name or '3000' in rule_name:
                return 'large_packet_flood'
        if 'arp' in rule_name:
            return 'arp_spoof'
        if 'tls' in rule_name or 'https' in rule_name:
            return 'tls_traffic_alert'
        if 'dns' in rule_name or 'name' in rule_name:
            return 'dns_anomaly'
        if 'external' in rule_name or 'cidr' in operator or 'blocked' in rule_name:
            return 'external_ip_access'
        if 'small' in rule_name and 'packet' in rule_name:
            return 'small_packet_anomaly'
        if protocol == 'UDP':
            return 'udp_flood'
        if protocol == 'TCP':
            return 'tcp_flood'
        
        return 'rule_match'

    def _apply_rules_to_packet(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Apply rules to a single packet. Return packet if it should be kept, or None if dropped.

        This is used on ingress to make rules affect newly received packets immediately.
        Also returns a list of findings generated by rule matches.
        """
        findings = []
        should_drop = False
        
        for rule in self.rules:
            try:
                if self._packet_matches_rule(packet, rule):
                    action = rule.get("action", "").strip().lower()
                    logger.info("Rule matched: %s -> Action: %s", rule, action)
                    
                    # Generate a finding for rule matches with specific attack type
                    rule_name = rule.get("name", "Unknown Rule")
                    attack_type = self._map_rule_to_attack_type(rule, packet)
                    
                    finding = {
                        'type': 'rule_match',
                        'attack_type': attack_type,
                        'message': f"{attack_type.replace('_', ' ').title()}: {rule_name}",
                        'rule_name': rule_name,
                        'protocol': packet.get('protocol', 'unknown'),
                        'src_ip': packet.get('src_ip', 'unknown'),
                        'dst_ip': packet.get('dst_ip', 'unknown'),
                        'length': packet.get('length', 0),
                        'action': action.title() if action else "Alert",  # Convert to title case
                    }
                    findings.append(finding)
                    
                    if action in ("drop packet", "drop"):
                        logger.info("Dropping packet due to rule: %s", rule)
                        should_drop = True
                        # Don't break - we still want to collect all findings
                    elif action == "log":
                        packet.setdefault("log", True)
                    elif action == "alert":
                        packet.setdefault("alert", True)
                        logger.warning("Immediate alert for packet: %s (rule: %s)", packet, rule)
            except Exception as e:
                logger.exception("Error applying rule %s to packet %s", rule, packet)
        
        # Store the findings generated by rules in the packet
        if findings:
            packet.setdefault("rule_findings", []).extend(findings)
        
        # Return None if should drop, otherwise return packet
        if should_drop:
            return None
        
        return packet

    def analyze_packet(self, packet: Dict[str, Any]):
        """Analyze a single packet and add it to the queue.

        Rules are applied on ingress; a 'Drop Packet' rule will prevent the packet
        from being queued or analyzed by detectors.
        """
        # Apply rules to incoming packet immediately
        packet_after_rules = self._apply_rules_to_packet(packet)
        if packet_after_rules is None:
            # packet dropped by rule
            return

        with self._lock:
            self.packet_queue.append(packet_after_rules)

        # Run detectors and report findings
        findings = self.analyze(packet_after_rules)
        for finding in findings:
            # if a rule wanted the packet to be logged/flagged, include it in findings
            if packet_after_rules.get("log"):
                finding.setdefault("logged_by_rule", True)
            if packet_after_rules.get("alert"):
                finding.setdefault("alerted_by_rule", True)
            logger.info("Finding: %s", finding)

    def process_packets(self, packets: List[Dict[str, Any]]):
        """Process a list of packets."""
        for packet in packets:
            try:
                self.analyze_packet(packet)
            except Exception as e:
                logger.exception("Failed to process packet %s: %s", packet, e)
