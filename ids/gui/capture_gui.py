#!/usr/bin/env python3
"""Unified IDS GUI with IPv4 and IPv6 Detection.

This module provides `run()` which launches the Tk GUI with merged functionality
from both capture_gui (IPv4) and capture_gui_adv (IPv6).
Supports both legacy IPv4 detection and advanced IPv6 analysis.
"""

import os
import sys
import signal
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
import logging
from collections import defaultdict
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from ids.capture.live_listener import LiveListener
from ids.detection.engine import DetectionEngine
from ids.traffic_analyser import TrafficAnalyzer
from ids.detection_ipv6 import IPv6AttackDetector
from ids.gui.ui_helpers import (
    create_treeview_with_scrollbar, get_finding_color, apply_row_color,
    show_error, show_info
)
from ids.gui.rules_manager import (
    load_rules_from_file, save_rules_to_file, validate_rule,
    AVAILABLE_FIELDS, AVAILABLE_OPERATORS, AVAILABLE_ACTIONS
)

logger = logging.getLogger(__name__)


# Add the project root directory to PYTHONPATH
def _add_project_root_to_path():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

_add_project_root_to_path()


class UnifiedCaptureGUI:
    """Unified IDS GUI supporting both IPv4 (Legacy) and IPv6 (Advanced) Detection."""
    
    # Color schemes
    PROTO_COLORS = {
        "arp": "#3498db",      # Blue
        "icmp": "#2ecc71",     # Green
        "dns": "#9b59b6",      # Purple
        "ipv6": "#e74c3c",     # Red
        "tcp": "#e67e22",      # Orange
        "udp": "#95a5a6",      # Gray
        "alert": "#c0392b",    # Dark Red
        "other": "#2c3e50"     # Dark Gray
    }

    ATTACK_COLORS = {
        "SYN Scan": "#e67e22",
        "SYN Flood": "#c0392b",
        "XMAS Scan": "#8e44ad",
        "NULL Scan": "#7f8c8d",
        "UDP Flood": "#2980b9",
        "ICMP Flood": "#27ae60",
        "ARP Flood": "#a93226",
        "ARP Spoofing": "#c2185b",
        "DNS Flood": "#0097a7"
    }

    ATTACK_DESCRIPTIONS = {
        "SYN Scan": "Port scanning technique using SYN packets to identify open ports",
        "SYN Flood": "Denial of Service attack flooding target with SYN packets",
        "XMAS Scan": "Stealth scanning method using FIN+PSH+URG flags",
        "NULL Scan": "Stealth port scan using packets with no flags set",
        "UDP Flood": "DDoS attack overwhelming target with UDP packets",
        "ICMP Flood": "Denial of Service via high-volume ICMP echo requests",
        "ARP Flood": "Network saturation attack through ARP packet flooding",
        "ARP Spoofing": "Man-in-the-middle attack impersonating network devices",
        "DNS Flood": "DNS query flooding attack causing service degradation"
    }

    def __init__(self, root):
        self.root = root
        root.title("IDS Advanced - Unified Network Threat Detection System (IPv4 & IPv6)")
        root.geometry("1600x950")
        root.configure(bg="#ecf0f1")
        
        self.listener = None
        self.detection_engine = DetectionEngine()
        
        # ===== IPv4 DETECTION SYSTEM =====
        # Grouping system for IPv4 detections
        self.detection_groups = {}  # Maps group_key -> {data, count, timestamps, item_id}
        
        # ===== IPv6 DETECTION SYSTEM (ADVANCED) =====
        self.ipv6_detector = IPv6AttackDetector()
        self.analyzer = TrafficAnalyzer()
        
        # Statistics for advanced analytics
        self.packet_count = 0
        self.alert_count = 0
        self.protocol_counts = defaultdict(int)
        self.attack_counts = defaultdict(int)
        self.attack_timeline = defaultdict(int)
        self.attacker_ips = defaultdict(int)
        self.behavioral_anomalies = []
        
        # Configuration
        self.is_paused = False
        self.filter_protocols = {"arp", "icmp", "dns", "ipv6", "tcp", "udp"}
        self.log_file = "logs.txt"
        
        # Create notebook with advanced styling
        self.tab_control = ttk.Notebook(root)
        
        # Build tabs
        self.capture_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.capture_tab, text="📝 Live Capture")
        
        self.detections_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.detections_tab, text="🛡️  Detections")
        
        self.alerts_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.alerts_tab, text="⚠️  Security Alerts")
        
        self.settings_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.settings_tab, text="⚙️  Settings")
        
        self.rules_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.rules_tab, text="📋 Custom Rules")
        
        self.stats_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.stats_tab, text="📊 Statistics")
        
        self.baseline_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.baseline_tab, text="📈 Traffic Baseline")
        
        self.analytics_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.analytics_tab, text="🔍 Advanced Analytics")
        
        self.tab_control.pack(expand=1, fill='both')
        
        # Build individual tabs
        self._build_capture_tab()
        self._build_detections_tab()
        self._build_alerts_tab()
        self._build_settings_tab()
        self._build_rules_tab()
        self._build_stats_tab()
        self._build_baseline_tab()
        self._build_analytics_tab()
        
        # Refresh interfaces
        self.refresh_interfaces()

    # ========== CAPTURE TAB ==========
    def _build_capture_tab(self):
        """Build the packet capture tab with IPv4/IPv6 support."""
        # Professional header frame
        header_frame = tk.Frame(self.capture_tab, bg="#34495e", height=80)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        
        header_label = tk.Label(
            header_frame,
            text="🌐 NETWORK PACKET CAPTURE & MONITORING (IPv4 & IPv6)",
            font=("Arial", 12, "bold"),
            bg="#34495e", fg="white", pady=10
        )
        header_label.pack(fill=tk.X)
        
        info_label = tk.Label(
            header_frame,
            text="Real-time packet capture with dual-stack IPv4 and IPv6 threat detection",
            font=("Arial", 9), fg="#bdc3c7", bg="#34495e"
        )
        info_label.pack(anchor=tk.W, padx=15)
        
        # Configuration frame
        config_frame = tk.Frame(self.capture_tab, bg="#ecf0f1")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(config_frame, text="Interface:", font=("Arial", 10, "bold"), bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        
        self.iface_var = tk.StringVar(value="lo")
        self.iface_combo = ttk.Combobox(config_frame, textvariable=self.iface_var, state="readonly", width=20)
        self.iface_combo.pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        tk.Button(config_frame, text="▶ Start", command=self.start_capture, 
                 bg="#27ae60", fg="white", padx=10).pack(side=tk.LEFT, padx=5)
        tk.Button(config_frame, text="⏹ Stop", command=self.stop_capture,
                 bg="#c0392b", fg="white", padx=10).pack(side=tk.LEFT, padx=2)
        tk.Button(config_frame, text="⏸ Pause", command=self.pause_capture,
                 bg="#f39c12", fg="white", padx=10).pack(side=tk.LEFT, padx=2)
        tk.Button(config_frame, text="⏯ Resume", command=self.resume_capture,
                 bg="#3498db", fg="white", padx=10).pack(side=tk.LEFT, padx=2)
        
        # Protocol filtering
        protocol_frame = tk.Frame(self.capture_tab, bg="#ecf0f1")
        protocol_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(protocol_frame, text="Monitor Protocols:", font=("Arial", 10, "bold"), bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        
        self.protocol_vars = {}
        protocols = ["ARP", "ICMP", "DNS", "IPv6", "TCP", "UDP"]
        for proto in protocols:
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(protocol_frame, text=proto, variable=var, 
                               command=self._update_filter, bg="#ecf0f1")
            cb.pack(side=tk.LEFT, padx=3)
            self.protocol_vars[proto.lower()] = var
        
        # Attack scanner checkboxes
        self.detector_name_map = {
            "ARP Spoof": "ArpSpoofDetector",
            "SYN Flood": "SynFloodDetector",
            "UDP Flood": "UdpFloodDetector",
            "XMAS Scan": "XmasNullScanDetector",
            "Null Scan": "XmasNullScanDetector",
            "Rate Detection": "SimpleRateDetector"
        }
        
        # Create a frame for detector checkboxes in one horizontal line
        detector_frame = tk.Frame(self.capture_tab, bg="#ecf0f1")
        detector_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(detector_frame, text="Enable IPv4 Detectors:", font=("Arial", 10, "bold"), bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        
        self.attack_scanners = {}
        attacks = ["ARP Spoof", "SYN Flood", "UDP Flood", "XMAS Scan", "Null Scan", "Rate Detection"]
        for col, attack in enumerate(attacks):
            var = tk.BooleanVar(value=True)
            callback = lambda varname, index, mode, attack_name=attack: self._on_detector_checkbox_changed(attack_name)
            var.trace_add("write", callback)
            chk = ttk.Checkbutton(detector_frame, text=attack, variable=var)
            chk.pack(side=tk.LEFT, padx=5)
            self.attack_scanners[attack] = var

        # Packet list with border
        list_frame = tk.Frame(self.capture_tab, bg="#34495e", bd=1, relief=tk.SUNKEN)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        list_label = tk.Label(list_frame, text="Captured Packets (Real-time Log)", 
                             font=("Arial", 10, "bold"), bg="#34495e", fg="white", pady=5)
        list_label.pack(fill=tk.X)
        
        self.packet_list = scrolledtext.ScrolledText(list_frame, width=150, height=25,
                                                      bg="#2c3e50", fg="#ecf0f1", font=("Courier", 9))
        self.packet_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tag colors for packets
        for proto, color in self.PROTO_COLORS.items():
            self.packet_list.tag_config(proto, foreground=color)

    # ========== DETECTIONS TAB (IPv4) ==========
    def _build_detections_tab(self):
        """Build the IPv4 detections display tab."""
        # Professional header
        alert_header = tk.Label(self.detections_tab,
                               text="🛡️  IPv4 DETECTIONS - GROUPED THREAT ANALYSIS",
                               font=("Arial", 12, "bold"),
                               bg="#3498db", fg="white", pady=10)
        alert_header.pack(fill=tk.X)
        
        info_text = tk.Label(self.detections_tab,
                            text="Real-time detection of IPv4 network attacks: Port Scans, Floods, Spoofing",
                            font=("Arial", 9), fg="#7f8c8d", bg="#ecf0f1")
        info_text.pack(anchor=tk.W, padx=15, pady=5)

        # Header with controls
        header_frame = ttk.Frame(self.detections_tab)
        header_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(header_frame, text="IPv4 Detections:", font=("Arial", 11, "bold")).pack(side="left", anchor="w")
        
        ttk.Button(header_frame, text="🗑️  Delete", width=12, command=self._delete_detection).pack(side="right", padx=5)
        ttk.Button(header_frame, text="Clear All", width=12, command=self._clear_all_detections).pack(side="right", padx=2)

        # Detection tree
        columns = ("Time", "Type", "Protocol", "Source IP", "Destination IP", "Count", "Details")
        column_definitions = [
            ("Time", 150, "Time"),
            ("Type", 150, "Attack Type"),
            ("Protocol", 100, "Protocol"),
            ("Source IP", 150, "Source IP"),
            ("Destination IP", 150, "Destination IP"),
            ("Count", 100, "Packet Count"),
            ("Details", 300, "Details")
        ]

        self.detections_tree, scrollbar = create_treeview_with_scrollbar(
            self.detections_tab, columns, column_definitions
        )
        
        self.detections_tree.pack(fill="both", expand=True, padx=10, pady=5)
        scrollbar.pack(side="right", fill="y")

        self.detections_tree.bind("<Double-1>", self._on_detection_double_click)
        self.detections_tree.bind("<Delete>", self._on_delete_key)

    # ========== ALERTS TAB (IPv6 ADVANCED) ==========
    def _build_alerts_tab(self):
        """Build the IPv6 advanced alerts tab with security threats."""
        # Professional header
        alert_header = tk.Label(self.alerts_tab,
                               text="⚠️  IPv6 SECURITY ALERTS - ADVANCED THREAT DETECTION",
                               font=("Arial", 12, "bold"),
                               bg="#c0392b", fg="white", pady=10)
        alert_header.pack(fill=tk.X)
        
        info_text = tk.Label(self.alerts_tab,
                            text="Advanced IPv6 threat detection: DDoS Floods, Port Scans, ARP Spoofing, DNS Anomalies",
                            font=("Arial", 9), fg="#7f8c8d", bg="#ecf0f1")
        info_text.pack(anchor=tk.W, padx=15, pady=5)
        
        # Alert area with formatted display
        alert_frame = tk.Frame(self.alerts_tab, bg="#ecf0f1")
        alert_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.alert_area = scrolledtext.ScrolledText(alert_frame, 
                                                     width=170, height=30,
                                                     bg="#2c3e50", fg="#ecf0f1",
                                                     font=("Courier", 9))
        self.alert_area.pack(fill=tk.BOTH, expand=True)
        
        # Tag colors for alerts
        self.alert_area.tag_config("alert", foreground="#c0392b", font=("Courier", 9, "bold"))
        self.alert_area.tag_config("warning", foreground="#f39c12")
        
        # Control buttons
        btn_frame = tk.Frame(self.alerts_tab, bg="#ecf0f1")
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(btn_frame, text="🧹 Clear Alerts", command=self._clear_alerts,
                 bg="#95a5a6", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="💾 Export Alerts", command=self._export_alerts,
                 bg="#3498db", fg="white").pack(side=tk.LEFT, padx=5)

    # ========== SETTINGS TAB ==========
    def _build_settings_tab(self):
        """Build the settings tab with professional layout."""
        from ids.utils import config as cfg
        
        # Header
        header_label = tk.Label(self.settings_tab, 
                               text="⚙️  DETECTION CONFIGURATION & THRESHOLDS",
                               font=("Arial", 12, "bold"),
                               bg="#34495e", fg="white", pady=10)
        header_label.pack(fill=tk.X)
        
        info_text = ttk.Label(self.settings_tab, text="Adjust detection thresholds. Changes take effect immediately.",
                             font=("Arial", 9), foreground="gray")
        info_text.pack(anchor="w", padx=10, pady=5)

        # Scrollable frame
        canvas = tk.Canvas(self.settings_tab, bg="#ecf0f1")
        scrollbar = ttk.Scrollbar(self.settings_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        self.attack_settings = {}
        
        # SYN Flood
        syn_cfg = cfg.get('syn_flood') or {}
        frame = ttk.LabelFrame(scrollable_frame, text="SYN Flood Detection", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="Time Window (seconds):").grid(row=0, column=0, sticky="w", pady=5)
        syn_window_var = tk.DoubleVar(value=float(syn_cfg.get('window', 0.5)))
        ttk.Entry(frame, textvariable=syn_window_var, width=10).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(Detection window in seconds)", font=("Arial", 8), foreground="gray").grid(row=0, column=2, sticky="w")
        
        ttk.Label(frame, text="Packet Threshold:").grid(row=1, column=0, sticky="w", pady=5)
        syn_threshold_var = tk.IntVar(value=int(syn_cfg.get('threshold', 50)))
        ttk.Entry(frame, textvariable=syn_threshold_var, width=10).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(TCP packets per window)", font=("Arial", 8), foreground="gray").grid(row=1, column=2, sticky="w")
        
        self.attack_settings["syn_flood"] = {"window": syn_window_var, "threshold": syn_threshold_var}

        # UDP Flood
        udp_cfg = cfg.get('udp_flood') or {}
        frame = ttk.LabelFrame(scrollable_frame, text="UDP Flood Detection", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="Time Window (seconds):").grid(row=0, column=0, sticky="w", pady=5)
        udp_window_var = tk.DoubleVar(value=float(udp_cfg.get('window', 0.5)))
        ttk.Entry(frame, textvariable=udp_window_var, width=10).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(Detection window in seconds)", font=("Arial", 8), foreground="gray").grid(row=0, column=2, sticky="w")
        
        ttk.Label(frame, text="Packet Threshold:").grid(row=1, column=0, sticky="w", pady=5)
        udp_threshold_var = tk.IntVar(value=int(udp_cfg.get('threshold', 50)))
        ttk.Entry(frame, textvariable=udp_threshold_var, width=10).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(UDP packets per window)", font=("Arial", 8), foreground="gray").grid(row=1, column=2, sticky="w")
        
        self.attack_settings["udp_flood"] = {"window": udp_window_var, "threshold": udp_threshold_var}

        # Generic Rate Detection
        simple_cfg = cfg.get('simple_rate') or {}
        frame = ttk.LabelFrame(scrollable_frame, text="Generic Rate Detection (Fallback)", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="Time Window (seconds):").grid(row=0, column=0, sticky="w", pady=5)
        simple_window_var = tk.DoubleVar(value=float(simple_cfg.get('window', 0.5)))
        ttk.Entry(frame, textvariable=simple_window_var, width=10).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(For all other protocols)", font=("Arial", 8), foreground="gray").grid(row=0, column=2, sticky="w")
        
        ttk.Label(frame, text="Packet Threshold:").grid(row=1, column=0, sticky="w", pady=5)
        simple_threshold_var = tk.IntVar(value=int(simple_cfg.get('threshold', 10)))
        ttk.Entry(frame, textvariable=simple_threshold_var, width=10).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="(Packets per window)", font=("Arial", 8), foreground="gray").grid(row=1, column=2, sticky="w")
        
        self.attack_settings["simple_rate"] = {"window": simple_window_var, "threshold": simple_threshold_var}

        # Fixed detection methods
        frame = ttk.LabelFrame(scrollable_frame, text="Fixed Detection Methods", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        
        info = """ARP Spoofing: Detected when same IP seen from different MAC
XMAS Scan: Detected when TCP flags are FIN+PSH+URG
NULL Scan: Detected when TCP packet has no flags set
Port Scan: Configured via Custom Rules tab
Large Packet: Detected when packet > 3000 bytes
External Access: Blocked CIDR ranges (configurable in rules)
DNS Anomaly: Detected from known DNS IPs (configurable in rules)"""
        
        ttk.Label(frame, text=info, font=("Arial", 8), justify="left").pack(anchor="w", padx=5, pady=5)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Button frame
        btn_frame = ttk.Frame(self.settings_tab)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(btn_frame, text="💾 Save Settings", command=self.save_settings).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🔄 Reset to Defaults", command=self.reset_settings).pack(side="left", padx=5)

    # ========== RULES TAB ==========
    def _build_rules_tab(self):
        """Build the custom rules tab."""
        # Header
        header_label = tk.Label(self.rules_tab,
                               text="📋 MANAGE CUSTOM DETECTION RULES",
                               font=("Arial", 12, "bold"),
                               bg="#34495e", fg="white", pady=10)
        header_label.pack(fill=tk.X)
        
        info_text = ttk.Label(self.rules_tab, text="Create and manage custom packet detection rules",
                             font=("Arial", 9), foreground="gray")
        info_text.pack(anchor="w", padx=10, pady=5)

        # Rules tree
        self.rules_tree = ttk.Treeview(
            self.rules_tab,
            columns=("Name", "Field", "Operator", "Value", "Action"),
            show="headings"
        )
        
        for col, width in [("Name", 200), ("Field", 150), ("Operator", 150), ("Value", 150), ("Action", 150)]:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=width, anchor="center")

        self.rules_tree.pack(fill="both", expand=True, padx=10, pady=5)

        # Rule management buttons
        btn_frame = ttk.Frame(self.rules_tab)
        btn_frame.pack(fill="x", pady=10, padx=10)

        ttk.Button(btn_frame, text="➕ Add Rule", command=self._add_rule).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="✏️  Edit Rule", command=self._edit_rule).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="❌ Delete Rule", command=self._delete_rule).pack(side="left", padx=5)

        self._load_rules()

    # ========== STATISTICS TAB ==========
    def _build_stats_tab(self):
        """Build the statistics tab with graphs."""
        # Header
        stats_frame = tk.Frame(self.stats_tab, bg="#34495e")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        header_label = tk.Label(stats_frame,
                               text="📈 NETWORK TRAFFIC ANALYSIS & STATISTICS",
                               font=("Arial", 12, "bold"),
                               bg="#34495e", fg="white", pady=10)
        header_label.pack(fill=tk.X)
        
        # Stats boxes
        stats_box = tk.Frame(stats_frame, bg="#ecf0f1")
        stats_box.pack(fill=tk.X, padx=5, pady=5)
        
        self.packet_label = tk.Label(stats_box, text="📦 Total Packets: 0",
                                    font=("Arial", 11, "bold"), bg="#ecf0f1")
        self.packet_label.pack(side=tk.LEFT, padx=15)
        
        self.alert_label = tk.Label(stats_box, text="⚠️  Security Alerts: 0",
                                   font=("Arial", 11, "bold"), bg="#ecf0f1", fg="#c0392b")
        self.alert_label.pack(side=tk.LEFT, padx=15)

        # Graph
        self.fig, self.ax = plt.subplots(figsize=(7, 4))
        self.ax.set_title("Network Traffic Distribution")
        self.ax.set_ylabel("Packet Count")
        self.fig.patch.set_facecolor("#ecf0f1")
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.stats_tab)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # ========== BASELINE TAB ==========
    def _build_baseline_tab(self):
        """Build the traffic baseline tab."""
        header_label = tk.Label(self.baseline_tab,
                               text="📋 TRAFFIC BASELINE ANALYSIS",
                               font=("Arial", 12, "bold"),
                               bg="#34495e", fg="white", pady=10)
        header_label.pack(fill=tk.X)
        
        self.baseline_area = scrolledtext.ScrolledText(self.baseline_tab, width=170, height=30,
                                                       bg="#2c3e50", fg="#ecf0f1", font=("Courier", 9))
        self.baseline_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for proto, color in self.PROTO_COLORS.items():
            self.baseline_area.tag_config(proto, foreground=color)

    # ========== ANALYTICS TAB (IPv6 ADVANCED) ==========
    def _build_analytics_tab(self):
        """Build the advanced analytics tab for IPv6 analysis."""
        header_label = tk.Label(self.analytics_tab,
                               text="🔍 ADVANCED ANALYTICS - IPv6 Attack Analysis",
                               font=("Arial", 12, "bold"),
                               bg="#34495e", fg="white", pady=10)
        header_label.pack(fill=tk.X)
        
        # Graph for attack distribution
        self.fig_analytics, self.ax_analytics = plt.subplots(figsize=(10, 4))
        self.ax_analytics.set_title("Attack Distribution by Type")
        self.ax_analytics.set_ylabel("Count")
        self.fig_analytics.patch.set_facecolor("#ecf0f1")
        self.canvas_analytics = FigureCanvasTkAgg(self.fig_analytics, master=self.analytics_tab)
        self.canvas_analytics.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # ========== HELPER METHODS ==========
    def _update_filter(self):
        """Update protocol filter based on checkboxes."""
        self.filter_protocols = set()
        for proto, var in self.protocol_vars.items():
            if var.get():
                self.filter_protocols.add(proto)

    def _on_detection_double_click(self, event):
        """Handle double-click on detection row to show grouped details."""
        try:
            selected_item = self.detections_tree.selection()[0]
            
            group_data = None
            for group_key, data in self.detection_groups.items():
                if data['item_id'] == selected_item:
                    group_data = data
                    break
            
            if not group_data:
                messagebox.showwarning("Error", "Could not find details for this detection.")
                return
            
            # Create a custom Toplevel window
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Detection Details - {group_data['attack_type']}")
            details_window.geometry("750x650")
            details_window.resizable(True, True)
            
            main_frame = ttk.Frame(details_window, padding="15")
            main_frame.pack(fill="both", expand=True)
            
            title_label = ttk.Label(main_frame, text="Grouped Detection Details",
                                   font=("Arial", 14, "bold"))
            title_label.pack(anchor="w", pady=(0, 15))
            
            text_frame = ttk.Frame(main_frame)
            text_frame.pack(fill="both", expand=True)
            
            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side="right", fill="y")
            
            text_widget = tk.Text(text_frame, height=28, width=90, wrap="word",
                                 yscrollcommand=scrollbar.set, font=("Courier", 10))
            text_widget.pack(side="left", fill="both", expand=True)
            scrollbar.config(command=text_widget.yview)
            
            content = self._format_detection_details(group_data)
            text_widget.insert("1.0", content)
            text_widget.config(state="disabled")
            
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill="x", pady=(10, 0))
            
            ttk.Button(button_frame, text="Close", command=details_window.destroy).pack(side="right")
            ttk.Button(button_frame, text="Copy Details",
                      command=lambda: self._copy_to_clipboard(content)).pack(side="right", padx=5)
            
        except IndexError:
            messagebox.showwarning("No Selection", "Please select a detection to view details.")
    
    def _format_detection_details(self, group_data):
        """Format detection details for display."""
        timestamps_str = "\n".join(f"  {i+1}. {ts}" for i, ts in enumerate(group_data['timestamps'][-20:]))
        
        content = f"""═══════════════════════════════════════════════════════════════════
                      DETECTION GROUP DETAILS
═══════════════════════════════════════════════════════════════════

━━━ ATTACK INFORMATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attack Type:              {group_data['attack_type']}
Protocol:                 {group_data['protocol']}
Source IP:                {group_data['src_ip']}
Destination IP:           {group_data['dst_ip']}

━━━ GROUPING STATISTICS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Packets Grouped:    {group_data['count']}
First Detected:           {group_data['first_time']}
Last Detected:            {group_data['last_time']}

━━━ RECENT DETECTION TIMESTAMPS (Last {len(group_data['timestamps'])} Events) ━━━
{timestamps_str}

━━━ ATTACK MESSAGE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{group_data['finding'].get('message', 'No details available')}

━━━ ADDITIONAL INFORMATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action:                   {group_data.get('action', 'ALERT').upper() if group_data.get('action') else 'ALERT'}

═══════════════════════════════════════════════════════════════════"""
        return content
    
    def _copy_to_clipboard(self, text):
        """Copy text to clipboard."""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Success", "Details copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")

    def _on_delete_key(self, event):
        """Handle Delete key press on detection tree."""
        self._delete_detection()

    def _delete_detection(self):
        """Delete selected detection(s) from the tree."""
        selected_items = self.detections_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a detection to delete.")
            return
        
        for item in selected_items:
            for group_key, group_data in list(self.detection_groups.items()):
                if group_data['item_id'] == item:
                    del self.detection_groups[group_key]
                    break
            
            self.detections_tree.delete(item)

    def _clear_all_detections(self):
        """Clear all detections from the tree."""
        if messagebox.askyesno("Clear All", "Are you sure you want to clear all detections?"):
            self.detection_groups.clear()
            for item in self.detections_tree.get_children():
                self.detections_tree.delete(item)

    def _clear_alerts(self):
        """Clear all alerts from the alert area."""
        if messagebox.askyesno("Clear Alerts", "Are you sure you want to clear all alerts?"):
            self.alert_area.config(state="normal")
            self.alert_area.delete("1.0", tk.END)
            self.alert_area.config(state="disabled")

    def _export_alerts(self):
        """Export alerts to file."""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.alert_area.get("1.0", tk.END))
                messagebox.showinfo("Success", f"Alerts exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export alerts: {e}")

    def _on_detector_checkbox_changed(self, attack_name):
        """Callback when a detector checkbox is changed."""
        detector_class_name = self.detector_name_map.get(attack_name)
        if not detector_class_name:
            return
        
        is_enabled = self.attack_scanners[attack_name].get()
        self.detection_engine.set_detector_enabled(detector_class_name, is_enabled)
        status = "enabled" if is_enabled else "disabled"
        self.packet_list.insert("end", f"[INFO] Detector '{attack_name}' {status}\n")
        self.packet_list.yview_moveto(1)
        logger.debug("Detector %s set to %s", detector_class_name, status)

    def start_capture(self):
        """Start packet capture on selected interface."""
        selected_iface = self.iface_var.get()
        if not selected_iface:
            show_error("Error", "No interface selected.")
            return

        self.listener = LiveListener(interface=selected_iface, filter_exp="ip")

        def gui_callback(packet):
            self.root.after(0, self._process_packet, packet)

        threading.Thread(target=self.listener.listen, args=(gui_callback,), daemon=True).start()
        self.packet_list.insert("end", f"[INFO] Capture started on {selected_iface}\n")

    def pause_capture(self):
        """Pause packet capture."""
        self.is_paused = True
        self.packet_list.insert("end", "[INFO] Capture paused.\n")

    def resume_capture(self):
        """Resume packet capture."""
        self.is_paused = False
        self.packet_list.insert("end", "[INFO] Capture resumed.\n")

    def _process_packet(self, packet):
        """Process and display a captured packet."""
        try:
            if self.is_paused:
                return
            
            # Update traffic analyzer (for IPv6)
            self.analyzer.analyze_packet(packet)
            
            packet_summary = (
                f"{packet['timestamp']} | {packet['src_ip']} -> {packet['dst_ip']} | "
                f"{packet['protocol']} | {packet['length']} bytes"
            )
            self.packet_list.insert("end", packet_summary + "\n")
            self.packet_list.yview_moveto(1)

            # Apply IPv4 rules
            packet_after_rules = self.detection_engine._apply_rules_to_packet(packet)
            
            if packet_after_rules is not None and "rule_findings" in packet_after_rules:
                for finding in packet_after_rules["rule_findings"]:
                    self._display_finding(finding)
            
            if packet_after_rules is None:
                self.packet_list.insert("end", "  [DROPPED] Packet filtered by rule\n")
                self.packet_list.yview_moveto(1)
                return

            # Analyze with IPv4 detectors
            findings = self.detection_engine.analyze(packet_after_rules)
            for finding in findings:
                self._display_finding(finding)
            
            # Analyze with IPv6 detector
            self._analyze_ipv6_packet(packet)
            
            # Update statistics
            self.packet_count += 1
            self.packet_label.config(text=f"📦 Total Packets: {self.packet_count}")
            
        except Exception as e:
            logger.exception("Error processing packet: %s", e)

    def _analyze_ipv6_packet(self, packet):
        """Analyze packet with IPv6 detector for advanced threats."""
        try:
            proto = packet.get("protocol", "unknown").lower()
            if proto not in self.filter_protocols:
                return
            
            pkt_info = {
                "protocol": proto,
                "src": packet.get("src_ip"),
                "dst": packet.get("dst_ip"),
                "flags": packet.get("flags", ""),
                "port": packet.get("dport", packet.get("sport"))
            }
            
            self.ipv6_detector.analyze_packet(pkt_info)
            alerts = list(self.ipv6_detector.get_alerts())
            
            if alerts:
                for alert in alerts:
                    raw_name = alert.get("attack", "Unknown")
                    normalized = self._normalize_attack_name(raw_name)
                    self.attack_counts[normalized] += 1
                    
                    src_ip = pkt_info.get('src')
                    if src_ip:
                        self.attacker_ips[src_ip] += 1
                    
                    description = alert.get("description", "")
                    
                    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    
                    attack_msg = f"\n{'='*100}\n"
                    attack_msg += f"⚠️  SECURITY ALERT (IPv6) - {timestamp}\n"
                    attack_msg += f"{'='*100}\n"
                    attack_msg += f"Attack Type:    {raw_name}\n"
                    attack_msg += f"Severity:       {'🔴 CRITICAL' if 'FLOOD' in raw_name.upper() else '🟠 HIGH'}\n"
                    attack_msg += f"Source IP:      {pkt_info.get('src', 'N/A')}\n"
                    attack_msg += f"Destination IP: {pkt_info.get('dst', 'N/A')}\n"
                    attack_msg += f"Protocol:       {proto.upper()}\n"
                    if pkt_info.get('port'):
                        attack_msg += f"Port:           {pkt_info.get('port')}\n"
                    attack_msg += f"\nTechnical Details:\n"
                    attack_msg += f"  • {description}\n"
                    
                    if normalized in self.ATTACK_DESCRIPTIONS:
                        attack_msg += f"\nSecurity Analysis:\n"
                        attack_msg += f"  • {self.ATTACK_DESCRIPTIONS[normalized]}\n"
                    
                    attack_msg += f"{'='*100}\n"
                    
                    self.alert_area.config(state="normal")
                    self.alert_area.insert(tk.END, attack_msg, "alert")
                    self.alert_area.see(tk.END)
                    self.alert_area.config(state="disabled")
                    
                    self.alert_count += 1
                    self.alert_label.config(text=f"⚠️  Security Alerts: {self.alert_count}")
                    
                    self._update_analytics_graph()
                
                self.ipv6_detector.alerts.clear()
        except Exception as e:
            logger.exception("Error analyzing IPv6 packet: %s", e)

    def _normalize_attack_name(self, raw):
        """Normalize attack name."""
        if not raw:
            return "Unknown"
        r = raw.upper()
        if "SYN SCAN" in r:
            return "SYN Scan"
        if "SYN FLOOD" in r:
            return "SYN Flood"
        if "XMAS" in r:
            return "XMAS Scan"
        if "NULL" in r:
            return "NULL Scan"
        if "UDP FLOOD" in r:
            return "UDP Flood"
        if "ICMP ECHO" in r or "ICMP FLOOD" in r:
            return "ICMP Flood"
        if "ARP FLOOD" in r:
            return "ARP Flood"
        if "ARP SPOOF" in r:
            return "ARP Spoofing"
        if "DNS FLOOD" in r:
            return "DNS Flood"
        return raw.title()

    def _update_analytics_graph(self):
        """Update the analytics graph with attack statistics."""
        self.ax_analytics.clear()
        self.ax_analytics.set_title("Attack Distribution by Type")
        self.ax_analytics.set_ylabel("Count")
        self.ax_analytics.set_xlabel("Attack Type")
        
        types_ = list(self.attack_counts.keys())
        counts_ = [self.attack_counts[t] for t in types_]
        colors = [self.ATTACK_COLORS.get(t, "grey") for t in types_]
        
        if types_:
            self.ax_analytics.bar(types_, counts_, color=colors)
            self.ax_analytics.tick_params(axis='x', rotation=45)
        else:
            self.ax_analytics.text(0.5, 0.5, "No attacks detected yet",
                                  horizontalalignment='center', verticalalignment='center',
                                  transform=self.ax_analytics.transAxes, fontsize=12, color='gray')
        
        self.fig_analytics.tight_layout()
        self.canvas_analytics.draw()

    def _get_group_key(self, finding):
        """Generate a group key for detection grouping."""
        attack_type = finding.get('attack_type', finding.get('type', 'Unknown'))
        protocol = finding.get('protocol', 'Unknown')
        src_ip = finding.get('src_ip', 'Unknown')
        dst_ip = finding.get('dst_ip', 'Unknown')
        return f"{attack_type}|{protocol}|{src_ip}|{dst_ip}"

    def _display_finding(self, finding):
        """Display a detection finding in the detections tree with grouping."""
        try:
            time = finding.get('time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            finding_type = finding.get('attack_type', finding.get('type', 'Unknown')).replace('_', ' ').title()
            protocol = finding.get('protocol', 'Unknown Protocol')
            src_ip = finding.get('src_ip', 'Unknown Source')
            dst_ip = finding.get('dst_ip', 'Unknown Destination')
            message = finding.get('message', 'No details available')
            action = finding.get('action', None)

            group_key = self._get_group_key(finding)
            row_color = get_finding_color(action)

            if group_key in self.detection_groups:
                group_data = self.detection_groups[group_key]
                group_data['count'] += 1
                group_data['last_time'] = time
                group_data['timestamps'].append(time)
                
                if len(group_data['timestamps']) > 50:
                    group_data['timestamps'] = group_data['timestamps'][-50:]
                
                item_id = group_data['item_id']
                count_text = f"[{group_data['count']}x]"
                
                self.detections_tree.item(item_id, values=(
                    group_data['first_time'],
                    finding_type,
                    protocol,
                    src_ip,
                    dst_ip,
                    count_text,
                    f"{message} (Last: {time})"
                ))
            else:
                item_id = self.detections_tree.insert("", "end", values=(
                    time, finding_type, protocol, src_ip, dst_ip, "[1x]", message
                ))
                
                self.detection_groups[group_key] = {
                    'first_time': time,
                    'last_time': time,
                    'attack_type': finding_type,
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'count': 1,
                    'timestamps': [time],
                    'item_id': item_id,
                    'action': action,
                    'finding': finding,
                }

            apply_row_color(self.detections_tree, item_id, row_color)
        except Exception as e:
            logger.exception("Error displaying finding: %s", e)

    def stop_capture(self):
        """Stop packet capture."""
        if self.listener:
            self.listener.stop()
            self.packet_list.insert("end", "[INFO] Capture stopped.\n")

    def save_settings(self):
        """Save settings to configuration file."""
        try:
            from ids.utils import config as cfg
            
            try:
                syn_window = float(self.attack_settings["syn_flood"]["window"].get())
                syn_threshold = int(self.attack_settings["syn_flood"]["threshold"].get())
                
                udp_window = float(self.attack_settings["udp_flood"]["window"].get())
                udp_threshold = int(self.attack_settings["udp_flood"]["threshold"].get())
                
                simple_window = float(self.attack_settings["simple_rate"]["window"].get())
                simple_threshold = int(self.attack_settings["simple_rate"]["threshold"].get())
                
                if syn_window <= 0 or syn_threshold <= 0:
                    show_error("Invalid Input", "SYN Flood: Window and threshold must be > 0")
                    return
                if udp_window <= 0 or udp_threshold <= 0:
                    show_error("Invalid Input", "UDP Flood: Window and threshold must be > 0")
                    return
                if simple_window <= 0 or simple_threshold <= 0:
                    show_error("Invalid Input", "Generic Rate: Window and threshold must be > 0")
                    return
                    
            except ValueError:
                show_error("Invalid Input", "Please enter valid numbers for all fields")
                return
            
            cfg.set_section("syn_flood", {"window": syn_window, "threshold": syn_threshold})
            cfg.set_section("udp_flood", {"window": udp_window, "threshold": udp_threshold})
            cfg.set_section("simple_rate", {"window": simple_window, "threshold": simple_threshold})
            cfg.save()
            
            show_info("Success", "Settings saved successfully!\nDetectors will use new values immediately.")
            logger.info("Settings updated")
        except Exception as e:
            show_error("Error", f"Failed to save settings: {e}")
            logger.exception("Error saving settings")

    def reset_settings(self):
        """Reset settings to default values."""
        if messagebox.askyesno("Reset to Defaults", "Are you sure you want to reset all settings to defaults?"):
            try:
                from ids.utils import config as cfg
                
                cfg.set_section("syn_flood", {"window": 0.5, "threshold": 10})
                cfg.set_section("udp_flood", {"window": 0.5, "threshold": 10})
                cfg.set_section("simple_rate", {"window": 0.5, "threshold": 10})
                cfg.save()
                
                self._build_settings_tab()
                show_info("Reset Complete", "Settings have been reset to defaults.")
                logger.info("Settings reset to defaults")
            except Exception as e:
                show_error("Error", f"Failed to reset settings: {e}")
                logger.exception("Error resetting settings")

    def refresh_interfaces(self):
        """Refresh list of available network interfaces."""
        try:
            import socket
            interfaces = [name for _idx, name in socket.if_nameindex()]
        except Exception as e:
            logger.error("Error fetching interfaces: %s", e)
            interfaces = ['lo']

        if not interfaces:
            interfaces = ['lo']

        self.iface_combo['values'] = interfaces
        current_iface = self.iface_var.get()
        if current_iface not in interfaces:
            self.iface_var.set('lo' if 'lo' in interfaces else interfaces[0])

    def _add_rule(self):
        """Open dialog to add a new rule."""
        self._show_rule_dialog(None, "Add Rule")

    def _edit_rule(self):
        """Open dialog to edit selected rule."""
        selected_item = self.rules_tree.selection()
        if not selected_item:
            show_error("Error", "No rule selected.")
            return

        item = self.rules_tree.item(selected_item)
        values = item["values"]
        self._show_rule_dialog(values, "Edit Rule")

    def _delete_rule(self):
        """Delete the selected rule."""
        selected_item = self.rules_tree.selection()
        if not selected_item:
            show_error("Error", "No rule selected.")
            return

        self.rules_tree.delete(selected_item)
        self._on_rule_change()

    def _show_rule_dialog(self, rule_values, title):
        """Show rule creation/editing dialog."""
        rule_window = tk.Toplevel(self.root)
        rule_window.title(title)

        fields = [
            ("Rule Name:", "name"),
            ("Field:", "field"),
            ("Operator:", "operator"),
            ("Value:", "value"),
            ("Action:", "action")
        ]

        vars_dict = {}

        for i, (label_text, var_name) in enumerate(fields):
            ttk.Label(rule_window, text=label_text).grid(row=i, column=0, sticky="w", padx=5, pady=5)

            var = tk.StringVar()
            if rule_values:
                var.set(rule_values[i])

            if var_name == "field":
                combo = ttk.Combobox(rule_window, textvariable=var, state="readonly")
                combo["values"] = AVAILABLE_FIELDS
                combo.grid(row=i, column=1, sticky="we", padx=5, pady=5)
            elif var_name == "operator":
                combo = ttk.Combobox(rule_window, textvariable=var, state="readonly")
                combo["values"] = AVAILABLE_OPERATORS
                combo.grid(row=i, column=1, sticky="we", padx=5, pady=5)
            elif var_name == "action":
                combo = ttk.Combobox(rule_window, textvariable=var, state="readonly")
                combo["values"] = AVAILABLE_ACTIONS
                combo.grid(row=i, column=1, sticky="we", padx=5, pady=5)
            else:
                ttk.Entry(rule_window, textvariable=var).grid(row=i, column=1, sticky="we", padx=5, pady=5)

            vars_dict[var_name] = var

        def save_rule():
            rule = {
                "name": vars_dict["name"].get(),
                "field": vars_dict["field"].get(),
                "operator": vars_dict["operator"].get(),
                "value": vars_dict["value"].get(),
                "action": vars_dict["action"].get()
            }

            is_valid, error_msg = validate_rule(rule)
            if not is_valid:
                show_error("Error", error_msg)
                return

            if rule_values:
                selected = self.rules_tree.selection()[0]
                self.rules_tree.item(selected, values=(
                    rule["name"], rule["field"], rule["operator"], rule["value"], rule["action"]
                ))
            else:
                self.rules_tree.insert("", "end", values=(
                    rule["name"], rule["field"], rule["operator"], rule["value"], rule["action"]
                ))

            self._on_rule_change()
            rule_window.destroy()

        ttk.Button(rule_window, text="Save", command=save_rule).grid(row=len(fields), column=0, columnspan=2, pady=10)

    def _load_rules(self):
        """Load rules from file and populate tree."""
        try:
            rules = load_rules_from_file()
            for rule in rules:
                self.rules_tree.insert("", "end", values=(
                    rule.get("name", ""),
                    rule.get("field", ""),
                    rule.get("operator", ""),
                    rule.get("value", ""),
                    rule.get("action", "")
                ))
        except FileNotFoundError:
            logger.warning("rules.json not found")
        except Exception as e:
            logger.error("Failed to load rules: %s", e)

    def _on_rule_change(self):
        """Save rules and reload in detection engine."""
        rules = []
        for item in self.rules_tree.get_children():
            values = self.rules_tree.item(item, "values")
            rules.append({
                "name": values[0],
                "field": values[1],
                "operator": values[2],
                "value": values[3],
                "action": values[4]
            })

        if save_rules_to_file(rules):
            self.detection_engine.reload_rules()


def run():
    """Run the unified IDS GUI."""
    root = tk.Tk()
    app = UnifiedCaptureGUI(root)

    def _handle_sigint(signum, frame):
        try:
            root.quit()
        except Exception:
            pass

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        try:
            root.quit()
        except Exception:
            pass


if __name__ == '__main__':
    run()
