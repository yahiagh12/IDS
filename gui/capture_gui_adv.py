import tkinter as tk
from tkinter import scrolledtext, Menu, ttk, filedialog, messagebox
from ..capture.live_listener_adv import LiveListener
from ..traffic_analyser import TrafficAnalyzer
from ..detection_ipv6 import IPv6AttackDetector
import threading
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
import hashlib
import secrets
import json
import os
try:
    import winsound
except ImportError:
    winsound = None

class CaptureGUI:
    """
    IDS Advanced GUI PRO - Network Threat Detection System
    Intrusion Detection System with Real-time Attack Detection
    Monitors network traffic for suspicious patterns and security threats
    """

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

    def __init__(self, interface="lo", backends=None, analyzer=None):
        self.interface = interface
        self.backends = backends if backends else ["arp", "icmp", "dns", "ipv6"]
        self.analyzer = analyzer if analyzer else TrafficAnalyzer()
        self.listener = None
        self.thread = None
        self.is_paused = False

        # Stats
        self.packet_count = 0
        self.alert_count = 0
        self.protocol_counts = defaultdict(int)
        self.attack_counts = defaultdict(int)
        
        # Advanced Analytics (Étape 3)
        self.attack_timeline = defaultdict(int)  # timestamp -> count of attacks
        self.attacker_ips = defaultdict(int)  # ip -> number of attacks
        self.behavioral_anomalies = []  # list of behavioral alerts

        # Logs
        self.log_file = "logs.txt"
        self.filter_protocols = set(self.backends)

        # IPv6 Detector
        self.ipv6_detector = IPv6AttackDetector()

        # GUI
        self.root = tk.Tk()
        self.root.title("IDS Advanced - Network Threat Detection System")
        self.root.geometry("1600x950")
        self.root.configure(bg="#ecf0f1")

        # prepare users file and show login before building the main UI
        self.users_path = os.path.join(os.path.dirname(__file__), 'users.json')
        self.authenticated = False
        self._load_or_create_users()
        # show login dialog (blocks until closed)
        self.show_login_dialog()

        if not self.authenticated:
            # user cancelled or failed auth — exit GUI
            self.root.destroy()
            return

        self._build_gui()
        self._update_stats_periodically()

    # ------------------------------
    # Build GUI
    # ------------------------------
    def _build_gui(self):
        # Menu
        menubar = Menu(self.root)
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Clear Logs", command=self.clear_logs)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_command(label="Export Graph (PNG)", command=self.export_graph)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        # Settings
        settings_menu = Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Configuration", command=self._check_rbac_and_open_settings)
        settings_menu.add_command(label="Change Password", command=self.change_password_dialog)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        self.root.config(menu=menubar)

        # Tabs
        self.tab_control = ttk.Notebook(self.root)
        self.log_tab = ttk.Frame(self.tab_control)
        self.stats_tab = ttk.Frame(self.tab_control)
        self.baseline_tab = ttk.Frame(self.tab_control)
        self.alert_tab = ttk.Frame(self.tab_control)
        self.heatmap_tab = ttk.Frame(self.tab_control)
        self.analytics_tab = ttk.Frame(self.tab_control)  # New: Analytics Tab
        self.tab_control.add(self.log_tab, text="📝 Live Logs")
        self.tab_control.add(self.stats_tab, text="📊 Stats & Graphs")
        self.tab_control.add(self.baseline_tab, text="📋 Traffic Baseline")
        self.tab_control.add(self.alert_tab, text="🛡️  Security Threats")
        self.tab_control.add(self.heatmap_tab, text="🔥 Heatmap")
        self.tab_control.add(self.analytics_tab, text="📈 Advanced Analytics")  # New tab
        self.tab_control.pack(expand=1, fill='both')

        # Config Frame - Professional header
        header_frame = tk.Frame(self.log_tab, bg="#34495e", height=50)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        
        header_label = tk.Label(header_frame, 
                               text="🌐 NETWORK PACKET CAPTURE & MONITORING",
                               font=("Arial", 12, "bold"),
                               bg="#34495e", fg="white", pady=10)
        header_label.pack(fill=tk.X)
        
        info_label = tk.Label(header_frame,
                             text="Real-time network monitoring on interface: " + self.interface,
                             font=("Arial", 9), fg="#bdc3c7", bg="#34495e")
        info_label.pack(anchor=tk.W, padx=15)
        
        # Config Frame
        config_frame = tk.Frame(self.log_tab, bg="#ecf0f1")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(config_frame, text="Select Protocols to Monitor:", font=("Arial", 10, "bold"), bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        
        self.protocol_vars = {}
        protocols = ["ARP", "ICMP", "DNS", "IPv6", "TCP", "UDP"]
        for proto in protocols:
            var = tk.BooleanVar(value=(proto.lower() in self.backends))
            cb = tk.Checkbutton(config_frame, text=proto, variable=var, command=self._update_filter, bg="#ecf0f1")
            cb.pack(side=tk.LEFT, padx=3)
            self.protocol_vars[proto.lower()] = var

        # Buttons
        tk.Button(config_frame, text="▶ Start", command=self.start_capture).pack(side=tk.LEFT, padx=8)
        tk.Button(config_frame, text="⏹ Stop", command=self.stop_capture).pack(side=tk.LEFT, padx=8)
        tk.Button(config_frame, text="⏸ Pause", command=self.pause_capture).pack(side=tk.LEFT, padx=8)
        tk.Button(config_frame, text="⏯ Resume", command=self.resume_capture).pack(side=tk.LEFT, padx=8)
        tk.Button(config_frame, text="🧹 Clear", command=self.clear_logs).pack(side=tk.LEFT, padx=8)

        # Logs Area
        self.text_area = scrolledtext.ScrolledText(self.log_tab, width=170, height=30)
        self.text_area.pack(padx=10, pady=5)

        # Baseline Area
        self.baseline_area = scrolledtext.ScrolledText(self.baseline_tab, width=170, height=30)
        self.baseline_area.pack(padx=10, pady=10)

        # Alert Tab Layout - split with top text area and bottom graph
        alert_top_frame = tk.Frame(self.alert_tab, bg="#ecf0f1")
        alert_top_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Alert Header
        alert_header = tk.Label(alert_top_frame, 
                                text="🛡️  DETECTED SECURITY THREATS & ATTACKS", 
                                font=("Arial", 12, "bold"),
                                bg="#c0392b", fg="white", pady=10)
        alert_header.pack(fill=tk.X)
        
        # Alert info
        info_text = tk.Label(alert_top_frame,
                            text="Real-time detection of network attacks including: DDoS Floods, Port Scans, ARP Spoofing, DNS Attacks",
                            font=("Arial", 9), fg="#7f8c8d", bg="#ecf0f1")
        info_text.pack(anchor=tk.W, padx=5, pady=5)
        
        # Alert Area (top) - limited height
        self.alert_area = scrolledtext.ScrolledText(alert_top_frame, 
                                                     width=170, height=8,
                                                     bg="#2c3e50", fg="#ecf0f1",
                                                     font=("Courier", 9))
        self.alert_area.pack(fill=tk.BOTH, expand=False, pady=5)

        # Attack Graph (bottom)
        graph_label = tk.Label(alert_top_frame, 
                              text="📊 ATTACK STATISTICS & THREAT ANALYSIS", 
                              font=("Arial", 11, "bold"),
                              bg="#34495e", fg="white", pady=5)
        graph_label.pack(fill=tk.X, pady=(10, 0))
        
        self.fig_alert, self.ax_alert = plt.subplots(figsize=(14, 3))
        self.ax_alert.set_title("Attack Distribution Over Time")
        self.ax_alert.set_ylabel("Number of Attacks")
        self.ax_alert.set_xlabel("Attack Type")
        self.fig_alert.patch.set_facecolor("#ecf0f1")
        self.canvas_alert = FigureCanvasTkAgg(self.fig_alert, master=alert_top_frame)
        self.canvas_alert.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Stats Frame - Professional Layout
        stats_frame = tk.Frame(self.stats_tab, bg="#2c3e50")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Header
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
        
        self.active_label = tk.Label(stats_box, text="🔍 Monitored Protocols: " + ", ".join(self.backends).upper(),
                                    font=("Arial", 10), bg="#ecf0f1")
        self.active_label.pack(side=tk.RIGHT, padx=15)

        # General Graph
        self.fig, self.ax = plt.subplots(figsize=(7, 3))
        self.ax.set_title("Network Traffic Distribution")
        self.ax.set_ylabel("Packet Count")
        self.fig.patch.set_facecolor("#ecf0f1")
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.stats_tab)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Tag colors
        for proto, color in self.PROTO_COLORS.items():
            self.text_area.tag_config(proto, foreground=color)
            self.baseline_area.tag_config(proto, foreground=color)
            self.alert_area.tag_config(proto, foreground=color)
        
        # Heatmap Tab (E - Étape E)
        heatmap_frame = tk.Frame(self.heatmap_tab, bg="#ecf0f1")
        heatmap_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        heatmap_header = tk.Label(heatmap_frame, 
                                  text="🔥 ATTACK HEATMAP - Temporal & Geographic Distribution",
                                  font=("Arial", 12, "bold"),
                                  bg="#34495e", fg="white", pady=10)
        heatmap_header.pack(fill=tk.X)
        
        self.fig_heatmap, self.ax_heatmap = plt.subplots(figsize=(10, 4))
        self.ax_heatmap.set_title("Attacks Over Time")
        self.ax_heatmap.set_xlabel("Time")
        self.ax_heatmap.set_ylabel("Attack Type")
        self.fig_heatmap.patch.set_facecolor("#ecf0f1")
        self.canvas_heatmap = FigureCanvasTkAgg(self.fig_heatmap, master=heatmap_frame)
        self.canvas_heatmap.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Analytics Tab (Étape 3 - Advanced Analytics)
        analytics_frame = tk.Frame(self.analytics_tab, bg="#ecf0f1")
        analytics_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        analytics_header = tk.Label(analytics_frame, 
                                    text="📈 ADVANCED ANALYTICS - Attack Analysis & Behavioral Insights",
                                    font=("Arial", 12, "bold"),
                                    bg="#34495e", fg="white", pady=10)
        analytics_header.pack(fill=tk.X)
        
        # Create two-panel layout: Top for graphs, Bottom for Top IPs
        top_panel = tk.Frame(analytics_frame, bg="#ecf0f1")
        top_panel.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Graph 1: Attack Type Distribution (pie chart)
        graph1_label = tk.Label(top_panel, text="Attack Distribution by Type", font=("Arial", 10, "bold"), bg="#ecf0f1")
        graph1_label.pack(anchor=tk.W, padx=5)
        
        self.fig_analytics1, self.ax_analytics1 = plt.subplots(figsize=(6, 4))
        self.ax_analytics1.set_title("Attack Type Distribution")
        self.fig_analytics1.patch.set_facecolor("#ecf0f1")
        self.canvas_analytics1 = FigureCanvasTkAgg(self.fig_analytics1, master=top_panel)
        self.canvas_analytics1.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Graph 2: Top Attacker IPs
        graph2_label = tk.Label(top_panel, text="Top Attacker IPs", font=("Arial", 10, "bold"), bg="#ecf0f1")
        graph2_label.pack(anchor=tk.W, padx=5)
        
        self.fig_analytics2, self.ax_analytics2 = plt.subplots(figsize=(6, 4))
        self.ax_analytics2.set_title("Top 10 Attacker IPs")
        self.fig_analytics2.patch.set_facecolor("#ecf0f1")
        self.canvas_analytics2 = FigureCanvasTkAgg(self.fig_analytics2, master=top_panel)
        self.canvas_analytics2.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bottom panel: Detailed analytics text
        bottom_panel = tk.Frame(analytics_frame, bg="#ecf0f1")
        bottom_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        analytics_label = tk.Label(bottom_panel, text="Detailed Attack Statistics", font=("Arial", 10, "bold"), bg="#ecf0f1")
        analytics_label.pack(anchor=tk.W)
        
        self.analytics_text = scrolledtext.ScrolledText(bottom_panel, width=170, height=10, bg="#2c3e50", fg="#ecf0f1")
        self.analytics_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initialize attack graph
        self._update_attack_graph()

    # ------------------------------
    # IPv6 Attack Detection
    # ------------------------------
    def detect_ipv6_attacks(self, pkt):
        proto_field = pkt.get("protocol", "")
        proto_lower = str(proto_field).lower()
        if proto_lower == "tcp":
            detector_proto = "TCP"
        elif proto_lower == "udp":
            detector_proto = "UDP"
        elif "icmp" in proto_lower:
            detector_proto = "ICMPv6"
        elif proto_lower == "arp":
            detector_proto = "ARP"
        elif proto_lower == "dns":
            detector_proto = "DNS"
        else:
            detector_proto = proto_field.upper() if proto_field else "OTHER"

        port = pkt.get("port", pkt.get("dport", pkt.get("sport", None)))
        pkt_info = {
            "protocol": detector_proto,
            "src": pkt.get("src"),
            "dst": pkt.get("dst"),
            "flags": pkt.get("flags", ""),
            "port": port,
            "icmp_type": pkt.get("icmp_type")
        }

        self.ipv6_detector.analyze_packet(pkt_info)
        alerts = list(self.ipv6_detector.get_alerts())
        
        # S'il y a des alertes (vraies attaques)
        if alerts:
            for alert in alerts:
                raw_name = alert.get("attack", "")
                normalized = self._normalize_attack_name(raw_name)
                self.attack_counts[normalized] += 1
                
                # Étape 3: Track attacker IP for analytics
                src_ip = pkt_info.get('src')
                if src_ip:
                    self.attacker_ips[src_ip] += 1
                
                description = alert.get("description", "")
                
                # Afficher l'attaque détectée dans la zone d'attaques avec plus de détails
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # ms precision
                
                # Format amélioré avec sections
                attack_msg = f"\n{'='*100}\n"
                attack_msg += f"⚠️  SECURITY ALERT - {timestamp}\n"
                attack_msg += f"{'='*100}\n"
                attack_msg += f"Attack Type:    {raw_name}\n"
                attack_msg += f"Severity:       {'🔴 CRITICAL' if 'FLOOD' in raw_name.upper() else '🟠 HIGH'}\n"
                attack_msg += f"Source IP:      {pkt_info.get('src', 'N/A')}\n"
                attack_msg += f"Destination IP: {pkt_info.get('dst', 'N/A')}\n"
                attack_msg += f"Protocol:       {detector_proto}\n"
                if pkt_info.get('port'):
                    attack_msg += f"Port:           {pkt_info.get('port')}\n"
                attack_msg += f"\nTechnical Details:\n"
                attack_msg += f"  • {description}\n"
                
                # Ajouter explication de sécurité
                if normalized in self.ATTACK_DESCRIPTIONS:
                    attack_msg += f"\nSecurity Analysis:\n"
                    attack_msg += f"  • {self.ATTACK_DESCRIPTIONS[normalized]}\n"
                
                attack_msg += f"{'='*100}\n"
                
                self.alert_area.insert(tk.END, attack_msg, "alert")
                self.alert_area.see(tk.END)
                
                self._raise_alert(raw_name, description)
                
                # Show critical alert pop-up and sound
                self._show_critical_alert(normalized, pkt_info)
                
                # Log alert to JSON for SIEM
                self._log_alert_json(normalized, pkt_info, description)

            # vider alert detector pour éviter doublons
            self.ipv6_detector.alerts.clear()
            self._update_attack_graph()
            self._update_heatmap()  # E - Update heatmap

    def _normalize_attack_name(self, raw):
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

    # ------------------------------
    # Raise alert in GUI
    # ------------------------------
    def _raise_alert(self, text, signature=""):
        self.alert_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        msg = f"[ALERT {timestamp}] {text} | Signature: {signature}\n"
        self.text_area.insert(tk.END, msg, "alert")
        self.text_area.see(tk.END)
        self.alert_area.insert(tk.END, msg, "alert")
        self.alert_area.see(tk.END)
        self._save_log(msg)

    # ------------------------------
    # Update attack graph
    # ------------------------------
    def _update_attack_graph(self):
        self.ax_alert.clear()
        self.ax_alert.set_title("Nombre d'attaques par type")
        self.ax_alert.set_ylabel("Count")
        self.ax_alert.set_xlabel("Attack Type")
        types_ = list(self.attack_counts.keys())
        counts_ = [self.attack_counts[t] for t in types_]
        colors = [self.ATTACK_COLORS.get(t, "grey") for t in types_]
        
        if types_:
            self.ax_alert.bar(types_, counts_, color=colors)
            self.ax_alert.tick_params(axis='x', rotation=45)
        else:
            # Afficher un message quand aucune attaque n'est détectée
            self.ax_alert.text(0.5, 0.5, "No attacks detected yet", 
                              horizontalalignment='center', verticalalignment='center',
                              transform=self.ax_alert.transAxes, fontsize=12, color='gray')
        
        self.fig_alert.tight_layout()
        self.canvas_alert.draw()

    # ------------------------------
    # Capture callback
    # ------------------------------
    def _callback(self, pkt):
        if self.is_paused:
            return

        proto = getattr(pkt, "protocol", "other").lower()
        if proto not in self.filter_protocols:
            proto = "other"

        self.packet_count += 1
        self.protocol_counts[proto] += 1

        pkt_info = {
            "protocol": proto,
            "src": getattr(pkt, "src", None),
            "dst": getattr(pkt, "dst", None),
            "sport": getattr(pkt, "sport", None),
            "dport": getattr(pkt, "dport", None),
            "flags": getattr(pkt, "flags", ""),
            "port": getattr(pkt, "port", getattr(pkt, "dport", None)),
            "icmp_type": getattr(pkt, "icmp_type", None)
        }

        self.analyzer.analyze_packet(pkt_info)
        #self.detect_ipv6_attacks(pkt_info)
        # Préparer le paquet pour le détecteur IPv6
        pkt_for_detector = {
            "protocol": pkt_info.get("protocol"),
            "src": pkt_info.get("src"),
            "dst": pkt_info.get("dst"),
            "flags": pkt_info.get("flags"),
            "port": pkt_info.get("port"),
            "icmp_type": pkt_info.get("icmp_type"),
            "src_mac": getattr(pkt, "src_mac", None),  # ARP spoofing detection
            "dst_mac": getattr(pkt, "dst_mac", None)   # ARP spoofing detection
            }
        self.detect_ipv6_attacks(pkt_for_detector)


        timestamp = datetime.now().strftime("%H:%M:%S")
        msg = f"[{timestamp}] {pkt_info}\n"
        self.text_area.insert(tk.END, msg, proto if proto in self.PROTO_COLORS else "other")
        self.text_area.see(tk.END)
        self._save_log(msg)

        self.update_baseline()
        self._update_stats()

    # ------------------------------
    # Traffic baseline
    # ------------------------------
    def update_baseline(self):
        baseline = self.analyzer.get_baseline()
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.baseline_area.insert(tk.END, f"\n[{timestamp}] Traffic Summary:\n", "other")
        for proto, count in baseline["protocol_count"].items():
            line = f"  {proto.upper():<5} | Total: {count}\n"
            self.baseline_area.insert(tk.END, line, proto if proto in self.PROTO_COLORS else "other")

        tcp_handshake_ok = baseline.get("tcp_handshake_ok", 0)
        tcp_flags_count = baseline.get("tcp_flags_count", {})
        port_usage = baseline.get("port_usage", {})

        self.baseline_area.insert(tk.END, f"  TCP handshakes completed: {tcp_handshake_ok}\n", "tcp")
        self.baseline_area.insert(tk.END, "  TCP flags detected:\n", "tcp")
        for flag, count in tcp_flags_count.items():
            self.baseline_area.insert(tk.END, f"    {flag}: {count}\n", "tcp")

        self.baseline_area.insert(tk.END, "  Ports usage:\n", "other")
        for port, count in port_usage.items():
            self.baseline_area.insert(tk.END, f"    Port {port}: {count}\n", "other")

        self.baseline_area.see(tk.END)

    # ------------------------------
    # Logging
    # ------------------------------
    def _save_log(self, msg):
        with open(self.log_file, "a") as f:
            f.write(msg)

    # ------------------------------
    # Protocol filter update
    # ------------------------------
    def _update_filter(self):
        self.filter_protocols = {proto for proto, var in self.protocol_vars.items() if var.get()}

    # ------------------------------
    # Capture control
    # ------------------------------
    def start_capture(self):
        if self.thread is None or not self.thread.is_alive():
            selected_backends = [k for k, v in self.protocol_vars.items() if v.get()]
            self.listener = LiveListener(interface=self.interface, backends=selected_backends)
            self.thread = threading.Thread(target=self.listener.listen, args=(self._callback,))
            self.thread.daemon = True
            self.thread.start()
            self.is_paused = False
            self.text_area.insert(tk.END, "[INFO] Capture started on interface: " + self.interface + "\n")

    def stop_capture(self):
        if self.listener:
            self.listener.stop()
            self.text_area.insert(tk.END, "[INFO] Capture stopped.\n")

    def pause_capture(self):
        self.is_paused = True
        if self.listener:
            self.listener.is_running = False
        self.text_area.insert(tk.END, "[INFO] Capture paused.\n")

    def resume_capture(self):
        if self.listener:
            self.is_paused = False
            self.listener.is_running = True
        self.text_area.insert(tk.END, "[INFO] Capture resumed.\n")

    # ------------------------------
    # Logs management
    # ------------------------------
    def clear_logs(self):
        self.text_area.delete("1.0", tk.END)
        self.baseline_area.delete("1.0", tk.END)
        self.alert_area.delete("1.0", tk.END)
        self.analytics_text.delete("1.0", tk.END)  # Clear analytics
        self.packet_count = 0
        self.alert_count = 0
        self.protocol_counts.clear()
        self.attack_counts.clear()
        self.attacker_ips.clear()  # Clear attacker IPs
        self.attack_timeline.clear()  # Clear timeline
        open(self.log_file, "w").close()
        self._update_attack_graph()
        self._update_analytics()  # Update analytics display

    def export_logs(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(self.log_file, "r") as src, open(filename, "w") as dst:
                dst.write(src.read())
            messagebox.showinfo("Export Logs", f"Logs exported to {filename}")

    def export_graph(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if filename:
            try:
                self.fig.savefig(filename)
            except Exception:
                pass
            try:
                self.fig_alert.savefig(filename.replace(".png", "_attacks.png"))
            except Exception:
                pass
            messagebox.showinfo("Export Graph", f"Graphs exported to {filename} and attacks graph.")

    # ------------------------------
    # Stats update
    # ------------------------------
    def _update_stats(self):
        self.packet_label.config(text=f"Packets: {self.packet_count}")
        self.alert_label.config(text=f"Alerts: {self.alert_count}")
        self.active_label.config(text="Active protocols: " + ", ".join(self.filter_protocols))

        self.ax.clear()
        self.ax.set_title("Packets per Protocol")
        self.ax.set_ylabel("Count")
        colors = [self.PROTO_COLORS.get(proto, "black") for proto in self.protocol_counts]
        if self.protocol_counts:
            self.ax.bar(self.protocol_counts.keys(), self.protocol_counts.values(), color=colors)
        self.canvas.draw()

    def _update_stats_periodically(self):
        self._update_stats()
        self._update_attack_graph()
        self._update_analytics()  # Étape 3: Update advanced analytics
        self.root.after(1000, self._update_stats_periodically)

    def _show_critical_alert(self, attack_type, packet_info):
        """Show pop-up and play alert sound for critical attacks."""
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        cfg = {}
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
        
        notif_cfg = cfg.get('notifications', {})
        enable_popup = notif_cfg.get('enable_popup', True)
        enable_sound = notif_cfg.get('enable_sound', True)
        critical_attacks = notif_cfg.get('critical_attacks', [])
        
        if attack_type not in critical_attacks:
            return
        
        # Play alert sound
        if enable_sound and winsound:
            try:
                winsound.Beep(1000, 500)  # 1000 Hz for 500ms
            except Exception:
                pass
        
        # Show pop-up notification
        if enable_popup:
            try:
                src_ip = packet_info.get('src_ip', 'Unknown')
                dst_ip = packet_info.get('dst_ip', 'Unknown')
                msg = f"🚨 CRITICAL ATTACK DETECTED!\n\nType: {attack_type}\nSource: {src_ip}\nTarget: {dst_ip}"
                messagebox.showerror('Security Alert', msg)
            except Exception:
                pass

    def _log_alert_json(self, attack_type, packet_info, description):
        """Log alert to JSON lines file for SIEM integration."""
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        cfg = {}
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
        
        siem_cfg = cfg.get('siem', {})
        if not siem_cfg.get('enable_json_logging', True):
            return
        
        log_file = siem_cfg.get('log_file', 'alerts.jsonl')
        log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), log_file)
        
        # Determine severity based on attack type
        severity = 'MEDIUM'
        if 'Flood' in attack_type or 'Spoofing' in attack_type:
            severity = 'CRITICAL'
        elif 'Scan' in attack_type:
            severity = 'LOW'
        
        # Get geolocation for source IP
        src_ip = packet_info.get('src', 'Unknown')
        geo_info = self._get_geolocation(src_ip)
        
        alert_record = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'severity': severity,
            'description': description,
            'source_ip': src_ip,
            'destination_ip': packet_info.get('dst', 'Unknown'),
            'protocol': packet_info.get('protocol', 'Unknown'),
            'port': packet_info.get('port', None),
            'flags': packet_info.get('flags', ''),
            'confidence': 0.95,
            'geolocation': {
                'source_country': geo_info.get('country', 'Unknown'),
                'source_city': geo_info.get('city', 'Unknown'),
                'latitude': geo_info.get('latitude'),
                'longitude': geo_info.get('longitude')
            }
        }
        
        # G - Send webhook
        self._send_webhook(alert_record)
        
        # H - Send syslog
        self._send_syslog(attack_type, severity)
        
        # I - Encrypt if enabled
        log_content = self._encrypt_alert(alert_record)
        
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(log_content + '\n')
        except Exception:
            pass

    def _get_geolocation(self, ip_address):
        """Get geolocation for an IP address using fallback API."""
        if not ip_address or ip_address == 'Unknown':
            return {'country': 'Unknown', 'city': 'Unknown', 'latitude': None, 'longitude': None}
        
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        cfg = {}
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
        
        geo_cfg = cfg.get('geolocation', {})
        if not geo_cfg.get('enable_geolocation', True):
            return {'country': 'Unknown', 'city': 'Unknown', 'latitude': None, 'longitude': None}
        
        api_timeout = geo_cfg.get('api_timeout', 2)
        
        try:
            import urllib.request
            import urllib.error
            
            # Try ip-api.com (free, no key required)
            url = f"http://ip-api.com/json/{ip_address}?fields=country,city,lat,lon,status"
            req = urllib.request.Request(url, headers={'User-Agent': 'IDS/1.0'})
            
            try:
                with urllib.request.urlopen(req, timeout=api_timeout) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get('status') == 'success':
                        return {
                            'country': data.get('country', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'latitude': data.get('lat'),
                            'longitude': data.get('lon')
                        }
            except (urllib.error.URLError, urllib.error.HTTPError, Exception):
                pass
        except Exception:
            pass
        
        return {'country': 'Unknown', 'city': 'Unknown', 'latitude': None, 'longitude': None}

    # F - RBAC Check
    def _check_rbac_and_open_settings(self):
        """F - Étape F: Check if user is admin before opening settings."""
        if self.current_role and self.current_role.lower() == 'admin':
            self.open_settings_dialog()
        else:
            messagebox.showerror('Access Denied', 'Only admin users can access Settings.')

    # G - Webhook & REST API
    def _send_webhook(self, alert_record):
        """G - Étape G: Send alert to webhook if configured."""
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        cfg = {}
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            return
        
        webhook_cfg = cfg.get('webhook', {})
        if not webhook_cfg.get('enable_webhook', False):
            return
        
        webhook_url = webhook_cfg.get('webhook_url', '')
        if not webhook_url:
            return
        
        try:
            import urllib.request
            req = urllib.request.Request(webhook_url, data=json.dumps(alert_record).encode('utf-8'),
                                        headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=3):
                pass
        except Exception:
            pass

    # H - Syslog Support
    def _send_syslog(self, attack_type, severity):
        """H - Étape H: Send alert to syslog if configured."""
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        cfg = {}
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            return
        
        syslog_cfg = cfg.get('syslog', {})
        if not syslog_cfg.get('enable_syslog', False):
            return
        
        try:
            import logging.handlers
            syslog_host = syslog_cfg.get('syslog_host', '127.0.0.1')
            syslog_port = syslog_cfg.get('syslog_port', 514)
            
            handler = logging.handlers.SysLogHandler(address=(syslog_host, syslog_port))
            logger = logging.getLogger('IDS')
            logger.addHandler(handler)
            logger.warning(f'IDS Alert: {attack_type} (Severity: {severity})')
            logger.removeHandler(handler)
        except Exception:
            pass

    # I - Log Encryption
    def _encrypt_alert(self, alert_record):
        """I - Étape I: Encrypt alert before logging if configured."""
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        cfg = {}
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            return json.dumps(alert_record)
        
        enc_cfg = cfg.get('encryption', {})
        if not enc_cfg.get('enable_log_encryption', False):
            return json.dumps(alert_record)
        
        try:
            from cryptography.fernet import Fernet
            key_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'secret.key')
            
            # Create key if not exists
            if not os.path.exists(key_path):
                key = Fernet.generate_key()
                with open(key_path, 'wb') as f:
                    f.write(key)
            else:
                with open(key_path, 'rb') as f:
                    key = f.read()
            
            cipher = Fernet(key)
            encrypted = cipher.encrypt(json.dumps(alert_record).encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception:
            return json.dumps(alert_record)

    # E - Update Heatmap
    def _update_heatmap(self):
        """E - Étape E: Update heatmap with attack data."""
        self.ax_heatmap.clear()
        if self.attack_counts:
            self.ax_heatmap.barh(list(self.attack_counts.keys()), list(self.attack_counts.values()),
                                color=[self.ATTACK_COLORS.get(k, 'grey') for k in self.attack_counts.keys()])
            self.ax_heatmap.set_xlabel('Number of Attacks')
            self.ax_heatmap.set_title('Attack Distribution Heatmap')
        else:
            self.ax_heatmap.text(0.5, 0.5, 'No attacks to display', 
                               horizontalalignment='center', verticalalignment='center',
                               transform=self.ax_heatmap.transAxes, fontsize=12, color='gray')
        self.fig_heatmap.tight_layout()
        self.canvas_heatmap.draw()

    # Étape 3: Advanced Analytics
    def _update_analytics(self):
        """Étape 3: Update advanced analytics with attack distribution and top IPs."""
        # Update attack type distribution (pie chart)
        self.ax_analytics1.clear()
        if self.attack_counts:
            types_ = list(self.attack_counts.keys())
            counts_ = [self.attack_counts[t] for t in types_]
            colors = [self.ATTACK_COLORS.get(t, 'grey') for t in types_]
            self.ax_analytics1.pie(counts_, labels=types_, autopct='%1.1f%%', colors=colors)
            self.ax_analytics1.set_title('Attack Type Distribution')
        else:
            self.ax_analytics1.text(0.5, 0.5, 'No attacks detected', 
                                   horizontalalignment='center', verticalalignment='center',
                                   transform=self.ax_analytics1.transAxes, fontsize=11, color='gray')
        self.fig_analytics1.tight_layout()
        self.canvas_analytics1.draw()
        
        # Update Top Attacker IPs (bar chart)
        self.ax_analytics2.clear()
        if self.attacker_ips:
            # Get top 10 IPs
            sorted_ips = sorted(self.attacker_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            ips = [ip for ip, count in sorted_ips]
            counts = [count for ip, count in sorted_ips]
            colors_ips = ['#e74c3c' if count > 5 else '#f39c12' for count in counts]
            self.ax_analytics2.barh(ips, counts, color=colors_ips)
            self.ax_analytics2.set_xlabel('Number of Attack Attempts')
            self.ax_analytics2.set_title('Top 10 Attacker IPs')
        else:
            self.ax_analytics2.text(0.5, 0.5, 'No attackers detected', 
                                   horizontalalignment='center', verticalalignment='center',
                                   transform=self.ax_analytics2.transAxes, fontsize=11, color='gray')
        self.fig_analytics2.tight_layout()
        self.canvas_analytics2.draw()
        
        # Update detailed statistics text
        self.analytics_text.delete('1.0', tk.END)
        stats_text = "=" * 150 + "\n"
        stats_text += "ATTACK SUMMARY & BEHAVIORAL ANALYSIS\n"
        stats_text += "=" * 150 + "\n\n"
        
        # Overall statistics
        stats_text += f"Total Packets Captured:     {self.packet_count}\n"
        stats_text += f"Total Security Alerts:      {self.alert_count}\n"
        stats_text += f"Total Unique Attack Types:  {len(self.attack_counts)}\n"
        stats_text += f"Total Unique Attacker IPs:  {len(self.attacker_ips)}\n\n"
        
        # Attack type summary
        stats_text += "ATTACK BREAKDOWN BY TYPE:\n"
        stats_text += "-" * 150 + "\n"
        for attack_type in sorted(self.attack_counts.keys()):
            count = self.attack_counts[attack_type]
            percentage = (count / self.alert_count * 100) if self.alert_count > 0 else 0
            stats_text += f"  {attack_type:<30} : {count:>5} attacks ({percentage:>5.1f}%)\n"
        
        stats_text += "\n" + "=" * 150 + "\n"
        
        self.analytics_text.insert('1.0', stats_text)

    # ------------------------------
    # Settings dialog
    # ------------------------------
    def open_settings_dialog(self):
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')

        # load existing config
        cfg = {}
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

        thresholds = cfg.get('thresholds', {})
        profiles = cfg.get('profiles', {})
        current_profile = cfg.get('current_profile', 'Custom')
        whitelist = cfg.get('whitelist', [])
        blacklist = cfg.get('blacklist', [])
        notif_cfg = cfg.get('notifications', {})
        enable_popup = notif_cfg.get('enable_popup', True)
        enable_sound = notif_cfg.get('enable_sound', True)
        siem_cfg = cfg.get('siem', {})
        enable_json_logging = siem_cfg.get('enable_json_logging', True)
        geo_cfg = cfg.get('geolocation', {})
        enable_geolocation = geo_cfg.get('enable_geolocation', True)
        heatmap_cfg = cfg.get('heatmap', {})
        enable_heatmap = heatmap_cfg.get('enable_heatmap', True)
        webhook_cfg = cfg.get('webhook', {})
        enable_webhook = webhook_cfg.get('enable_webhook', False)
        webhook_url = webhook_cfg.get('webhook_url', '')
        enable_rest_api = webhook_cfg.get('enable_rest_api', False)
        syslog_cfg = cfg.get('syslog', {})
        enable_syslog = syslog_cfg.get('enable_syslog', False)
        syslog_host = syslog_cfg.get('syslog_host', '127.0.0.1')
        enc_cfg = cfg.get('encryption', {})
        enable_encryption = enc_cfg.get('enable_log_encryption', False)

        # Dictionary to store entry widgets for later access
        entries = {}

        def load_profile(profile_name):
            """Load a profile and populate threshold entries."""
            if profile_name in profiles:
                prof_thresholds = profiles[profile_name]
                entries['scan'].delete(0, tk.END)
                entries['scan'].insert(0, prof_thresholds.get('SCAN_PORT_THRESHOLD', 5))
                entries['syn'].delete(0, tk.END)
                entries['syn'].insert(0, prof_thresholds.get('SYN_FLOOD_THRESHOLD', 10))
                entries['udp'].delete(0, tk.END)
                entries['udp'].insert(0, prof_thresholds.get('UDP_FLOOD_THRESHOLD', 15))
                entries['icmp'].delete(0, tk.END)
                entries['icmp'].insert(0, prof_thresholds.get('ICMP_FLOOD_THRESHOLD', 10))
                entries['arp'].delete(0, tk.END)
                entries['arp'].insert(0, prof_thresholds.get('ARP_FLOOD_THRESHOLD', 10))
                entries['dns'].delete(0, tk.END)
                entries['dns'].insert(0, prof_thresholds.get('DNS_FLOOD_THRESHOLD', 15))
                entries['time'].delete(0, tk.END)
                entries['time'].insert(0, prof_thresholds.get('TIME_WINDOW', 3))

        def save_config():
            new_thresholds = {
                'SCAN_PORT_THRESHOLD': int(entries['scan'].get()),
                'SYN_FLOOD_THRESHOLD': int(entries['syn'].get()),
                'UDP_FLOOD_THRESHOLD': int(entries['udp'].get()),
                'ICMP_FLOOD_THRESHOLD': int(entries['icmp'].get()),
                'ARP_FLOOD_THRESHOLD': int(entries['arp'].get()),
                'DNS_FLOOD_THRESHOLD': int(entries['dns'].get()),
                'TIME_WINDOW': int(entries['time'].get())
            }

            new_whitelist = [line.strip() for line in wl_text.get('1.0', tk.END).splitlines() if line.strip()]
            new_blacklist = [line.strip() for line in bl_text.get('1.0', tk.END).splitlines() if line.strip()]

            final = cfg
            final['thresholds'] = new_thresholds
            final['current_profile'] = profile_var.get()
            final['whitelist'] = new_whitelist
            final['blacklist'] = new_blacklist
            final['notifications'] = {
                'enable_popup': popup_var.get(),
                'enable_sound': sound_var.get(),
                'critical_attacks': ["SYN Flood", "UDP Flood", "ICMP Flood", "ARP Flood", "ARP Spoofing", "DNS Flood"]
            }
            final['siem'] = {
                'enable_json_logging': json_logging_var.get(),
                'log_file': 'alerts.jsonl'
            }
            final['geolocation'] = {
                'enable_geolocation': geo_var.get(),
                'api_timeout': 2
            }
            final['heatmap'] = {
                'enable_heatmap': heatmap_var.get()
            }
            final['webhook'] = {
                'enable_webhook': webhook_var.get(),
                'webhook_url': webhook_entry.get(),
                'api_port': 5000,
                'enable_rest_api': api_var.get()
            }
            final['syslog'] = {
                'enable_syslog': syslog_var.get(),
                'syslog_host': syslog_host_entry.get(),
                'syslog_port': 514
            }
            final['encryption'] = {
                'enable_log_encryption': enc_var.get()
            }

            try:
                with open(cfg_path, 'w', encoding='utf-8') as f:
                    json.dump(final, f, indent=2)
                messagebox.showinfo('Settings', 'Configuration saved.')
                # apply to detector
                try:
                    self.ipv6_detector.load_config(cfg_path)
                except Exception:
                    pass
                win.destroy()
            except Exception as e:
                messagebox.showerror('Error', f'Could not save config: {e}')

        win = tk.Toplevel(self.root)
        win.title('Configuration IDS')

        frm = tk.Frame(win, padx=10, pady=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # Profile Selection Section
        tk.Label(frm, text='Security Profile', font=('Arial', 10, 'bold')).grid(row=0, column=0, columnspan=2, sticky='w')
        tk.Label(frm, text='Select Profile:').grid(row=1, column=0, sticky='e')
        profile_var = tk.StringVar(value=current_profile)
        profile_dropdown = ttk.Combobox(frm, textvariable=profile_var, values=['Custom'] + list(profiles.keys()), state='readonly', width=20)
        profile_dropdown.grid(row=1, column=1)
        profile_dropdown.bind('<<ComboboxSelected>>', lambda e: load_profile(profile_var.get()))

        # Detection Thresholds Section
        tk.Label(frm, text='Detection Thresholds', font=('Arial', 10, 'bold')).grid(row=2, column=0, columnspan=2, sticky='w', pady=(10,0))

        tk.Label(frm, text='Scan ports threshold:').grid(row=3, column=0, sticky='e')
        entries['scan'] = tk.Entry(frm); entries['scan'].grid(row=3, column=1)
        entries['scan'].insert(0, thresholds.get('SCAN_PORT_THRESHOLD', self.ipv6_detector.SCAN_PORT_THRESHOLD))

        tk.Label(frm, text='SYN flood threshold:').grid(row=4, column=0, sticky='e')
        entries['syn'] = tk.Entry(frm); entries['syn'].grid(row=4, column=1)
        entries['syn'].insert(0, thresholds.get('SYN_FLOOD_THRESHOLD', self.ipv6_detector.SYN_FLOOD_THRESHOLD))

        tk.Label(frm, text='UDP flood threshold:').grid(row=5, column=0, sticky='e')
        entries['udp'] = tk.Entry(frm); entries['udp'].grid(row=5, column=1)
        entries['udp'].insert(0, thresholds.get('UDP_FLOOD_THRESHOLD', self.ipv6_detector.UDP_FLOOD_THRESHOLD))

        tk.Label(frm, text='ICMP flood threshold:').grid(row=6, column=0, sticky='e')
        entries['icmp'] = tk.Entry(frm); entries['icmp'].grid(row=6, column=1)
        entries['icmp'].insert(0, thresholds.get('ICMP_FLOOD_THRESHOLD', self.ipv6_detector.ICMP_FLOOD_THRESHOLD))

        tk.Label(frm, text='ARP flood threshold:').grid(row=7, column=0, sticky='e')
        entries['arp'] = tk.Entry(frm); entries['arp'].grid(row=7, column=1)
        entries['arp'].insert(0, thresholds.get('ARP_FLOOD_THRESHOLD', self.ipv6_detector.ARP_FLOOD_THRESHOLD))

        tk.Label(frm, text='DNS flood threshold:').grid(row=8, column=0, sticky='e')
        entries['dns'] = tk.Entry(frm); entries['dns'].grid(row=8, column=1)
        entries['dns'].insert(0, thresholds.get('DNS_FLOOD_THRESHOLD', self.ipv6_detector.DNS_FLOOD_THRESHOLD))

        tk.Label(frm, text='Time window (s):').grid(row=9, column=0, sticky='e')
        entries['time'] = tk.Entry(frm); entries['time'].grid(row=9, column=1)
        entries['time'].insert(0, thresholds.get('TIME_WINDOW', self.ipv6_detector.TIME_WINDOW))

        # Notifications Section
        tk.Label(frm, text='Notifications & Alerts', font=('Arial', 10, 'bold')).grid(row=10, column=0, columnspan=2, sticky='w', pady=(10,0))
        popup_var = tk.BooleanVar(value=enable_popup)
        tk.Checkbutton(frm, text='Enable Pop-up Alerts for Critical Attacks', variable=popup_var).grid(row=11, column=0, columnspan=2, sticky='w')
        sound_var = tk.BooleanVar(value=enable_sound)
        tk.Checkbutton(frm, text='Enable Alert Sound', variable=sound_var).grid(row=12, column=0, columnspan=2, sticky='w')

        # SIEM & Logging Section
        tk.Label(frm, text='SIEM & Logging', font=('Arial', 10, 'bold')).grid(row=13, column=0, columnspan=2, sticky='w', pady=(10,0))
        json_logging_var = tk.BooleanVar(value=enable_json_logging)
        tk.Checkbutton(frm, text='Enable JSON Logging (alerts.jsonl)', variable=json_logging_var).grid(row=14, column=0, columnspan=2, sticky='w')

        # Advanced Features Section
        tk.Label(frm, text='Advanced Features', font=('Arial', 10, 'bold')).grid(row=15, column=0, columnspan=2, sticky='w', pady=(10,0))
        geo_var = tk.BooleanVar(value=enable_geolocation)
        tk.Checkbutton(frm, text='Enable IP Geolocation (for alerts)', variable=geo_var).grid(row=16, column=0, columnspan=2, sticky='w')
        
        # E - Heatmap
        heatmap_var = tk.BooleanVar(value=enable_heatmap)
        tk.Checkbutton(frm, text='Enable Attack Heatmap', variable=heatmap_var).grid(row=17, column=0, columnspan=2, sticky='w')
        
        # G - Webhook & REST API
        tk.Label(frm, text='Integrations', font=('Arial', 10, 'bold')).grid(row=18, column=0, columnspan=2, sticky='w', pady=(10,0))
        webhook_var = tk.BooleanVar(value=enable_webhook)
        tk.Checkbutton(frm, text='Enable Webhook Alerts', variable=webhook_var).grid(row=19, column=0, columnspan=2, sticky='w')
        tk.Label(frm, text='Webhook URL:').grid(row=20, column=0, sticky='e')
        webhook_entry = tk.Entry(frm, width=30)
        webhook_entry.grid(row=20, column=1)
        webhook_entry.insert(0, webhook_url)
        
        api_var = tk.BooleanVar(value=enable_rest_api)
        tk.Checkbutton(frm, text='Enable REST API (Port 5000)', variable=api_var).grid(row=21, column=0, columnspan=2, sticky='w')
        
        # H - Syslog
        syslog_var = tk.BooleanVar(value=enable_syslog)
        tk.Checkbutton(frm, text='Enable Syslog Integration', variable=syslog_var).grid(row=22, column=0, columnspan=2, sticky='w')
        tk.Label(frm, text='Syslog Host:').grid(row=23, column=0, sticky='e')
        syslog_host_entry = tk.Entry(frm, width=30)
        syslog_host_entry.grid(row=23, column=1)
        syslog_host_entry.insert(0, syslog_host)
        
        # I - Encryption
        enc_var = tk.BooleanVar(value=enable_encryption)
        tk.Checkbutton(frm, text='Enable Log Encryption (Fernet)', variable=enc_var).grid(row=24, column=0, columnspan=2, sticky='w')

        # Whitelist / Blacklist
        tk.Label(frm, text='Whitelist (one IP per line):', font=('Arial', 10, 'bold')).grid(row=25, column=0, columnspan=2, sticky='w', pady=(10,0))
        wl_text = scrolledtext.ScrolledText(frm, width=40, height=5)
        wl_text.grid(row=26, column=0, columnspan=2, pady=5)
        wl_text.insert(tk.END, '\n'.join(whitelist))

        tk.Label(frm, text='Blacklist (one IP per line):', font=('Arial', 10, 'bold')).grid(row=27, column=0, columnspan=2, sticky='w', pady=(10,0))
        bl_text = scrolledtext.ScrolledText(frm, width=40, height=5)
        bl_text.grid(row=28, column=0, columnspan=2, pady=5)
        bl_text.insert(tk.END, '\n'.join(blacklist))

        btn_frame = tk.Frame(frm)
        btn_frame.grid(row=29, column=0, columnspan=2, pady=10)
        tk.Button(btn_frame, text='Save', command=save_config).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text='Cancel', command=win.destroy).pack(side=tk.LEFT, padx=5)

    # ------------------------------
    # Run GUI
    # ------------------------------
    def run(self):
        self.root.mainloop()

    # ------------------------------
    # Authentication / Users
    # ------------------------------
    def _load_or_create_users(self):
        # users file at ids_advanced/users.json
        try:
            if os.path.exists(self.users_path):
                with open(self.users_path, 'r', encoding='utf-8') as f:
                    self._users = json.load(f)
            else:
                # create default admin user with password 'rayou'
                salt = secrets.token_hex(8)
                default_pw = 'rayou'
                pw_hash = hashlib.sha256((default_pw + salt).encode('utf-8')).hexdigest()
                self._users = {'users': [{'username': 'rayou', 'password_hash': pw_hash, 'salt': salt, 'role': 'admin'}]}
                with open(self.users_path, 'w', encoding='utf-8') as f:
                    json.dump(self._users, f, indent=2)
                try:
                    messagebox.showinfo('Default User Created', "Default admin created: username='rayou' password='rayou'. ")
                except Exception:
                    pass
        except Exception:
            self._users = {'users': []}

    def _save_users(self):
        try:
            with open(self.users_path, 'w', encoding='utf-8') as f:
                json.dump(self._users, f, indent=2)
        except Exception:
            pass

    def _hash_password(self, password, salt):
        return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

    def _verify_user(self, username, password):
        for u in self._users.get('users', []):
            if u.get('username') == username:
                salt = u.get('salt', '')
                if self._hash_password(password, salt) == u.get('password_hash'):
                    return True, u.get('role', 'user')
                return False, None
        return False, None

    def show_login_dialog(self):
        win = tk.Toplevel(self.root)
        win.title('Login - IDS Admin')
        win.geometry('350x180')
        win.transient(self.root)
        win.grab_set()

        frm = tk.Frame(win, padx=10, pady=10)
        frm.pack(fill=tk.BOTH, expand=True)

        tk.Label(frm, text='Username:').grid(row=0, column=0, sticky='e')
        user_entry = tk.Entry(frm)
        user_entry.grid(row=0, column=1, pady=5)
        user_entry.insert(0, 'rayou')

        tk.Label(frm, text='Password:').grid(row=1, column=0, sticky='e')
        pass_entry = tk.Entry(frm, show='*')
        pass_entry.grid(row=1, column=1, pady=5)

        msg_label = tk.Label(frm, text='', fg='red')
        msg_label.grid(row=2, column=0, columnspan=2)

        def attempt_login():
            username = user_entry.get().strip()
            password = pass_entry.get()
            ok, role = self._verify_user(username, password)
            if ok:
                self.authenticated = True
                self.current_user = username
                self.current_role = role
                win.destroy()
            else:
                msg_label.config(text='Utilisateur/mot de passe invalide')
                try:
                    messagebox.showerror('Erreur', 'Utilisateur/mot de passe invalide')
                except Exception:
                    pass

        def cancel():
            self.authenticated = False
            win.destroy()

        btn_frame = tk.Frame(frm)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(btn_frame, text='Login', command=attempt_login).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text='Cancel', command=cancel).pack(side=tk.LEFT, padx=5)

        self.root.wait_window(win)

    def change_password_dialog(self):
        win = tk.Toplevel(self.root)
        win.title('Change Admin Password')
        win.geometry('380x220')
        win.transient(self.root)
        frm = tk.Frame(win, padx=10, pady=10)
        frm.pack(fill=tk.BOTH, expand=True)

        tk.Label(frm, text='Current password:').grid(row=0, column=0, sticky='e')
        cur_entry = tk.Entry(frm, show='*')
        cur_entry.grid(row=0, column=1, pady=5)

        tk.Label(frm, text='New password:').grid(row=1, column=0, sticky='e')
        new_entry = tk.Entry(frm, show='*')
        new_entry.grid(row=1, column=1, pady=5)

        tk.Label(frm, text='Confirm new password:').grid(row=2, column=0, sticky='e')
        conf_entry = tk.Entry(frm, show='*')
        conf_entry.grid(row=2, column=1, pady=5)

        msg = tk.Label(frm, text='', fg='red')
        msg.grid(row=3, column=0, columnspan=2)

        def do_change():
            cur = cur_entry.get()
            new = new_entry.get()
            conf = conf_entry.get()
            ok, role = self._verify_user(self.current_user, cur)
            if not ok:
                msg.config(text='Current password incorrect')
                return
            if new != conf or not new:
                msg.config(text='New passwords do not match or empty')
                return
            # update user record
            for u in self._users.get('users', []):
                if u.get('username') == self.current_user:
                    salt = secrets.token_hex(8)
                    u['salt'] = salt
                    u['password_hash'] = self._hash_password(new, salt)
                    self._save_users()
                    messagebox.showinfo('Password Changed', 'Password updated successfully')
                    win.destroy()
                    return
            msg.config(text='User not found')

        tk.Button(frm, text='Change', command=do_change).grid(row=4, column=0, pady=10)
        tk.Button(frm, text='Cancel', command=win.destroy).grid(row=4, column=1, pady=10)
