# ids_advanced/detection_ipv6.py

from collections import defaultdict, deque
import time
import json
import os


class IPv6AttackDetector:
    """
    Détection des attaques IPv6 :
    - SYN Scan
    - SYN Flood
    - XMAS Scan
    - NULL Scan
    - UDP Flood
    - ICMPv6 Echo Flood (Type 128)

    Partie 4 : Signatures techniques
    Chaque attaque possède une signature pour la distinguer :
        - SYN Scan : SYN sur plusieurs ports, pas d'ACK.
        - XMAS Scan : FIN+PSH+URG.
        - NULL Scan : flags = 0.
        - UDP Flood : volume UDP anormal.
        - ICMP Flood : volume ICMP très élevé.
    """

    def __init__(self):
        # SYN scan : SYN sur plusieurs ports
        self.syn_history = defaultdict(set)  # ip -> ports scannés
        self.syn_timestamps = defaultdict(deque)  # ip -> timestamps

        # SYN flood : volume SYN élevé
        self.syn_counter = defaultdict(int)

        # UDP flood
        self.udp_counter = defaultdict(int)

        # ICMPv6 Echo flood
        self.icmp_echo_counter = defaultdict(int)

        # ARP Spoofing detection: track IP -> MAC mapping
        self.arp_ip_mac_map = {}  # ip -> set of MAC addresses seen
        self.arp_mac_timeline = defaultdict(deque)  # (ip, mac) -> timestamps for spoofing detection

        # Behavioral Analysis (Section 5)
        self.port_scan_sequences = defaultdict(list)  # ip -> list of (port, timestamp) for sequential detection
        self.ip_packet_volume = defaultdict(int)  # ip -> total packet count (for anomaly detection)
        self.ip_volume_timestamps = defaultdict(deque)  # ip -> deque of timestamps (for rate calculation)
        self.unusual_flags = defaultdict(set)  # ip -> set of unusual flag combinations seen
        self.src_ips_per_protocol = defaultdict(set)  # protocol -> set of source IPs

        # logs
        self.alerts = []

        # valeurs par défaut (peuvent être surchargées par config)
        self.SCAN_PORT_THRESHOLD = 10        # ports différents → scan
        self.SYN_FLOOD_THRESHOLD = 50        # SYN en 3 sec
        self.UDP_FLOOD_THRESHOLD = 80        # UDP en 3 sec
        self.ICMP_FLOOD_THRESHOLD = 60       # ICMPv6 echo en 3 sec
        self.ARP_FLOOD_THRESHOLD = 10        # ARP en 3 sec
        self.DNS_FLOOD_THRESHOLD = 15        # DNS en 3 sec
        
        # Behavioral thresholds
        self.SEQUENTIAL_PORT_THRESHOLD = 5   # Consecutive ports = suspicious
        self.ANOMALY_VOLUME_THRESHOLD = 200  # packets/second = unusual
        self.UNUSUAL_FLAGS_THRESHOLD = 3     # Different unusual flags from one IP

        self.TIME_WINDOW = 3  # secondes pour les floods

        # whitelist / blacklist
        self.whitelist = set()
        self.blacklist = set()

        # Charger config si disponible
        try:
            self.load_config()
        except Exception:
            # ne pas planter si config malformée
            pass
        # -------------------------------
        # Partie 4 : Signatures techniques
        # -------------------------------
        self.signatures = {
            "SYN_SCAN": {
                "protocol": "TCP",
                "flags": "S",
                "description": "SYN sur plusieurs ports, pas d'ACK"
            },
            "XMAS_SCAN": {
                "protocol": "TCP",
                "flags_set": {"F", "P", "U"},
                "description": "Flags FIN+PSH+URG"
            },
            "NULL_SCAN": {
                "protocol": "TCP",
                "flags": "",
                "description": "Flags TCP = 0"
            },
            "UDP_FLOOD": {
                "protocol": "UDP",
                "volume_threshold": self.UDP_FLOOD_THRESHOLD,
                "description": "Volume UDP anormal"
            },
            "ICMP_FLOOD": {
                "protocol": "ICMPv6",
                "icmp_type": 128,
                "volume_threshold": self.ICMP_FLOOD_THRESHOLD,
                "description": "Volume ICMPv6 très élevé"
            }
        }

    # ==================================================================
    # ======================= MAIN PACKET HANDLER ======================
    # ==================================================================

    def analyze_packet(self, pkt):
        """
        pkt = {
            "src": ...,
            "dst": ...,
            "protocol": "TCP" / "UDP" / "ICMPv6" / "ARP" / "DNS",
            "flags": "S" / "FPU" / "",
            "icmp_type": 128,
            "port": 80
        }
        """
        proto = (pkt.get("protocol") or "").upper()

        src = pkt.get("src")
        # whitelist: ignorer les sources explicitement confiantes
        if src and src in self.whitelist:
            return

        # blacklist: alerter immédiatement
        if src and src in self.blacklist:
            self._raise_alert("BLACKLISTED IP", f"{src} est sur la liste noire")
            return

        if proto == "TCP":
            self._handle_tcp(pkt)

        elif proto == "UDP":
            self._handle_udp(pkt)

        elif proto in ("ICMPV6", "ICMP"):
            self._handle_icmpv6(pkt)

        elif proto == "ARP":
            self._handle_arp(pkt)

        elif proto == "DNS":
            self._handle_dns(pkt)

        # Section 5: Behavioral Analysis
        self._analyze_behavioral_anomalies(pkt)

    # ==================================================================
    # ============================= TCP ================================
    # ==================================================================

    def _handle_tcp(self, pkt):
        flags = pkt.get("flags", "")
        src = pkt.get("src")
        port = pkt.get("port")

        # ============ 3.1 SYN SCAN IPv6 ============
        if flags == "S":  # SYN only
            self.syn_history[src].add(port)
            self.syn_timestamps[src].append(time.time())

            if len(self.syn_history[src]) >= self.SCAN_PORT_THRESHOLD:
                self._raise_alert(
                    "SYN SCAN IPv6",
                    f"{src} a envoyé des SYN sur {len(self.syn_history[src])} ports différents"
                )

        # ============ 3.2 SYN FLOOD IPv6 ============
        if flags == "S":
            now = time.time()
            self.syn_timestamps[src].append(now)

            # nettoyer ancien historique
            while self.syn_timestamps[src] and now - self.syn_timestamps[src][0] > self.TIME_WINDOW:
                self.syn_timestamps[src].popleft()

            # seuil
            if len(self.syn_timestamps[src]) >= self.SYN_FLOOD_THRESHOLD:
                self._raise_alert(
                    "SYN FLOOD IPv6",
                    f"{src} a envoyé {len(self.syn_timestamps[src])} SYN en {self.TIME_WINDOW} secondes"
                )

        # ============ 3.3 XMAS Scan ============
        if set(flags) == {"F", "P", "U"}:
            self._raise_alert(
                "XMAS SCAN IPv6",
                f"Paquet XMAS détecté depuis {src} vers port {port}"
            )

        # ============ 3.4 NULL Scan ============
        if flags == "" or flags == "0":
            self._raise_alert(
                "NULL SCAN IPv6",
                f"Paquet TCP NULL (flags=0x00) détecté depuis {src}"
            )

    # ==================================================================
    # ============================= UDP ================================
    # ==================================================================

    def _handle_udp(self, pkt):
        src = pkt.get("src")
        now = time.time()

        if "udp_timestamps" not in self.__dict__:
            self.udp_timestamps = defaultdict(deque)

        self.udp_timestamps[src].append(now)

        # remove old timestamps
        while self.udp_timestamps[src] and now - self.udp_timestamps[src][0] > self.TIME_WINDOW:
            self.udp_timestamps[src].popleft()

        if len(self.udp_timestamps[src]) >= self.UDP_FLOOD_THRESHOLD:
            self._raise_alert(
                "UDP FLOOD IPv6",
                f"{src} a envoyé {len(self.udp_timestamps[src])} paquets UDP en {self.TIME_WINDOW} sec"
            )

    # ==================================================================
    # ============================ ICMPv6 ==============================
    # ==================================================================

    def _handle_icmpv6(self, pkt):
        src = pkt.get("src")
        icmp_type = pkt.get("icmp_type")

        now = time.time()

        if "icmp_timestamps" not in self.__dict__:
            self.icmp_timestamps = defaultdict(deque)

        # ============ 3.6 ICMPv6 Echo Flood ============
        if icmp_type == 128:  # Echo Request
            self.icmp_timestamps[src].append(now)

            while self.icmp_timestamps[src] and now - self.icmp_timestamps[src][0] > self.TIME_WINDOW:
                self.icmp_timestamps[src].popleft()

            if len(self.icmp_timestamps[src]) >= self.ICMP_FLOOD_THRESHOLD:
                self._raise_alert(
                    "ICMPv6 ECHO FLOOD",
                    f"{src} a envoyé {len(self.icmp_timestamps[src])} Echo Request (128)"
                )

    # ==================================================================
    # ============================== ARP ===============================
    # ==================================================================

    def _handle_arp(self, pkt):
        """Détection ARP Spoofing et ARP Flood"""
        src = pkt.get("src")
        src_mac = pkt.get("src_mac")  # MAC address field in ARP
        now = time.time()

        if "arp_timestamps" not in self.__dict__:
            self.arp_timestamps = defaultdict(deque)

        self.arp_timestamps[src].append(now)

        # nettoyer ancien historique
        while self.arp_timestamps[src] and now - self.arp_timestamps[src][0] > self.TIME_WINDOW:
            self.arp_timestamps[src].popleft()

        # ============ ARP SPOOFING DETECTION ============
        # Track IP -> MAC mapping to detect spoofing (same IP, different MAC)
        if src and src_mac:
            if src not in self.arp_ip_mac_map:
                # First time seeing this IP
                self.arp_ip_mac_map[src] = {src_mac}
            else:
                # Check if MAC changed for this IP
                if src_mac not in self.arp_ip_mac_map[src]:
                    # Different MAC for same IP = Spoofing !
                    self._raise_alert(
                        "ARP SPOOFING DETECTED",
                        f"IP {src} seen with multiple MAC addresses: {self.arp_ip_mac_map[src]} + new: {src_mac}"
                    )
                    self.arp_ip_mac_map[src].add(src_mac)

        # Détection ARP Flood
        if len(self.arp_timestamps[src]) >= self.ARP_FLOOD_THRESHOLD:
            self._raise_alert(
                "ARP FLOOD",
                f"{src} a envoyé {len(self.arp_timestamps[src])} paquets ARP en {self.TIME_WINDOW} secondes"
            )

    # ==================================================================
    # ============================= DNS ===============================
    # ==================================================================

    def _handle_dns(self, pkt):
        """Détection DNS Flood et DNS Tunneling"""
        src = pkt.get("src")
        now = time.time()

        if "dns_timestamps" not in self.__dict__:
            self.dns_timestamps = defaultdict(deque)

        self.dns_timestamps[src].append(now)

        # nettoyer ancien historique
        while self.dns_timestamps[src] and now - self.dns_timestamps[src][0] > self.TIME_WINDOW:
            self.dns_timestamps[src].popleft()

        # Détection DNS Flood
        if len(self.dns_timestamps[src]) >= self.DNS_FLOOD_THRESHOLD:
            self._raise_alert(
                "DNS FLOOD",
                f"{src} a envoyé {len(self.dns_timestamps[src])} requêtes DNS en {self.TIME_WINDOW} secondes"
            )

    # ==================================================================
    # ========================= BEHAVIORAL ANALYSIS ====================
    # ==================================================================

    def _analyze_behavioral_anomalies(self, pkt):
        """Section 5: Behavioral analysis for unusual patterns"""
        proto = (pkt.get("protocol") or "").upper()
        src = pkt.get("src")
        port = pkt.get("port")
        flags = pkt.get("flags", "")
        now = time.time()

        if not src:
            return

        # Track IP packet volume for anomaly detection
        self.ip_packet_volume[src] += 1
        self.ip_volume_timestamps[src].append(now)

        # Clean old timestamps
        while self.ip_volume_timestamps[src] and now - self.ip_volume_timestamps[src][0] > self.TIME_WINDOW:
            self.ip_volume_timestamps[src].popleft()

        # Anomaly 1: Unusual volume per second
        volume_rate = len(self.ip_volume_timestamps[src]) / self.TIME_WINDOW
        if volume_rate > self.ANOMALY_VOLUME_THRESHOLD:
            self._raise_alert(
                "BEHAVIORAL ANOMALY - HIGH VOLUME",
                f"{src} sending {int(volume_rate)} packets/sec (threshold: {self.ANOMALY_VOLUME_THRESHOLD})"
            )

        # Anomaly 2: Sequential port scanning
        if proto == "TCP" and port:
            self.port_scan_sequences[src].append((port, now))

            # Keep only recent ports (last SCAN_PORT_THRESHOLD seconds)
            self.port_scan_sequences[src] = [
                (p, t) for p, t in self.port_scan_sequences[src]
                if now - t < self.TIME_WINDOW
            ]

            # Check for sequential ports
            if len(self.port_scan_sequences[src]) >= self.SEQUENTIAL_PORT_THRESHOLD:
                ports = sorted([p for p, t in self.port_scan_sequences[src]])
                # Check if ports are consecutive
                is_sequential = all(ports[i+1] - ports[i] <= 2 for i in range(len(ports)-1))
                if is_sequential:
                    self._raise_alert(
                        "BEHAVIORAL ANOMALY - SEQUENTIAL PORT SCAN",
                        f"{src} scanning consecutive ports: {ports}"
                    )

        # Anomaly 3: Unusual flag combinations
        if flags and proto == "TCP":
            # RFC allows: S, SA, A, FA, F, R, RA, RSA, etc.
            # Unusual: combinations like S with U, or P with R
            unusual_combos = [
                {"S", "U"}, {"S", "P"}, {"F", "R"}, {"P", "R", "U"},
                {"S", "F"}, {"S", "R"}, {"A", "F", "U"}
            ]
            flag_set = set(flags)
            for combo in unusual_combos:
                if combo.issubset(flag_set):
                    if flags not in self.unusual_flags[src]:
                        self.unusual_flags[src].add(flags)
                        if len(self.unusual_flags[src]) >= self.UNUSUAL_FLAGS_THRESHOLD:
                            self._raise_alert(
                                "BEHAVIORAL ANOMALY - UNUSUAL FLAGS",
                                f"{src} using unusual TCP flags: {self.unusual_flags[src]}"
                            )

    # ==================================================================
    # ============================= ALERTS =============================
    # ==================================================================

    def _raise_alert(self, attack_type, description):
        event = {
            "attack": attack_type,
            "description": description,
            "timestamp": time.strftime("%H:%M:%S")
        }

        self.alerts.append(event)
        print(f"[ALERT] {attack_type}: {description}")

    def get_alerts(self):
        return self.alerts

    # ------------------------------
    # Configuration loader
    # ------------------------------
    def load_config(self, path=None):
        """Load thresholds, whitelist and blacklist from a JSON config file.
        By default looks for `ids_advanced/config.json` (project-level).
        """
        if path is None:
            # default: project root / ids_advanced / config.json
            base = os.path.dirname(os.path.dirname(__file__))  # project root
            cfg_path = os.path.join(base, 'ids_advanced', 'config.json')
            # if that doesn't exist, try project root
            if not os.path.exists(cfg_path):
                cfg_path = os.path.join(os.path.dirname(__file__), 'config.json')
        else:
            cfg_path = path

        if not os.path.exists(cfg_path):
            return

        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            return

        # apply thresholds
        thresholds = cfg.get('thresholds', {})
        for k, v in thresholds.items():
            if hasattr(self, k):
                try:
                    setattr(self, k, int(v))
                except Exception:
                    pass

        # whitelist / blacklist
        wl = cfg.get('whitelist', []) or []
        bl = cfg.get('blacklist', []) or []
        self.whitelist = set(wl)
        self.blacklist = set(bl)

        return cfg
