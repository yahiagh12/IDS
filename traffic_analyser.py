# ids_advanced/traffic_analyser.py
from collections import Counter, defaultdict

class TrafficAnalyzer:
    def __init__(self):
        self.protocol_count = Counter()
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.dns_queries = Counter()
        self.icmp_count = 0
        self.arp_count = 0

        # TCP spécifique
        self.tcp_connections = defaultdict(list)  # clé = (src, dst, sport, dport), valeur = liste de flags
        self.tcp_flags_count = Counter()          # flags anormaux
        self.port_usage = Counter()               # ports utilisés

    def analyze_packet(self, pkt):
        proto = pkt.get("protocol")
        self.protocol_count[proto] += 1

        src = pkt.get("src")
        dst = pkt.get("dst")
        sport = pkt.get("sport")
        dport = pkt.get("dport")

        # Comptage IPs
        if src:
            self.src_ips[src] += 1
        if dst:
            self.dst_ips[dst] += 1

        # DNS
        if proto == "DNS":
            query = pkt.get("query_name", "unknown")
            self.dns_queries[query] += 1

        # ICMP
        if proto == "ICMP":
            self.icmp_count += 1

        # ARP
        if proto == "ARP":
            self.arp_count += 1

        # TCP spécifique
        if proto == "TCP" and sport and dport:
            flags = pkt.get("flags", "")
            conn_key = (src, dst, sport, dport)
            self.tcp_connections[conn_key].append(flags)
            self.tcp_flags_count[flags] += 1
            self.port_usage[sport] += 1
            self.port_usage[dport] += 1

    def get_baseline(self):
        """Retourne les métriques réseau normales et flags TCP"""
        # TCP handshake complet (SYN->SYN/ACK->ACK)
        handshake_ok = 0
        for flags_seq in self.tcp_connections.values():
            if "S" in flags_seq and "SA" in flags_seq and "A" in flags_seq:
                handshake_ok += 1

        return {
            "protocol_count": dict(self.protocol_count),
            "top_src_ips": self.src_ips.most_common(10),
            "top_dst_ips": self.dst_ips.most_common(10),
            "dns_queries": self.dns_queries.most_common(10),
            "icmp_count": self.icmp_count,
            "arp_count": self.arp_count,
            "tcp_handshake_ok": handshake_ok,
            "tcp_flags_count": dict(self.tcp_flags_count),
            "port_usage": dict(self.port_usage)
        }
