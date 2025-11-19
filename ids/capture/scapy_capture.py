from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

class ScapyCapture:
    

    def __init__(self, interface=None, bpf_filter="ip"):
        self.interface = interface
        self.bpf_filter = bpf_filter

    def _convert(self, pkt):
        """Convertit un paquet Scapy en dictionnaire lisible."""
        if not pkt.haslayer(IP):
            return None

        proto = "OTHER"
        if pkt.haslayer(TCP): proto = "TCP"
        elif pkt.haslayer(UDP): proto = "UDP"
        elif pkt.haslayer(ICMP): proto = "ICMP"

        return {
            "timestamp": datetime.now().isoformat(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": proto,
            "length": len(pkt),
            "summary": pkt.summary()
        }

    def start(self, callback, count=0):
        

        def handler(pkt):
            parsed = self._convert(pkt)
            if parsed:
                callback(parsed)

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=handler,
            store=False,
            count=count
        )
