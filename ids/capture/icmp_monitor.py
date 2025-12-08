from scapy.all import sniff, ICMP, IP

class ICMPMonitor:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.is_running = False

    def _process_packet(self, pkt):
        if pkt.haslayer(ICMP):
            pkt.protocol = "icmp"
            return pkt

    def sniff_one(self):
        sniff(iface=self.interface, filter="icmp", prn=self._process_packet, count=1, store=False)

    def start(self):
        self.is_running = True

    def stop(self):
        self.is_running = False
