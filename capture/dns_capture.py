from scapy.all import sniff, UDP, DNS

class DNSListener:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.is_running = False

    def _process_packet(self, pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(UDP):
            pkt.protocol = "dns"
            return pkt

    def sniff_one(self):
        sniff(iface=self.interface, filter="udp port 53", prn=self._process_packet, count=1, store=False)

    def start(self):
        self.is_running = True

    def stop(self):
        self.is_running = False
