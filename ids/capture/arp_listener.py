from scapy.all import sniff, ARP

class ARPListener:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.is_running = False

    def _process_packet(self, pkt):
        if pkt.haslayer(ARP):
            pkt.protocol = "arp"
            # Extract source IP and MAC from ARP layer
            arp_layer = pkt[ARP]
            pkt.src = arp_layer.psrc  # ARP sender IP (Proxy Source)
            pkt.src_mac = arp_layer.hwsrc  # ARP sender MAC (Hardware Source)
            pkt.dst = arp_layer.pdst  # ARP target IP (Proxy Destination)
            pkt.dst_mac = arp_layer.hwdst  # ARP target MAC (Hardware Destination)
            return pkt

    def sniff_one(self):
        sniff(iface=self.interface, filter="arp", prn=self._process_packet, count=1, store=False)

    def start(self):
        self.is_running = True

    def stop(self):
        self.is_running = False
