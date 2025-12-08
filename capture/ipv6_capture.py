from scapy.all import sniff, IPv6

class IPv6Capture:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.is_running = False

    def _process_packet(self, pkt):
        if pkt.haslayer(IPv6):
            pkt.protocol = "ipv6"
            # Pas de print ici, le callback du LiveListener affichera
            return pkt

    def sniff_one(self):
        """Capture un seul paquet IPv6"""
        sniff(iface=self.interface, filter="ip6", prn=self._process_packet, count=1, store=False)

    def start(self):
        """Ne fait rien : la boucle est gérée par LiveListener"""
        self.is_running = True

    def stop(self):
        self.is_running = False
