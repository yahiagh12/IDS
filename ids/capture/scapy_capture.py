from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP
import time
from typing import Optional

from ids.capture.helpers import make_packet_dict


class ScapyCapture:
    def __init__(self, interface: Optional[str] = None, bpf_filter: str = "ip or arp"):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False

    def _convert(self, pkt):
        # Handle ARP packets
        if pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            proto = "ARP"
            src = arp_layer.psrc  # ARP source IP
            dst = arp_layer.pdst  # ARP destination IP
            
            arp_raw = {
                'arp_psrc': arp_layer.psrc,
                'arp_pdst': arp_layer.pdst,
                'arp_hwsrc': arp_layer.hwsrc,  # Source MAC
                'arp_hwdst': arp_layer.hwdst,  # Destination MAC
                'arp_op': arp_layer.op,
                'scapy': True,
            }
            
            return make_packet_dict(
                src=src,
                dst=dst,
                proto=proto,
                length=len(pkt),
                summary=pkt.summary(),
                raw=arp_raw,
            )
        
        # Handle IP-based packets (TCP, UDP, ICMP)
        if not pkt.haslayer(IP):
            return None

        proto = "OTHER"
        if pkt.haslayer(TCP):
            proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        # Debug: Scapy raw packet
        print(f"Debug: Scapy raw packet: {pkt.summary()} | Raw: {pkt}")

        return make_packet_dict(
            src=pkt[IP].src,
            dst=pkt[IP].dst,
            proto=proto,
            length=len(pkt),
            summary=pkt.summary(),
            raw={
                "scapy": True,
            },
        )

    def start(self, callback, count: int = 0):
        """Start capturing; this blocks until `stop()` is called."""
        def handler(pkt):
            parsed = self._convert(pkt)
            if parsed:
                callback(parsed)

        self._running = True
        self._sniffer = AsyncSniffer(iface=self.interface, filter=self.bpf_filter, prn=handler, store=False)
        self._sniffer.start()

        # keep running until stop() is called
        try:
            while self._running:
                time.sleep(0.2)
        finally:
            # ensure sniffer is stopped
            try:
                if self._sniffer:
                    self._sniffer.stop()
            except Exception:
                pass

    def stop(self):
        self._running = False
        try:
            if self._sniffer:
                self._sniffer.stop()
        except Exception:
            pass
