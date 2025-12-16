from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP
import time
from typing import Optional

from ids.capture.helpers import make_packet_dict


class ScapyCapture:
    def __init__(self, interface: Optional[str] = None, bpf_filter: str = "ip or arp"):
        self.interface = interface
        # Handle loopback interface - use None filter to capture all
        if interface and interface.lower() in ['lo', 'lo0', 'localhost']:
            self.bpf_filter = None
        else:
            self.bpf_filter = bpf_filter if bpf_filter else None
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

        ip_layer = pkt[IP]
        proto = "OTHER"
        src_port = None
        dst_port = None
        
        # Check by IP protocol number (more reliable on loopback)
        proto_num = ip_layer.proto
        if proto_num == 6:
            proto = "TCP"
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
        elif proto_num == 17:
            proto = "UDP"
            if pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
        elif proto_num == 1:
            proto = "ICMP"
        else:
            # Fallback to layer checking
            if pkt.haslayer(TCP):
                proto = "TCP"
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

        return make_packet_dict(
            src=pkt[IP].src,
            dst=pkt[IP].dst,
            proto=proto,
            length=len(pkt),
            summary=pkt.summary(),
            src_port=src_port,
            dst_port=dst_port,
            raw={
                "scapy": True,
                "proto_num": proto_num,
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
