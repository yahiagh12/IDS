import pyshark
from typing import Optional

from ids.capture.helpers import make_packet_dict


class PysharkCapture:

    def __init__(self, interface: Optional[str] = None, display_filter: str = "ip or arp"):
        self.interface = interface
        self.display_filter = display_filter
        self._cap: Optional[pyshark.LiveCapture] = None
        self._running = False

    def start(self, callback):
        """Start capture; loop is stoppable by calling `stop()` which closes the capture."""
        self._cap = pyshark.LiveCapture(interface=self.interface, display_filter=self.display_filter)
        self._running = True

        try:
            for pkt in self._cap:
                if not self._running:
                    break
                try:
                    # Handle ARP packets
                    if hasattr(pkt, 'arp'):
                        arp_layer = pkt.arp
                        src = getattr(arp_layer, 'src_proto_ipv4', None) or getattr(arp_layer, 'src', None)
                        dst = getattr(arp_layer, 'dst_proto_ipv4', None) or getattr(arp_layer, 'dst', None)
                        proto = 'ARP'
                        length = getattr(pkt, 'length', 0)
                        summary = str(pkt)
                        
                        arp_raw = {
                            'arp_psrc': src,
                            'arp_pdst': dst,
                            'arp_hwsrc': getattr(arp_layer, 'src_hw_mac', None),
                            'arp_hwdst': getattr(arp_layer, 'dst_hw_mac', None),
                            'arp_op': getattr(arp_layer, 'opcode', None),
                            'pyshark': True
                        }
                        
                        packet_dict = make_packet_dict(src, dst, proto, int(length) if length else 0, summary, raw=arp_raw)
                        callback(packet_dict)
                        continue
                    
                    # Handle IP-based packets
                    if not hasattr(pkt, 'ip'):
                        continue
                    
                    src = getattr(pkt.ip, 'src', None)
                    dst = getattr(pkt.ip, 'dst', None)
                    
                    # Determine protocol - check multiple sources for reliability
                    proto = "OTHER"
                    
                    # First check for specific layers
                    if hasattr(pkt, 'tcp'):
                        proto = "TCP"
                    elif hasattr(pkt, 'udp'):
                        proto = "UDP"
                    elif hasattr(pkt, 'icmp'):
                        proto = "ICMP"
                    else:
                        # Fallback to highest_layer if specific layers not found
                        highest = getattr(pkt, 'highest_layer', None)
                        if highest and highest not in ['DATA', 'RAW', 'UNKNOWN']:
                            proto = highest
                        elif hasattr(pkt, 'ip'):
                            # Use IP protocol number as last resort
                            proto_num = getattr(pkt.ip, 'proto', None)
                            if proto_num == '6':
                                proto = "TCP"
                            elif proto_num == '17':
                                proto = "UDP"
                            elif proto_num == '1':
                                proto = "ICMP"
                    
                    length = getattr(pkt, 'length', None)
                    length = getattr(pkt, 'length', None)
                    summary = str(pkt)
                    
                    # Extract ports for TCP/UDP
                    src_port = None
                    dst_port = None
                    if hasattr(pkt, 'tcp'):
                        src_port = int(getattr(pkt.tcp, 'srcport', 0) or 0)
                        dst_port = int(getattr(pkt.tcp, 'dstport', 0) or 0)
                    elif hasattr(pkt, 'udp'):
                        src_port = int(getattr(pkt.udp, 'srcport', 0) or 0)
                        dst_port = int(getattr(pkt.udp, 'dstport', 0) or 0)
                    
                    packet_dict = make_packet_dict(src, dst, proto, int(length) if length else 0, summary, 
                                                  src_port=src_port, dst_port=dst_port, raw={'pyshark': True})
                    callback(packet_dict)
                except Exception:
                    # best-effort continue
                    continue
        finally:
            try:
                if self._cap:
                    self._cap.close()
            except Exception:
                pass

    def stop(self):
        self._running = False
        try:
            if self._cap:
                self._cap.close()
                self._cap = None  # Reset the capture reference
        except Exception as e:
            print(f"Error stopping Pyshark capture: {e}")

