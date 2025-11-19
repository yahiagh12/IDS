import pyshark
from datetime import datetime

class PysharkCapture:

    def __init__(self, interface=None, display_filter="ip"):
        self.interface = interface
        self.display_filter = display_filter

    def start(self, callback):
        

        cap = pyshark.LiveCapture(
            interface=self.interface,
            display_filter=self.display_filter
        )

        for pkt in cap:
            try:
                packet_dict = {
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "protocol": pkt.highest_layer,
                    "length": pkt.length,
                    "summary": pkt
                }
                callback(packet_dict)
            except Exception:
                pass 
