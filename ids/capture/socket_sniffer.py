# socket_sniffer.py
import socket
from datetime import datetime
import struct

class SocketSniffer:
    """
    Sniffer basé sur les sockets brutes.
    Simple, léger, mais demande décodage manuel.
    """

    def __init__(self, interface=None):
        self.interface = interface

    def start(self, callback):
        """
        Capture brute IPv4.
        """

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        while True:
            raw_packet, _ = sock.recvfrom(65535)
            ip_header = raw_packet[14:34]

            try:
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                proto = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])

                proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, "OTHER")

                packet_dict = {
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto_name,
                    "length": len(raw_packet),
                    "summary": "RawSocketPacket"
                }

                callback(packet_dict)

            except Exception:
                continue
