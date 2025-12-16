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
        self._sock = None
        self._running = False

    def start(self, callback):
        """
        Capture brute IPv4.
        """
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        # if an interface was provided, bind the raw socket to it so we only
        # receive packets from that interface (AF_PACKET accepts (ifname, proto))
        try:
            if self.interface:
                sock.bind((self.interface, 0))
        except Exception:
            # binding can fail if interface doesn't exist or insufficient perms
            pass

        self._sock = sock
        self._running = True
        sock.settimeout(1.0)

        while self._running:
            try:
                raw_packet, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            ip_header = raw_packet[14:34]

            try:
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                proto = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])
                ip_header_len = (iph[0] & 0x0F) * 4

                proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, "OTHER")

                # Extract ports for TCP/UDP
                src_port = None
                dst_port = None
                if proto in [6, 17]:  # TCP or UDP
                    try:
                        transport_header = raw_packet[14 + ip_header_len:14 + ip_header_len + 4]
                        if len(transport_header) >= 4:
                            src_port, dst_port = struct.unpack('!HH', transport_header[:4])
                    except Exception:
                        pass

                from ids.capture.helpers import make_packet_dict
                packet_dict = make_packet_dict(src_ip, dst_ip, proto_name, len(raw_packet), "RawSocketPacket", src_port=src_port, dst_port=dst_port, raw={'raw_len': len(raw_packet)})

                callback(packet_dict)

            except Exception:
                continue

    def stop(self):
        self._running = False
        try:
            if self._sock:
                # Only call shutdown if the socket supports it
                if hasattr(self._sock, 'shutdown'):
                    self._sock.shutdown(socket.SHUT_RDWR)
                self._sock.close()
                self._sock = None  # Reset the socket reference
        except Exception as e:
            print(f"Error stopping socket: {e}")
