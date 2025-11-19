from ids.capture.live_listener import LiveListener

def print_packet(pkt):
    print("[PACKET]", pkt)

if __name__ == "__main__":
    # backend = 'scapy', 'pyshark', 'socket'
    listener = LiveListener(backend="scapy", interface="wlan0")
    print("Starting LiveListener...")
    listener.listen(print_packet)
