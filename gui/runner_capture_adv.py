# runner_capture_adv.py
"""
Runner principal pour le projet ids_advanced.

Permet de lancer la capture réseau via GUI ou directement en console.
"""

from ids.gui.capture_gui_adv import CaptureGUI
from ids.capture.live_listener_adv import LiveListener
import argparse

def run_gui(interface="lo", backends=None):
    """
    Lance l'interface graphique.
    """
    gui = CaptureGUI(interface=interface, backends=backends)
    gui.run()

def run_console(interface="lo", backends=None, packet_count=5):
    """
    Lance la capture en console et affiche les paquets.
    """
    def print_packet(pkt):
        print(pkt)

    listener = LiveListener(interface=interface, backends=backends)
    
    captured = [0]  # compteur de paquets

    def limited_callback(pkt):
        print_packet(pkt)
        captured[0] += 1
        if captured[0] >= packet_count:
            listener.stop()

    listener.listen(callback=limited_callback)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Advanced Runner")
    parser.add_argument("--gui", action="store_true", help="Lancer la capture via GUI")
    parser.add_argument("--interface", type=str, default="lo", help="Interface réseau à écouter")
    parser.add_argument("--backends", type=str, nargs="+", default=["arp", "icmp", "dns"], help="Backends à activer")
    parser.add_argument("--count", type=int, default=5, help="Nombre de paquets à capturer en console")
    
    args = parser.parse_args()

    if args.gui:
        run_gui(interface=args.interface, backends=args.backends)
    else:
        run_console(interface=args.interface, backends=args.backends, packet_count=args.count)
