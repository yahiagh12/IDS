# runner_capture_adv.py
"""
Runner principal pour le projet ids_advanced.
"""

from .gui.capture_gui_adv import CaptureGUI
from .capture.live_listener_adv import LiveListener
from .traffic_analyser import TrafficAnalyzer

import argparse

# Initialisation du Traffic Analyzer
analyzer = TrafficAnalyzer()


def build_pkt_info(pkt):
    """
    Transforme un paquet brut en format simple pour TrafficAnalyzer et GUI.
    """
    info = {
        "protocol": getattr(pkt, "protocol", "UNKNOWN"),
        "src": getattr(pkt, "src", None),
        "dst": getattr(pkt, "dst", None),
        "sport": getattr(pkt, "sport", None),
        "dport": getattr(pkt, "dport", None),
        "flags": getattr(pkt, "flags", "")
    }
    return info


def run_gui(interface="lo", backends=None):
    """
    Lance l'interface graphique.
    """
    gui = CaptureGUI(interface=interface, backends=backends, analyzer=analyzer)
    gui.run()


def run_console(interface="lo", backends=None, packet_count=5):
    """
    Lance la capture en console + analyse IDS.
    """

    listener = LiveListener(interface=interface, backends=backends)
    captured = [0]

    def limited_callback(pkt):

        # Affichage du paquet brut
        print(pkt)

        # Conversion en format analysable
        pkt_info = build_pkt_info(pkt)

        # Analyse IDS
        analyzer.analyze_packet(pkt_info)

        captured[0] += 1

        if captured[0] >= packet_count:
            listener.stop()
            print("\n=== BASELINE DU TRAFIC ===")
            print(analyzer.get_baseline())

    listener.listen(callback=limited_callback)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Advanced Runner")

    parser.add_argument("--gui", action="store_true", help="Lancer la capture via GUI")
    parser.add_argument("--interface", type=str, default="lo",
                        help="Interface réseau à écouter (ex: eth0, Wi-Fi, lo)")
    parser.add_argument("--backends", type=str, nargs="+",
                        default=["arp", "icmp", "dns", "ipv6"],
                        help="Backends à activer (arp, icmp, dns, ipv6)")
    parser.add_argument("--count", type=int, default=5,
                        help="Nombre de paquets à capturer en mode console")

    args = parser.parse_args()

    if args.gui:
        run_gui(interface=args.interface, backends=args.backends)
    else:
        run_console(interface=args.interface, backends=args.backends, packet_count=args.count)
