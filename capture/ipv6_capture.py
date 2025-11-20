# capture/ipv6_capture.py
"""
Module ipv6_capture

Capture et affiche les paquets IPv6 sur une interface réseau.
"""

from scapy.all import sniff, IPv6

class IPv6Capture:
    """
    IPv6Capture : capture les paquets IPv6 et affiche source, destination et info.
    """

    def __init__(self, interface="eth0"):
        """
        Args:
            interface (str): interface réseau à écouter (ex: "eth0", "wlan0")
        """
        self.interface = interface
        self.is_running = False

    def _process_packet(self, packet):
        """
        Fonction appelée pour chaque paquet capturé.
        Affiche les informations IPv6.
        """
        if packet.haslayer(IPv6):
            print(f"[IPv6] {packet[IPv6].src} -> {packet[IPv6].dst} | Next Header: {packet[IPv6].nh}")

    def start(self):
        """Démarre la capture IPv6."""
        print(f"[INFO] Démarrage de la capture IPv6 sur l'interface {self.interface}...")
        self.is_running = True
        try:
            sniff(iface=self.interface, filter="ip6", prn=self._process_packet, store=False)
        except KeyboardInterrupt:
            print("\n[INFO] Capture IPv6 arrêtée par l'utilisateur")
        finally:
            self.stop()

    def stop(self):
        """Arrête la capture."""
        self.is_running = False
        print("[INFO] Capture IPv6 terminée")


# ===== Test du module =====
if __name__ == "__main__":
    listener = IPv6Capture(interface="lo")  # Remplace "lo" par ton interface
    listener.start()
