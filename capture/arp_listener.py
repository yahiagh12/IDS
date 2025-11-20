# capture/arp_listener.py
"""
Module arp_listener

Ce module écoute les paquets ARP sur une interface réseau donnée
et affiche les adresses IP et MAC des paquets ARP détectés.
"""

from scapy.all import ARP, sniff

class ARPListener:
    """
    ARPListener : capture et affiche les paquets ARP sur une interface.
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
        Affiche les informations ARP.
        """
        if packet.haslayer(ARP):
            arp_op = "who-has" if packet[ARP].op == 1 else "is-at"
            print(f"[ARP] {arp_op} | {packet[ARP].psrc} -> {packet[ARP].pdst} | MAC: {packet[ARP].hwsrc}")

    def start(self):
        """Démarre la capture ARP."""
        print(f"[INFO] Démarrage de l'écoute ARP sur l'interface {self.interface}...")
        self.is_running = True
        try:
            sniff(iface=self.interface, filter="arp", prn=self._process_packet, store=False)
        except KeyboardInterrupt:
            print("\n[INFO] Capture ARP arrêtée par l'utilisateur")
        finally:
            self.stop()

    def stop(self):
        """Arrête la capture."""
        self.is_running = False
        print("[INFO] Capture ARP terminée")


# ===== Test du module =====
if __name__ == "__main__":
    listener = ARPListener(interface="lo")  # Remplace "lo" par ton interface
    listener.start()
