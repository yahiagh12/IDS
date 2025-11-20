# capture/icmp_monitor.py
"""
Module icmp_monitor

Capture et affiche les paquets ICMP (ping) sur une interface réseau.
"""

from scapy.all import sniff, ICMP, IP

class ICMPMonitor:
    """
    ICMPMonitor : capture les paquets ICMP et affiche source, destination et type.
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
        Affiche les informations ICMP.
        """
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            icmp_type = packet[ICMP].type
            print(f"[ICMP] {packet[IP].src} -> {packet[IP].dst} | Type: {icmp_type}")

    def start(self):
        """Démarre la capture ICMP."""
        print(f"[INFO] Démarrage de la capture ICMP sur l'interface {self.interface}...")
        self.is_running = True
        try:
            sniff(iface=self.interface, filter="icmp", prn=self._process_packet, store=False)
        except KeyboardInterrupt:
            print("\n[INFO] Capture ICMP arrêtée par l'utilisateur")
        finally:
            self.stop()

    def stop(self):
        """Arrête la capture."""
        self.is_running = False
        print("[INFO] Capture ICMP terminée")


# ===== Test du module =====
if __name__ == "__main__":
    monitor = ICMPMonitor(interface="lo")  # Remplace "lo" par ton interface
    monitor.start()
