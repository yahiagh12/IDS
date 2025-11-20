# capture/dns_capture.py
"""
Module dns_capture

Capture et affiche les paquets DNS sur une interface réseau.
"""

from scapy.all import sniff, DNS, DNSQR, DNSRR, UDP, IP

class DNSListener:
    """
    DNSListener : capture les paquets DNS et affiche les requêtes et réponses.
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
        Affiche les informations DNS.
        """
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # Requête
                print(f"[DNS Request] {packet[IP].src} -> {packet[IP].dst} | Query: {dns_layer.qd.qname.decode()}")
            elif dns_layer.qr == 1:  # Réponse
                answers = [dns_layer.an[i].rrname.decode() for i in range(dns_layer.ancount)]
                print(f"[DNS Response] {packet[IP].src} -> {packet[IP].dst} | Answers: {answers}")

    def start(self):
        """Démarre la capture DNS."""
        print(f"[INFO] Démarrage de la capture DNS sur l'interface {self.interface}...")
        self.is_running = True
        try:
            sniff(iface=self.interface, filter="udp port 53", prn=self._process_packet, store=False)
        except KeyboardInterrupt:
            print("\n[INFO] Capture DNS arrêtée par l'utilisateur")
        finally:
            self.stop()

    def stop(self):
        """Arrête la capture."""
        self.is_running = False
        print("[INFO] Capture DNS terminée")


# ===== Test du module =====
if __name__ == "__main__":
    listener = DNSListener(interface="lo")  # Remplace "lo" par ton interface
    listener.start()
