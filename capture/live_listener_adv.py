import threading
import time
from .arp_listener import ARPListener
from .icmp_monitor import ICMPMonitor
from .dns_capture import DNSListener
from .ipv6_capture import IPv6Capture

class LiveListener:
    """
    LiveListener : combine plusieurs modules de capture et exécute la capture en live.
    """

    def __init__(self, interface="eth0", backends=None):
        """
        Args:
            interface (str): interface réseau à écouter
            backends (list): types de capture à activer : "arp", "icmp", "dns", "ipv6"
        """
        self.interface = interface
        self.backends = backends if backends else ["arp", "icmp", "dns", "ipv6"]
        self.listeners = []
        self.threads = []
        self.is_running = False

        self._init_listeners()

    def _init_listeners(self):
        """Initialise les modules de capture selon les backends demandés."""
        for backend in self.backends:
            if backend == "arp":
                self.listeners.append(ARPListener(interface=self.interface))
            elif backend == "icmp":
                self.listeners.append(ICMPMonitor(interface=self.interface))
            elif backend == "dns":
                self.listeners.append(DNSListener(interface=self.interface))
            elif backend == "ipv6":
                self.listeners.append(IPv6Capture(interface=self.interface))
            else:
                print(f"[LiveListener] Backend inconnu : {backend}")

    def _run_listener(self, listener, callback):
        """Démarre un listener et envoie chaque paquet au callback."""
        # On peut redéfinir _process_packet pour appeler callback
        original_process = listener._process_packet
        def new_process(packet):
            original_process(packet)
            if callback:
                callback(packet)
        listener._process_packet = new_process
        listener.start()

    def listen(self, callback=None):
        """Démarre tous les listeners en threads séparés."""
        print(f"[LiveListener] Démarrage de la capture live sur {self.interface}...")
        self.is_running = True

        for listener in self.listeners:
            t = threading.Thread(target=self._run_listener, args=(listener, callback))
            t.daemon = True
            t.start()
            self.threads.append(t)

        try:
            while self.is_running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[LiveListener] Capture live arrêtée par l'utilisateur")
        finally:
            self.stop()

    def stop(self):
        """Arrête tous les listeners."""
        self.is_running = False
        for listener in self.listeners:
            listener.stop()
        print("[LiveListener] Tous les listeners ont été arrêtés")


# ===== Test du module =====
if __name__ == "__main__":
    def print_packet(pkt):
        print(f"[PACKET] {pkt.summary() if hasattr(pkt, 'summary') else pkt}")

    listener = LiveListener(interface="lo", backends=["arp", "icmp", "dns"])
    listener.listen(callback=print_packet)
