import threading
import time
from .arp_listener import ARPListener
from .icmp_monitor import ICMPMonitor
from .dns_capture import DNSListener
from .ipv6_capture import IPv6Capture

class LiveListener:
    """
    LiveListener : combine plusieurs modules de capture et envoie chaque paquet au callback
    (ex: GUI) pour affichage en temps réel.
    """

    def __init__(self, interface="eth0", backends=None):
        self.interface = interface
        self.backends = backends if backends else ["arp", "icmp", "dns", "ipv6"]
        self.listeners = []
        self.threads = []
        self.is_running = False
        self._init_listeners()

    def _init_listeners(self):
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
        """Boucle continue pour capturer les paquets et les envoyer au callback"""
        original_process = listener._process_packet

        def new_process(pkt):
            original_process(pkt)
            if callback:
                # Transfert du paquet vers le GUI
                callback(pkt)

        listener._process_packet = new_process

        # Boucle infinie tant que is_running=True
        while self.is_running:
            try:
                # Capture un seul paquet sans bloquer
                listener.sniff_one()
            except Exception:
                time.sleep(0.05)

    def listen(self, callback=None):
        """Démarre tous les listeners dans des threads et envoie paquets au callback"""
        print(f"[INFO] Démarrage de la capture live sur {self.interface}...")
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
            print("\n[INFO] Capture stoppée par l'utilisateur")
            self.stop()

    def stop(self):
        """Arrête tous les listeners"""
        self.is_running = False
        for listener in self.listeners:
            listener.stop()
        print("[INFO] Tous les listeners ont été arrêtés")
