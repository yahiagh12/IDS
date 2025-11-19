from ids.capture.scapy_capture import ScapyCapture
from ids.capture.pyshark_capture import PysharkCapture
from ids.capture.socket_sniffer import SocketSniffer
import threading

class LiveListener:
    """
    LiveListener permet de capturer les paquets réseau en temps réel
    avec plusieurs backends : Scapy, PyShark ou raw socket.
    """

    def __init__(self, backend="scapy", interface=None, filter_exp="ip"):
        """
        :param backend: 'scapy', 'pyshark' ou 'socket'
        :param interface: interface réseau à écouter (ex: 'wlan0')
        :param filter_exp: filtre BPF / display filter (ex: 'ip')
        """
        self.backend = backend.lower()
        self.interface = interface
        self.filter_exp = filter_exp
        self.engine = self._init_engine()

    def _init_engine(self):
        if self.backend == "scapy":
            return ScapyCapture(self.interface, self.filter_exp)
        elif self.backend == "pyshark":
            return PysharkCapture(self.interface, self.filter_exp)
        elif self.backend == "socket":
            return SocketSniffer()
        else:
            raise ValueError(f"Backend inconnu: {self.backend}")

    def listen(self, callback):
        """
        Démarre la capture avec le backend choisi.
        :param callback: fonction qui reçoit chaque paquet capturé
        """
        print(f"[LiveListener] Starting capture using {self.backend} on interface {self.interface}")
        try:
            # Lancer dans un thread pour ne pas bloquer le terminal
            t = threading.Thread(target=self.engine.start, args=(callback,))
            t.daemon = True
            t.start()
            t.join()  # Optionnel : attendre la fin si count est défini dans le backend
        except KeyboardInterrupt:
            print("[LiveListener] Capture stopped by user")
        except Exception as e:
            print(f"[LiveListener] Error: {e}")
        finally:
            self.engine.stop()
            print("[LiveListener] Capture ended")