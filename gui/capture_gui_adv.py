# gui/capture_gui_adv.py
"""
Module capture_gui_adv

Interface graphique pour le projet ids_advanced.
Permet de démarrer/arrêter la capture et d'afficher les paquets capturés.
"""

import tkinter as tk
from tkinter import scrolledtext
from ids.capture.live_listener_adv import LiveListener
import threading

class CaptureGUI:
    """
    CaptureGUI : Interface graphique pour contrôler la capture réseau.
    """

    def __init__(self, interface="lo", backends=None):
        """
        Args:
            interface (str): interface réseau à écouter
            backends (list): types de capture à activer
        """
        self.interface = interface
        self.backends = backends if backends else ["arp", "icmp", "dns"]
        self.listener = LiveListener(interface=self.interface, backends=self.backends)
        self.root = tk.Tk()
        self.root.title("IDS Advanced - Capture GUI")
        self._build_gui()
        self.thread = None

    def _build_gui(self):
        """Construction de l'interface graphique."""
        # Zone de texte pour afficher les paquets
        self.text_area = scrolledtext.ScrolledText(self.root, width=100, height=30)
        self.text_area.pack(padx=10, pady=10)

        # Boutons Start et Stop
        self.start_button = tk.Button(self.root, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=5)

        self.stop_button = tk.Button(self.root, text="Stop Capture", command=self.stop_capture)
        self.stop_button.pack(side=tk.RIGHT, padx=10, pady=5)

    def _callback(self, pkt):
        """Callback pour afficher les paquets capturés."""
        self.text_area.insert(tk.END, f"{pkt}\n")
        self.text_area.see(tk.END)

    def start_capture(self):
        """Démarre la capture dans un thread séparé."""
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self.listener.listen, args=(self._callback,))
            self.thread.daemon = True
            self.thread.start()
            self.text_area.insert(tk.END, "[INFO] Capture démarrée...\n")

    def stop_capture(self):
        """Arrête la capture."""
        self.listener.stop()
        self.text_area.insert(tk.END, "[INFO] Capture arrêtée.\n")

    def run(self):
        """Lance l'interface graphique."""
        self.root.mainloop()


# ===== Test du module =====
if __name__ == "__main__":
    gui = CaptureGUI(interface="lo", backends=["arp", "icmp", "dns"])
    gui.run()
