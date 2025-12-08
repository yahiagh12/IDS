from ids.capture.scapy_capture import ScapyCapture
from ids.capture.pyshark_capture import PysharkCapture
from ids.capture.socket_sniffer import SocketSniffer
import threading
import time

class LiveListener:
    """
    LiveListener permet de capturer les paquets réseau en temps réel
    avec plusieurs backends : Scapy, PyShark et raw socket.
    """

    def __init__(self, interface=None, filter_exp="ip"):
        """
        :param interface: interface réseau à écouter (ex: 'wlan0')
        :param filter_exp: filtre BPF / display filter (ex: 'ip')
        """
        self.interface = interface
        self.filter_exp = filter_exp
        self.is_running = False

        # Initialize engines for all backends
        self.engines = {
            "scapy": ScapyCapture(self.interface, self.filter_exp),
            "pyshark": PysharkCapture(self.interface, self.filter_exp),
            "socket": SocketSniffer(self.interface)
        }

        self.threads = []

    def listen(self, callback):
        """
        Démarre la capture avec tous les backends.
        :param callback: fonction qui reçoit chaque paquet capturé
        """
        print(f"[LiveListener] Starting capture on interface {self.interface}")
        self.is_running = True

        try:
            # Launch a thread for each engine
            for backend, engine in self.engines.items():
                t = threading.Thread(target=self._capture_thread, args=(engine, callback, backend))
                t.daemon = True
                t.start()
                self.threads.append(t)

            # Wait until stopped
            while self.is_running:
                time.sleep(0.1)

        except KeyboardInterrupt:
            print("\n[LiveListener] Capture stopped by user")
        except Exception as e:
            print(f"[LiveListener] Error: {e}")
        finally:
            self.stop()
            print("[LiveListener] Capture ended")

    def _capture_thread(self, engine, callback, backend):
        """Thread pour la capture des paquets"""
        try:
            print(f"[LiveListener] Starting {backend} backend")
            engine.start(callback)
        except Exception as e:
            print(f"[LiveListener] {backend} thread error: {e}")
            self.is_running = False

    def stop(self):
        """Arrête la capture"""
        self.is_running = False
        for backend, engine in self.engines.items():
            try:
                if hasattr(engine, 'stop'):
                    engine.stop()
                print(f"[LiveListener] Stopped {backend} backend")
            except Exception as e:
                print(f"[LiveListener] Error stopping {backend} backend: {e}")

# ===== TEST CODE - RUN DIRECTLY =====
def print_packet(pkt):
    """Simple callback to print packets"""
    print(f"{pkt['timestamp']} | {pkt['src_ip']:15} -> {pkt['dst_ip']:15} | {pkt['protocol']:6} | {pkt['length']:4} bytes")

if __name__ == "__main__":
    print("=== Testing LiveListener ===")
    
    # Test different backends
    backends = ["scapy", "socket"]  # Start with these
    
    for backend in backends:
        print(f"\n--- Testing {backend} backend ---")
        
        
        try:
            listener = LiveListener(
                backend=backend, 
                interface="lo",  # Use loopback for testing
                filter_exp="ip"
            )
            
            # use a mutable container so the nested callback can modify the counter
            packet_count = [0]
            def test_callback(pkt):
                packet_count[0] += 1
                print_packet(pkt)
                # Stop after 5 packets for testing
                if packet_count[0] >= 5:
                    print(f"✓ Captured {packet_count[0]} packets with {backend}")
                    listener.stop()
            
            print(f"Starting {backend} capture... (Press Ctrl+C to stop)")
            listener.listen(test_callback)
            
        except KeyboardInterrupt:
            print(f"Stopped {backend} backend test")
            continue
        except Exception as e:
            print(f"✗ Error with {backend} backend: {e}")
            continue
    
    print("\n=== All tests completed ===")