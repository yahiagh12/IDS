#!/usr/bin/env python3
"""
Port Scan Attack Simulation
Scans sequential ports on target to trigger port scan detection.

Pattern: Sequential port connections from external IP
Expected Detection: 'Port Scan'
Expected Action: RED (DROP) or ORANGE (ALERT)
"""

import sys
import time
import random
from scapy.all import IP, TCP, send, conf

# Configure Scapy
conf.verb = 0

def print_header():
    print("\n" + "="*70)
    print("  🔴 PORT SCAN ATTACK SIMULATION")
    print("="*70)
    print("\n📋 Attack Details:")
    print("  • Type: Port Scan (Reconnaissance)")
    print("  • Method: Sequential port connections")
    print("  • Source: External IP (203.0.113.50)")
    print("  • Ports: 1-20 (sequential)")
    print("  • Expected: Attack Type = 'Port Scan'")
    print("  • Action: 🔴 RED (DROP) or 🟠 ORANGE (ALERT)\n")

def attack_port_scan():
    """Simulate Port Scan."""
    source_ip = "203.0.113.50"  # External IP
    target_ip = "127.0.0.1"
    
    print(f"Source IP: {source_ip} (External)")
    print(f"Target IP: {target_ip}")
    print(f"\nScanning ports 1-20 sequentially...\n")
    
    start_time = time.time()
    
    for port in range(1, 21):
        pkt = IP(src=source_ip, dst=target_ip) / TCP(
            sport=random.randint(50000, 60000),
            dport=port,
            flags="S"  # SYN
        )
        
        try:
            send(pkt, verbose=False)
            elapsed = time.time() - start_time
            print(f"  [{port:2d}/20] Scanning port {port:2d} (elapsed: {elapsed:.2f}s)")
        except Exception as e:
            print(f"  ❌ Error scanning port {port}: {e}")
            return False
        
        time.sleep(0.1)  # 100ms between ports
    
    elapsed = time.time() - start_time
    print(f"\n✅ Port scan complete in {elapsed:.2f}s")
    print(f"\n📊 Statistics:")
    print(f"  • Ports scanned: 20")
    print(f"  • Duration: {elapsed:.2f}s")
    print(f"  • Rate: {20/elapsed:.1f} ports/sec")
    print(f"  • Pattern: Sequential (1→20)")
    return True

def main():
    print_header()
    
    print("⚠️  Setup Required:")
    print("  1. Start the GUI with 'python3 ids/gui/capture_gui.py'")
    print("  2. Click 'Start Capture' and select 'lo' interface")
    print("  3. Watch the 'Detections' tab for alerts\n")
    
    try:
        input("Press Enter to start Port Scan attack...")
        success = attack_port_scan()
        
        if success:
            print("\n✅ Check GUI for 'Port Scan' detection!")
            print("\n💡 What you should see:")
            print("  • In 'Detections' tab: Multiple port scan attempts")
            print("  • Color: 🔴 RED or 🟠 ORANGE")
            print("  • Source: 203.0.113.50 (blocked external IP)")
            print("  • Ports: 1-20")
        else:
            print("\n❌ Attack simulation failed")
            sys.exit(1)
    
    except PermissionError:
        print("\n❌ ERROR: This script needs sudo to send packets!")
        print("\nRun with:")
        print("  sudo /home/yaya/Documents/IDS/ids_venv/bin/python attack_port_scan.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
