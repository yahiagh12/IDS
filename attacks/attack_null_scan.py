#!/usr/bin/env python3
"""
NULL Scan Attack Simulation
Sends TCP packets with no flags set.

Pattern: TCP packets with no flags
Expected Detection: 'Null Scan'
Expected Action: ORANGE (ALERT)
"""

import sys
import time
import random
from scapy.all import IP, TCP, send, conf

# Configure Scapy
conf.verb = 0

def print_header():
    print("\n" + "="*70)
    print("  🔴 NULL SCAN ATTACK SIMULATION")
    print("="*70)
    print("\n📋 Attack Details:")
    print("  • Type: NULL Scan (Stealth port scanning)")
    print("  • TCP Flags: None (empty flag set)")
    print("  • Detection: Unusual TCP flag combinations")
    print("  • Expected: Attack Type = 'Null Scan'")
    print("  • Action: 🟠 ORANGE (ALERT)\n")

def attack_null_scan():
    """Simulate NULL Scan."""
    source_ip = "192.168.1.251"
    target_ip = "127.0.0.1"
    
    print(f"Source IP: {source_ip}")
    print(f"Target IP: {target_ip}")
    print(f"\nSending 10 NULL scan packets (no TCP flags)...\n")
    
    start_time = time.time()
    
    for i in range(10):
        # NULL scan: no TCP flags
        pkt = IP(src=source_ip, dst=target_ip) / TCP(
            sport=50000 + i,
            dport=80 + i,
            flags=""  # No flags (NULL)
        )
        
        try:
            send(pkt, verbose=False)
            elapsed = time.time() - start_time
            print(f"  [{i+1:2d}/10] NULL packet to port {80+i} (elapsed: {elapsed:.2f}s)")
            print(f"           Flags: NONE")
        except Exception as e:
            print(f"  ❌ Error sending NULL packet {i+1}: {e}")
            return False
        
        time.sleep(0.1)  # 100ms between packets
    
    elapsed = time.time() - start_time
    print(f"\n✅ NULL scan complete in {elapsed:.2f}s")
    print(f"\n📊 Statistics:")
    print(f"  • Packets sent: 10")
    print(f"  • Duration: {elapsed:.2f}s")
    print(f"  • Rate: {10/elapsed:.1f} packets/sec")
    print(f"  • Flag pattern: No TCP flags set")
    return True

def main():
    print_header()
    
    print("⚠️  Setup Required:")
    print("  1. Start the GUI with 'python3 ids/gui/capture_gui.py'")
    print("  2. Click 'Start Capture' and select 'lo' interface")
    print("  3. Watch the 'Detections' tab for alerts\n")
    
    try:
        input("Press Enter to start NULL Scan attack...")
        success = attack_null_scan()
        
        if success:
            print("\n✅ Check GUI for 'Null Scan' detection!")
            print("\n💡 What you should see:")
            print("  • In 'Detections' tab: Attack Type = 'Null Scan'")
            print("  • Color: 🟠 ORANGE (ALERT)")
            print("  • Source: 192.168.1.251")
            print("  • TCP Flags: None (unusual pattern)")
        else:
            print("\n❌ Attack simulation failed")
            sys.exit(1)
    
    except PermissionError:
        print("\n❌ ERROR: This script needs sudo to send packets!")
        print("\nRun with:")
        print("  sudo /home/yaya/Documents/IDS/ids_venv/bin/python attack_null_scan.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
