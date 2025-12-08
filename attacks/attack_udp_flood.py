#!/usr/bin/env python3
"""
UDP Flood Attack Simulation
Sends rapid UDP packets from a source IP to trigger rate-based detection.

Threshold: 10+ UDP packets in 0.5 seconds
Expected Detection: 'Udp Flood'
Expected Action: ORANGE (ALERT)
"""

import sys
import time
import random
from scapy.all import IP, UDP, send, conf

# Configure Scapy
conf.verb = 0

def print_header():
    print("\n" + "="*70)
    print("  🔴 UDP FLOOD ATTACK SIMULATION")
    print("="*70)
    print("\n📋 Attack Details:")
    print("  • Type: UDP Flood (Denial of Service)")
    print("  • Threshold: 10+ UDP packets in 0.5 seconds")
    print("  • Detection: Rate-based detection")
    print("  • Expected: Attack Type = 'Udp Flood'")
    print("  • Action: 🟠 ORANGE (ALERT)\n")

def attack_udp_flood():
    """Simulate UDP Flood Attack."""
    source_ip = "192.168.1.200"
    target_ip = "127.0.0.1"
    
    print(f"Source IP: {source_ip}")
    print(f"Target IP: {target_ip}")
    print(f"\nSending 15 UDP packets rapidly (0.02s intervals = 0.3s total)...\n")
    
    start_time = time.time()
    
    for i in range(15):
        pkt = IP(src=source_ip, dst=target_ip) / UDP(
            sport=random.randint(10000, 60000),
            dport=random.randint(1, 65535)
        ) / ("FLOOD" * 100)  # Payload
        
        try:
            send(pkt, verbose=False)
            elapsed = time.time() - start_time
            print(f"  [{i+1:2d}/15] UDP sent to port {pkt[UDP].dport} (elapsed: {elapsed:.2f}s)")
        except Exception as e:
            print(f"  ❌ Error sending packet {i+1}: {e}")
            return False
        
        time.sleep(0.02)  # 0.02s interval = 50 packets/sec
    
    elapsed = time.time() - start_time
    print(f"\n✅ Attack complete in {elapsed:.2f}s")
    print(f"\n📊 Statistics:")
    print(f"  • Packets sent: 15")
    print(f"  • Duration: {elapsed:.2f}s")
    print(f"  • Rate: {15/elapsed:.1f} packets/sec")
    print(f"  • Threshold met: {'Yes ✓' if 15 >= 10 else 'No'}")
    return True

def main():
    print_header()
    
    print("⚠️  Setup Required:")
    print("  1. Start the GUI with 'python3 ids/gui/capture_gui.py'")
    print("  2. Click 'Start Capture' and select 'lo' interface")
    print("  3. Watch the 'Detections' tab for alerts\n")
    
    try:
        input("Press Enter to start UDP Flood attack...")
        success = attack_udp_flood()
        
        if success:
            print("\n✅ Check GUI for 'Udp Flood' detection!")
            print("\n💡 What you should see:")
            print("  • In 'Detections' tab: Attack Type = 'Udp Flood'")
            print("  • Color: 🟠 ORANGE")
            print("  • Source: 192.168.1.200")
            print("  • Protocol: UDP")
        else:
            print("\n❌ Attack simulation failed")
            sys.exit(1)
    
    except PermissionError:
        print("\n❌ ERROR: This script needs sudo to send packets!")
        print("\nRun with:")
        print("  sudo /home/yaya/Documents/IDS/ids_venv/bin/python attack_udp_flood.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
