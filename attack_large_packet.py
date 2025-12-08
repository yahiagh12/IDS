#!/usr/bin/env python3
"""
Large Packet Flood (Data Flood) Attack Simulation
Sends oversized packets to trigger packet size detection rules.

Threshold: Packets > 3000 bytes
Expected Detection: 'Large Packet Flood' or 'Data Flood'
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
    print("  🔴 LARGE PACKET FLOOD ATTACK SIMULATION")
    print("="*70)
    print("\n📋 Attack Details:")
    print("  • Type: Large Packet/Data Flood")
    print("  • Threshold: Packets > 3000 bytes")
    print("  • Detection: Packet size-based rule")
    print("  • Expected: Attack Type = 'Large Packet Flood'")
    print("  • Action: 🟠 ORANGE (ALERT)\n")

def attack_large_packet_flood():
    """Simulate Large Packet Flood."""
    source_ip = "192.168.1.150"
    target_ip = "127.0.0.1"
    
    print(f"Source IP: {source_ip}")
    print(f"Target IP: {target_ip}")
    print(f"\nSending 10 large packets (~4000 bytes each)...\n")
    
    start_time = time.time()
    
    for i in range(10):
        # Create large payload (4000 bytes)
        payload = "DATADATA" * 500  # ~4000 bytes
        
        pkt = IP(src=source_ip, dst=target_ip) / TCP(
            sport=50000 + i,
            dport=random.randint(1, 65535),
            flags="PSH"  # Push flag
        ) / payload
        
        try:
            packet_size = len(pkt)
            send(pkt, verbose=False)
            elapsed = time.time() - start_time
            print(f"  [{i+1:2d}/10] Large packet sent ({packet_size} bytes) (elapsed: {elapsed:.2f}s)")
        except Exception as e:
            print(f"  ❌ Error sending packet {i+1}: {e}")
            return False
        
        time.sleep(0.1)  # 100ms between packets
    
    elapsed = time.time() - start_time
    print(f"\n✅ Attack complete in {elapsed:.2f}s")
    print(f"\n📊 Statistics:")
    print(f"  • Packets sent: 10")
    print(f"  • Packet size: ~4000 bytes")
    print(f"  • Duration: {elapsed:.2f}s")
    print(f"  • Total data: ~40 KB")
    print(f"  • Threshold met: {'Yes ✓' if 4000 > 3000 else 'No'}")
    return True

def main():
    print_header()
    
    print("⚠️  Setup Required:")
    print("  1. Start the GUI with 'python3 ids/gui/capture_gui.py'")
    print("  2. Click 'Start Capture' and select 'lo' interface")
    print("  3. Watch the 'Detections' tab for alerts\n")
    
    try:
        input("Press Enter to start Large Packet Flood attack...")
        success = attack_large_packet_flood()
        
        if success:
            print("\n✅ Check GUI for 'Large Packet Flood' detection!")
            print("\n💡 What you should see:")
            print("  • In 'Detections' tab: Attack Type = 'Large Packet Flood'")
            print("  • Color: 🟠 ORANGE")
            print("  • Packet size: > 3000 bytes")
            print("  • Source: 192.168.1.150")
        else:
            print("\n❌ Attack simulation failed")
            sys.exit(1)
    
    except PermissionError:
        print("\n❌ ERROR: This script needs sudo to send packets!")
        print("\nRun with:")
        print("  sudo /home/yaya/Documents/IDS/ids_venv/bin/python attack_large_packet.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
