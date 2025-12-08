#!/usr/bin/env python3
"""
External Access Attack Simulation
Simulates unauthorized access attempts from blocked external IPs and DNS servers.

Pattern: Connections from blocked CIDR ranges and DNS servers
Expected Detection: 'External Ip Access' or 'Dns Anomaly'
Expected Action: RED (DROP) for CIDR, ORANGE (ALERT) for DNS
"""

import sys
import time
import random
from scapy.all import IP, TCP, send, conf

# Configure Scapy
conf.verb = 0

def print_header():
    print("\n" + "="*70)
    print("  🔴 EXTERNAL ACCESS ATTACK SIMULATION")
    print("="*70)
    print("\n📋 Attack Details:")
    print("  • Type: Unauthorized External Access")
    print("  • Sources: Blocked CIDR ranges + DNS servers")
    print("  • Detection: CIDR matching + source IP rules")
    print("  • Expected: 'External Ip Access' or 'Dns Anomaly'")
    print("  • Action: 🔴 RED (DROP) or 🟠 ORANGE (ALERT)\n")

def attack_external_access():
    """Simulate unauthorized external access."""
    target_ip = "127.0.0.1"
    
    # External sources: CIDR blocks and DNS servers
    sources = [
        ("203.0.113.100", 22, "SSH (Blocked CIDR 203.0.113.0/24)"),
        ("203.0.113.200", 3306, "MySQL (Blocked CIDR 203.0.113.0/24)"),
        ("198.51.100.100", 5432, "PostgreSQL (Blocked CIDR 198.51.100.0/24)"),
        ("198.51.100.200", 27017, "MongoDB (Blocked CIDR 198.51.100.0/24)"),
        ("8.8.8.8", 53, "DNS - Google (Alert on src IP)"),
        ("1.1.1.1", 53, "DNS - Cloudflare (Alert on src IP)"),
    ]
    
    print(f"Target IP: {target_ip}")
    print(f"\nSimulating access attempts from blocked external IPs...\n")
    
    start_time = time.time()
    
    for i, (src_ip, dport, desc) in enumerate(sources, 1):
        pkt = IP(src=src_ip, dst=target_ip) / TCP(
            sport=random.randint(50000, 60000),
            dport=dport,
            flags="S"  # SYN
        )
        
        try:
            send(pkt, verbose=False)
            elapsed = time.time() - start_time
            print(f"  [{i}/6] {desc}")
            print(f"       From: {src_ip} → Port {dport} (elapsed: {elapsed:.2f}s)")
        except Exception as e:
            print(f"  ❌ Error sending packet {i}: {e}")
            return False
        
        time.sleep(0.2)  # 200ms between attempts
    
    elapsed = time.time() - start_time
    print(f"\n✅ External access simulation complete in {elapsed:.2f}s")
    print(f"\n📊 Statistics:")
    print(f"  • Access attempts: 6")
    print(f"  • Blocked CIDR blocks: 2 (203.0.113.0/24, 198.51.100.0/24)")
    print(f"  • DNS servers: 2 (8.8.8.8, 1.1.1.1)")
    print(f"  • Duration: {elapsed:.2f}s")
    return True

def main():
    print_header()
    
    print("⚠️  Setup Required:")
    print("  1. Start the GUI with 'python3 ids/gui/capture_gui.py'")
    print("  2. Click 'Start Capture' and select 'lo' interface")
    print("  3. Watch the 'Detections' tab for alerts\n")
    
    try:
        input("Press Enter to start External Access attack...")
        success = attack_external_access()
        
        if success:
            print("\n✅ Check GUI for external access detections!")
            print("\n💡 What you should see:")
            print("  • CIDR ranges (203.0.113.x, 198.51.100.x):")
            print("    - Attack Type: 'External Ip Access'")
            print("    - Color: 🔴 RED (DROP)")
            print("  • DNS servers (8.8.8.8, 1.1.1.1):")
            print("    - Attack Type: 'Dns Anomaly'")
            print("    - Color: 🟠 ORANGE (ALERT)")
        else:
            print("\n❌ Attack simulation failed")
            sys.exit(1)
    
    except PermissionError:
        print("\n❌ ERROR: This script needs sudo to send packets!")
        print("\nRun with:")
        print("  sudo /home/yaya/Documents/IDS/ids_venv/bin/python attack_external_access.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
