#!/usr/bin/env python3
"""
DNS Anomaly/Amplification Attack Simulation
Sends DNS queries from known DNS servers to trigger DNS anomaly detection.

Pattern: DNS queries from 8.8.8.8 and 1.1.1.1
Expected Detection: 'Dns Anomaly'
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
    print("  🔴 DNS ANOMALY ATTACK SIMULATION")
    print("="*70)
    print("\n📋 Attack Details:")
    print("  • Type: DNS Anomaly/Amplification Attack")
    print("  • Sources: Google DNS (8.8.8.8), Cloudflare DNS (1.1.1.1)")
    print("  • Port: 53 (DNS)")
    print("  • Detection: DNS server source IP rule")
    print("  • Expected: Attack Type = 'Dns Anomaly'")
    print("  • Action: 🟠 ORANGE (ALERT)\n")

def attack_dns_anomaly():
    """Simulate DNS Anomaly Attack."""
    target_ip = "127.0.0.1"
    dns_servers = ["8.8.8.8", "1.1.1.1"]
    
    print(f"Target IP: {target_ip}")
    print(f"\nSending DNS queries from known DNS servers (5 each)...\n")
    
    start_time = time.time()
    query_num = 0
    
    for dns_server in dns_servers:
        for i in range(5):
            query_num += 1
            
            # DNS query packet
            pkt = IP(src=dns_server, dst=target_ip) / UDP(
                sport=random.randint(50000, 60000),
                dport=53  # DNS port
            ) / ("DNS_QUERY" * 50)  # DNS query payload
            
            try:
                send(pkt, verbose=False)
                elapsed = time.time() - start_time
                print(f"  [{query_num:2d}/10] Query from {dns_server} (elapsed: {elapsed:.2f}s)")
            except Exception as e:
                print(f"  ❌ Error sending query {query_num}: {e}")
                return False
            
            time.sleep(0.05)  # 50ms between queries
    
    elapsed = time.time() - start_time
    print(f"\n✅ DNS anomaly simulation complete in {elapsed:.2f}s")
    print(f"\n📊 Statistics:")
    print(f"  • Total DNS queries: 10")
    print(f"  • From 8.8.8.8: 5 queries")
    print(f"  • From 1.1.1.1: 5 queries")
    print(f"  • Duration: {elapsed:.2f}s")
    print(f"  • Rate: {10/elapsed:.1f} queries/sec")
    return True

def main():
    print_header()
    
    print("⚠️  Setup Required:")
    print("  1. Start the GUI with 'python3 ids/gui/capture_gui.py'")
    print("  2. Click 'Start Capture' and select 'lo' interface")
    print("  3. Watch the 'Detections' tab for alerts\n")
    
    try:
        input("Press Enter to start DNS Anomaly attack...")
        success = attack_dns_anomaly()
        
        if success:
            print("\n✅ Check GUI for 'Dns Anomaly' detection!")
            print("\n💡 What you should see:")
            print("  • In 'Detections' tab: Attack Type = 'Dns Anomaly'")
            print("  • Color: 🟠 ORANGE (ALERT)")
            print("  • Source IPs: 8.8.8.8 and 1.1.1.1")
            print("  • Port: 53 (DNS)")
            print("  • Count: 10 queries (5 from each DNS server)")
        else:
            print("\n❌ Attack simulation failed")
            sys.exit(1)
    
    except PermissionError:
        print("\n❌ ERROR: This script needs sudo to send packets!")
        print("\nRun with:")
        print("  sudo /home/yaya/Documents/IDS/ids_venv/bin/python attack_dns_anomaly.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
