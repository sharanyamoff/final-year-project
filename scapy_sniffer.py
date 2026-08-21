#!/usr/bin/env python3
import sys
import json
import argparse
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether

def packet_callback(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            size = len(packet)
            
            protocol = 'Unknown'
            flags = {'syn': False, 'ack': False, 'fin': False, 'rst': False, 'psh': False}
            summary = packet.summary()
            
            if TCP in packet:
                protocol = 'TCP'
                # Parse TCP flags
                tcp_flags = packet[TCP].flags
                if 'S' in tcp_flags: flags['syn'] = True
                if 'A' in tcp_flags: flags['ack'] = True
                if 'F' in tcp_flags: flags['fin'] = True
                if 'R' in tcp_flags: flags['rst'] = True
                if 'P' in tcp_flags: flags['psh'] = True
            elif UDP in packet:
                protocol = 'UDP'
            elif ICMP in packet:
                protocol = 'ICMP'
            elif packet.haslayer(Ether) and packet[Ether].type == 0x86dd:
                protocol = 'IPv6'

            # Build the JSON object exactly as the Node.js backend expects
            pkt_data = {
                "timestamp": int(time.time() * 1000),
                "sourceIp": src_ip,
                "destinationIp": dst_ip,
                "protocol": protocol,
                "packetSize": size,
                "tcpFlags": flags,
                "summary": summary[:50]
            }
            
            # Print as JSON on a single line so Node.js can parse it easily
            print(json.dumps(pkt_data), flush=True)
    except Exception as e:
        # Silently ignore packets that can't be parsed
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scapy Packet Sniffer for XRL-IDARS")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to sniff on")
    parser.add_argument('-f', '--filter', required=False, default="", help="BPF filter string")
    
    args = parser.parse_args()
    
    # Notify backend that we're starting
    print(json.dumps({"status": "started", "interface": args.interface, "filter": args.filter}), flush=True)
    
    try:
        sniff(iface=args.interface, filter=args.filter, prn=packet_callback, store=0)
    except Exception as e:
        print(json.dumps({"error": str(e)}), flush=True)
        sys.exit(1)
