from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        payload = packet[IP].payload

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {proto}")
        print(f"Payload: {payload}")
        print("-" * 50)

def main():
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
