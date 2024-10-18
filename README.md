1.Importing Scapy:

>from scapy.all import *: This imports all necessary functions from Scapy.

2.Packet Callback Function:

>packet_callback(packet): This function is called for each captured packet.

>It extracts the source IP, destination IP, protocol, and payload from each packet and prints them.

3.Main Function:

>sniff(filter="ip", prn=packet_callback, store=0): This starts sniffing for IP packets and calls packet_callback for each packet. The store=0 option ensures packets are not stored in memory, preventing high memory usage.

#Ethical Considerations:
>Permission: Always ensure you have explicit permission to capture network traffic on the network you are monitoring.

>Usage: Use this tool for educational purposes only. Unauthorized packet sniffing is illegal and unethical.
