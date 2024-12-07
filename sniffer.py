from scapy.all import sniff, TCP, IP, Raw
import logging
from database import save_packet

sniffing = True

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        logging.info(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}, Protocol: {ip_layer.proto}")
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            logging.info(f"Captured packet: {packet.summary()}")
            logging.info(f"Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}, Flags: {tcp_layer.flags}")

            payload = None
            if Raw in packet:
                payload = packet[Raw].load
                logging.info(f"Payload: {payload}")

            save_packet(ip_layer.src, ip_layer.dst, ip_layer.proto, tcp_layer.sport, tcp_layer.dport, payload)

def start_sniffing(interface="eth0", filter="ip"):
    global sniffing
    try:
        logging.info(f"Starting packet sniffing on interface: {interface} with filter: {filter}")
        sniff(iface=interface, prn=packet_handler, filter=filter, stop_filter=lambda x: not sniffing)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
