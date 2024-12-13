from scapy.all import sniff, TCP, IP, Raw
import logging
import argparse
import signal
import sys
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


DATABASE_URL = "sqlite:///packets.db" 
Base = declarative_base()

class Packet(Base):
    __tablename__ = 'packets'
    
    id = Column(Integer, primary_key=True)
    source_ip = Column(String)
    destination_ip = Column(String)
    protocol = Column(String)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    payload = Column(String)


engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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


def save_packet(source_ip, destination_ip, protocol, source_port, destination_port, payload):
    packet = Packet(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=str(protocol),
        source_port=source_port,
        destination_port=destination_port,
        payload=payload.decode('utf-8', errors='ignore') if payload else None
    )
    session.add(packet)
    session.commit()
    logging.info("Packet saved to database.")


def start_sniffing(interface="eth0", filter="ip"):
    global sniffing
    try:
        logging.info(f"Starting packet sniffing on interface: {interface} with filter: {filter}")
        sniff(iface=interface, prn=packet_handler, filter=filter, stop_filter=lambda x: not sniffing)
    except Exception as e:
        logging.error(f"An error occurred: {e}")


def signal_handler(sig, frame):
    global sniffing
    logging.info("Stopping packet sniffing...")
    sniffing = False
    session.close() 
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter to apply")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    start_sniffing(interface=args.interface, filter=args.filter)
