import argparse
import logging
import signal
import sys
from sniffer import start_sniffing
from logger import setup_logging


def signal_handler(sig, frame):
    logging.info("Stopping packet sniffing...")
    sys.exit(0)


if __name__ == "__main__":
    setup_logging()
    
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter to apply")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    start_sniffing(interface=args.interface, filter=args.filter)
