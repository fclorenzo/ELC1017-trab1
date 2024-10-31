# receive_wtsp.py
from scapy.all import *
from wtsp import Wtsp  # Import the Wtsp class from wtsp.py

# Function to handle received WTSP packets
def packet_handler(packet):
    if Wtsp in packet:
        print("Received WTSP packet:")
        packet.show()

# Sniff for WTSP packets
def receive_wtsp():
    sniff(filter="ip proto 42", prn=packet_handler, iface="h2-eth0")

if __name__ == "__main__":
    receive_wtsp()
