# send_wtsp.py
from scapy.all import *
from wtsp import Wtsp  # Import the Wtsp class from wtsp.py

# Function to send WTSP packet from h1 to h2
def send_wtsp():
    # Create a WTSP packet with the new fields
    packet = IP(dst="10.2.2.1") / Wtsp(
        router_id="10.1.1.254",     # Set router ID
        destination="10.2.2.0/24",  # Destination network
        hop_count=1,                # Hop count
        sequence=1,                 # Sequence number
        next_hop="10.2.2.254"       # Next hop IP
    )
    
    # Send the packet
    send(packet)
    print("WTSP packet sent!")

if __name__ == "__main__":
    send_wtsp()
