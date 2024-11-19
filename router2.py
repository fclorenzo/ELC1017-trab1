#router2.py
import time
import threading
from threading import Lock
from scapy.all import send, sniff, IP
from wtsp import Wtsp
from forward import forward_packet

# Hardcoded router configuration
router_id = "10.2.2.2"
neighbors = ["10.1.2.1"]
sniff_ifaces = ["r2-eth0", "r2-eth1"]

# Initialize routing table with directly connected networks
routing_table = {
    "10.2.2.0/24": {"next_hop": router_id, "hop_count": 0, "sequence": 0},
    "10.1.1.0/24": {"next_hop": "10.1.2.1", "hop_count": 0, "sequence": 0},
}

# Initialize a lock to control access to the routing table
routing_table_lock = Lock()

# Interface mapping
interface_mapping = {
    "r2-eth0": "10.2.2.0/24",
    "r2-eth1": "10.1.2.0/24",
}

print(f"Initialized routing table for router {router_id}:")
for dest, info in routing_table.items():
    print(f"Destination: {dest}, Next Hop: {info['next_hop']}, Hop Count: {info['hop_count']}")

# Function to send routing updates to neighbors
def send_routing_update():
    with routing_table_lock:  # Acquire lock to safely access routing_table
        for dest, route_info in routing_table.items():
            for neighbor_ip in neighbors:
                packet = IP(dst=neighbor_ip) / Wtsp(
                    router_id=router_id,
                    next_hop=route_info["next_hop"],
                    destination=dest,
                    hop_count=route_info["hop_count"] + 1,  # Increment hop count
                    sequence=route_info["sequence"]
                )
                send(packet)
                print(f"Sent routing update to {neighbor_ip} for destination {dest}")

# Periodic update function that runs in a loop
def update_loop():
    while True:
        send_routing_update()
        time.sleep(10)  # Update interval

# Function to process incoming WTSP packets
def process_routing_update(packet):
    if Wtsp in packet:
        # Extract routing data from WTSP packet
        received_router_id = packet[Wtsp].router_id
        destination = packet[Wtsp].destination
        next_hop = received_router_id
        hop_count = packet[Wtsp].hop_count
        sequence = packet[Wtsp].sequence

        # Use the lock when updating routing_table
        with routing_table_lock:
            # Check if we should update the routing table
            if destination not in routing_table or \
               routing_table[destination]["hop_count"] > hop_count or \
               routing_table[destination]["sequence"] < sequence:
                routing_table[destination] = {
                    "next_hop": next_hop,
                    "hop_count": hop_count,
                    "sequence": sequence
                }
                print(f"Updated route to {destination}: {routing_table[destination]}")

# Sniff WTSP packets to receive routing updates on specified interfaces
def receive_routing_updates():
    sniff(filter="ip proto 42", prn=process_routing_update, iface=sniff_ifaces)

# Sniff and forward packets
def packet_forwarding_loop():
    sniff(filter="ip", prn=lambda pkt: forward_packet(pkt, routing_table, interface_mapping), iface=sniff_ifaces)

print(f"Router {router_id}: Starting forwarding loop...")

# Start the periodic update and receiving functions in separate threads
threading.Thread(target=update_loop).start()
threading.Thread(target=receive_routing_updates).start()
threading.Thread(target=packet_forwarding_loop, daemon=True).start()