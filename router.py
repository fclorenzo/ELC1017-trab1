import argparse
import time
import threading
from scapy.all import send, sniff, IP
from wtsp import Wtsp

# Parse command-line arguments for router configuration
parser = argparse.ArgumentParser()
parser.add_argument("--router_id", required=True, help="Router's IP address for identification")
parser.add_argument("--neighbors", required=True, help="Comma-separated list of neighbor IPs")
parser.add_argument("--netmask", required=True, help="Subnet mask, e.g., /24 or /30")
parser.add_argument("--sniff_ifaces", required=True, help="Comma-separated list of interfaces to sniff")
args = parser.parse_args()

# Assign router_id, neighbors, netmask, and sniff interfaces from arguments
router_id = args.router_id
neighbors = args.neighbors.split(",")
netmask = args.netmask
sniff_ifaces = args.sniff_ifaces.split(",")  # Split comma-separated interfaces into a list

# Initialize routing table with directly connected networks
routing_table = {}

# Helper function to derive the network address based on an IP address and netmask
def get_network_address(ip, mask):
    ip_parts = ip.split(".")
    mask_bits = int(mask.strip("/"))
    network_bits = "".join([f"{int(octet):08b}" for octet in ip_parts])[:mask_bits]
    network_bits = network_bits.ljust(32, "0")  # Fill remaining bits with 0s
    network_ip = ".".join([str(int(network_bits[i:i+8], 2)) for i in range(0, 32, 8)])
    return f"{network_ip}{mask}"

# Populate routing table with directly connected networks
# Add the router's own network as directly connected
router_network = get_network_address(router_id, netmask)
routing_table[router_network] = {"next_hop": router_id, "hop_count": 0, "sequence": 0}

# Add each neighbor as a directly connected network
for neighbor_ip in neighbors:
    neighbor_network = get_network_address(neighbor_ip, netmask)
    routing_table[neighbor_network] = {"next_hop": neighbor_ip, "hop_count": 1, "sequence": 0}

print(f"Initialized routing table for router {router_id}:")
for dest, info in routing_table.items():
    print(f"Destination: {dest}, Next Hop: {info['next_hop']}, Hop Count: {info['hop_count']}")

# Function to send routing updates to neighbors
def send_routing_update():
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
        time.sleep(5)  # Update interval

# Function to process incoming WTSP packets
def process_routing_update(packet):
    if Wtsp in packet:
        # Extract routing data from WTSP packet
        received_router_id = packet[Wtsp].router_id
        destination = packet[Wtsp].destination
        next_hop = received_router_id
        hop_count = packet[Wtsp].hop_count
        sequence = packet[Wtsp].sequence

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

# Start the periodic update and receiving functions in separate threads
threading.Thread(target=update_loop).start()
threading.Thread(target=receive_routing_updates).start()
