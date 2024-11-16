import argparse
import time
import threading
from threading import Lock
from wtsp import Wtsp
from scapy.all import send, sendp, sniff, IP, Ether, ARP, get_if_hwaddr, sr1

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
interface_mapping = {}  # Map of interfaces to networks
mac_cache = {}  # Cache for resolved MAC addresses

# Initialize a lock to control access to the routing table
routing_table_lock = Lock()

# Helper function to derive the network address based on an IP address and netmask
def get_network_address(ip, mask):
    ip_parts = ip.split(".")
    mask_bits = int(mask.strip("/"))
    network_bits = "".join([f"{int(octet):08b}" for octet in ip_parts])[:mask_bits]
    network_bits = network_bits.ljust(32, "0")  # Fill remaining bits with 0s
    network_ip = ".".join([str(int(network_bits[i:i+8], 2)) for i in range(0, 32, 8)])
    return f"{network_ip}{mask}"

# Populate routing table with directly connected networks
router_network = get_network_address(router_id, netmask)
routing_table[router_network] = {"next_hop": router_id, "hop_count": 0, "sequence": 0}

for neighbor_ip in neighbors:
    neighbor_network = get_network_address(neighbor_ip, netmask)
    routing_table[neighbor_network] = {"next_hop": neighbor_ip, "hop_count": 1, "sequence": 0}

# Initialize interface mapping for each sniff interface
for iface in sniff_ifaces:
    interface_ip = get_if_hwaddr(iface)  # Assuming this fetches the IP assigned to the interface
    interface_mapping[iface] = get_network_address(interface_ip, netmask)

print(f"Initialized routing table for router {router_id}:")
for dest, info in routing_table.items():
    print(f"Destination: {dest}, Next Hop: {info['next_hop']}, Hop Count: {info['hop_count']}")

# Function to resolve MAC address of the next hop via ARP
def get_next_hop_mac(next_hop_ip):
    if next_hop_ip in mac_cache:
        return mac_cache[next_hop_ip]
    # Send an ARP request to resolve the MAC address
    arp_request = ARP(pdst=next_hop_ip)
    arp_response = sr1(arp_request, timeout=2, verbose=False)
    if arp_response:
        mac_cache[next_hop_ip] = arp_response.hwsrc  # Cache the MAC address
        return arp_response.hwsrc
    return None

# Function to find the correct interface for a given next hop IP
def get_iface_for_next_hop(next_hop_ip):
    for iface, network in interface_mapping.items():
        if next_hop_ip in network:
            return iface
    return None

# Function to send routing updates to neighbors
def send_routing_update():
    with routing_table_lock:
        for dest, route_info in routing_table.items():
            for neighbor_ip in neighbors:
                packet = IP(dst=neighbor_ip) / Wtsp(
                    router_id=router_id,
                    next_hop=route_info["next_hop"],
                    destination=dest,
                    hop_count=route_info["hop_count"] + 1,
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
        received_router_id = packet[Wtsp].router_id
        destination = packet[Wtsp].destination
        next_hop = received_router_id
        hop_count = packet[Wtsp].hop_count
        sequence = packet[Wtsp].sequence

        with routing_table_lock:
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

# Function to forward packets based on the routing table
def forward_packet(packet):
    if IP in packet:
        dest_ip = packet[IP].dst
        with routing_table_lock:
            for network, info in routing_table.items():
                if dest_ip in network:
                    next_hop = info["next_hop"]
                    next_hop_mac = get_next_hop_mac(next_hop)
                    iface = get_iface_for_next_hop(next_hop)

                    if next_hop_mac and iface:
                        packet[Ether].dst = next_hop_mac
                        sendp(packet, iface=iface)
                        print(f"Forwarded packet to {dest_ip} via next hop {next_hop} on {iface}")
                    else:
                        print(f"Failed to forward packet to {dest_ip}: no MAC or interface found.")
                    return
        print(f"No route to {dest_ip}; dropping packet.")

# Sniff IP packets and forward them if a route exists
def packet_forwarding_loop():
    sniff(filter="ip", prn=forward_packet, iface=sniff_ifaces)

# Start the periodic update, receiving, and forwarding functions in separate threads
threading.Thread(target=update_loop).start()
threading.Thread(target=receive_routing_updates).start()
threading.Thread(target=packet_forwarding_loop).start()
