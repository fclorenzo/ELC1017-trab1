from scapy.all import get_if_addr, send, IP
from wtsp import Wtsp
import time
import threading

# Retrieve router's own IP
router_ip = get_if_addr('r-eth1')  # Adjust the interface name as needed
print(f"This router's IP: {router_ip}")

# Define routing table and neighbors based on IP scheme
# Example assumes neighbors are predictable (next IP in subnet)
# E.g., if router IP is 10.1.1.1, neighbor IP could be 10.1.1.2
neighbors = [f"10.1.1.{int(router_ip.split('.')[-1]) + 1}"]

routing_table = {
    "10.2.2.0/24": {"next_hop": "10.2.2.254", "hop_count": 1, "sequence": 1}
}

# Function to send routing updates to neighbors
def send_routing_update():
    for dest, route_info in routing_table.items():
        for neighbor_ip in neighbors:
            packet = IP(dst=neighbor_ip) / Wtsp(
                router_id=router_ip,
                next_hop=route_info["next_hop"],
                destination=dest,
                hop_count=route_info["hop_count"],
                sequence=route_info["sequence"]
            )
            send(packet)
            print(f"Routing update sent to {neighbor_ip} for destination {dest}")

# Periodic update function
def update_loop():
    while True:
        send_routing_update()
        time.sleep(5)  # Update interval

# Start the periodic update in a separate thread
threading.Thread(target=update_loop).start()
