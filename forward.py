#Forward.py
from scapy.all import sendp, Ether, IP, ARP, sr1
from threading import Lock
import ipaddress

# Initialize a MAC cache (shared between routers)
mac_cache = {}
routing_table_lock = Lock()

def get_iface_for_next_hop(next_hop_ip, interface_mapping):
    """
    Determine the correct interface for the next hop IP based on the interface mapping.
    """
    for iface, network in interface_mapping.items():
        net = ipaddress.ip_network(network, strict=False)
        if ipaddress.ip_address(next_hop_ip) in net:
            return iface
    return None

def resolve_next_hop_mac(next_hop_ip, iface):
    """
    Resolve the MAC address for the next hop using ARP.
    """
    if next_hop_ip in mac_cache:
        return mac_cache[next_hop_ip]
    
    # Send ARP request
    print(f"Resolving MAC for {next_hop_ip} on interface {iface}")
    arp_request = ARP(pdst=next_hop_ip)
    arp_response = sr1(arp_request, iface=iface, timeout=2, verbose=False)
    
    if arp_response:
        mac_cache[next_hop_ip] = arp_response.hwsrc
        print(f"Resolved MAC for {next_hop_ip}: {arp_response.hwsrc}")
        return arp_response.hwsrc
    else:
        print(f"Failed to resolve MAC for {next_hop_ip}")
    return None

def forward_packet(packet, routing_table, interface_mapping):
    """
    Forward a packet based on the routing table.
    """
    if IP in packet:
        dest_ip = packet[IP].dst

        with routing_table_lock:
            for network, info in routing_table.items():
                net = ipaddress.ip_network(network, strict=False)
                if ipaddress.ip_address(dest_ip) in net:
                    next_hop = info["next_hop"]

                    # Get the correct interface for the next hop
                    iface = get_iface_for_next_hop(next_hop, interface_mapping)
                    if iface:
                        # Resolve the next hop MAC address
                        next_hop_mac = resolve_next_hop_mac(next_hop, iface)
                        if next_hop_mac:
                            # Modify packet for forwarding
                            packet[Ether].dst = next_hop_mac
                            sendp(packet, iface=iface)
                            print(f"Forwarded packet to {dest_ip} via {next_hop} on {iface}")
                        else:
                            print(f"Failed to resolve MAC for next hop {next_hop}")
                    else:
                        print(f"No interface found for next hop {next_hop}")
                    return
        print(f"No route found for {dest_ip}, dropping packet.")
