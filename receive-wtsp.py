from scapy.all import *

# Define the WTSP class as previously defined
class Wtsp(Packet):
    name = "WTSP"
    fields_desc = [
        IntField("router_id", 0),
        IPField("destination", "0.0.0.0"),
        IntField("metric", 0),
        IntField("sequence", 0),
        FieldLenField("len", None, fmt="!H", length_of="routing_data"),
        StrLenField("routing_data", "", length_from=lambda pkt: pkt.len)
    ]

# Bind the WTSP protocol to IP with protocol number 42
bind_layers(IP, Wtsp, proto=42)

# Function to handle incoming packets
def packet_handler(packet):
    if Wtsp in packet:
        print("Received WTSP packet:")
        packet.show()

# Sniffing for WTSP packets on h2
def receive_wtsp():
    sniff(filter="ip proto 42", prn=packet_handler, iface="h2-eth0")

if __name__ == "__main__":
    receive_wtsp()
