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

# Sending WTSP packet from h1 to h2
def send_wtsp():
    # Create a WTSP packet
    packet = IP(dst="10.2.2.1")/Wtsp(router_id=1, destination="10.2.2.0", metric=10, sequence=1, routing_data="Sample routing data")
    
    # Send the packet from h1
    send(packet)
    print("WTSP packet sent!")

if __name__ == "__main__":
    send_wtsp()
