from scapy.all import *

# Wonderful Table Sharing Protocol
class Wtsp(Packet):
    name = "WTSP"

    fields_desc = [
        IPField("router_id", "0.0.0.0"),           # Router ID sending the update
        IPField("destination", "0.0.0.0/0"),       # Destination network
        IntField("hop_count", 0),                  # Hop count to the destination
        IntField("sequence", 0),                   # Sequence number for versioning
        IPField("next_hop", "0.0.0.0")             # Next hop for the destination
    ]

    #Don't uncomment
    # Method to interpret the next packet as WTSP
    #def guess_payload_class(self, payload):
        #return Wtsp

# Bind WTSP to IP layer with protocol number 42
bind_layers(IP, Wtsp, proto=42)
