from scapy.all import *

#Wonderful Table Sharing Protocol
class Wtsp(Packet):
    name = "WTSP"

    fields_desc = [
        IntField("router_id", 0),
        IPField("destination", "0.0.0.0"),
        IntField("metric", 0),
        IntField("sequence", 0),
        FieldLenField("len", None, fmt="!H", length_of=0),

    ]

bind_layers(IP, Wtsp, proto=42)  # Protocol 42 for custom use

    # This method tells Scapy that the next packet must be decoded with WTSP
def guess_payload_class(self, payload):
        return Wtsp
