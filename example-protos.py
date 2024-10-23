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

    # This method tells Scapy that the next packet must be decoded with DNSTCP
def guess_payload_class(self, payload):
        return Wtsp

class DNSTCP(Packet):
    name = "DNS over TCP"
    
    fields_desc = [
        FieldLenField("len", None, fmt="!H", length_of="dns"),
        PacketLenField("dns", 0, DNS, length_from=lambda p: p.len)]
    
    # This method tells Scapy that the next packet must be decoded with DNSTCP
    def guess_payload_class(self, payload):
        return DNSTCP

        from scapy.all import *

# Wonderful Table Sharing Protocol
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

    # This method tells Scapy that the next packet must be decoded with WTSP
    def guess_payload_class(self, payload):
        return Wtsp

# Bind the custom protocol to IP, using protocol number 42
bind_layers(IP, Wtsp, proto=42)

# Example packet creation and sending
packet = IP(dst="192.168.1.1")/Wtsp(router_id=1, destination="10.0.0.0", metric=10, sequence=1, routing_data="Sample Data")
packet.show()
