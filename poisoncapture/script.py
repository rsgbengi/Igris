from scapy.all import * 
def llmnr():
    p = rdpcap('responder.pcapng')
    
    for pkt in p:
        if UDP in pkt:
            if pkt[UDP].sport==5355 or pkt[UDP].dport==5355:
                pkt.show()
def nbt_ns():
    p = rdpcap('responder.pcapng')
    for pkt in p:
        if UDP in pkt:
            if pkt[UDP].sport==137 or pkt[UDP].dport==135:
                pkt.show()
def mdns():
    p = rdpcap('responder.pcapng')
    for pkt in p:
        if UDP in pkt:
            if pkt[UDP].sport==5353 or pkt[UDP].dport==5353:
                pkt.show()
def dns():
    p = rdpcap('responder.pcapng')
    for pkt in p:
        if UDP in pkt:
            if pkt[UDP].sport==53 or pkt[UDP].dport==53:
                pkt.show()
def dhcp():
    p = rdpcap('dhcp.pcapng')
    for pkt in p:
        pkt.show()

def dhcp2():
    p = rdpcap('dhcp2.pcapng')
    for pkt in p:
        pkt.show()
def dhcpi():
    p = rdpcap('igrisdhcp.pcapng')
    for pkt in p:
        pkt.show()


#ns()
#dns()
#llmnr()
#nbt_ns()
#dhcp()
#dhcpi()
dhcp2()

