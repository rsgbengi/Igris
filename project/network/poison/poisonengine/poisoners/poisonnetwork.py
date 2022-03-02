from loguru import logger
from typing import Tuple
from scapy.all import (
    Ether,
    IP,
    IPv6,
    packet,
)
import time
from threading import Thread


class PoisonNetwork:
    """[ Class with all the information needed to perform a poisoning attack ]

    Args:
        ip (str): [ ipv4 of the attacker ]
        ipv6 (str): [ ipv6 of the attacker ]
        mac_addres (str): [ mac_address of the attacker ]
        iface (str): [ interface for sniffing packets  ]
        info_logger (logger): [ Logger for the output ]
        level (logger): [ Logger level to display information ]
    """

    def __init__(
        self,
        ip: str,
        ipv6: str,
        mac_addres: str,
        iface: str,
        info_logger: logger,
        level: str,
    ) -> None:
        self._ip = ip
        self._ipv6 = ipv6
        self._mac_address = mac_addres
        self._iface = iface
        self._targets_used = []
        self._logger_level = level
        self._info_logger = info_logger

    @property
    def ip(self) -> str:
        return self._ip

    @property
    def mac_address(self) -> str:
        return self._mac_address

    @property
    def iface(self) -> str:
        return self._iface

    @property
    def ipv6(self) -> str:
        return self._ipv6

    @property
    def targets_used(self) -> list:
        return self._targets_used

    @property
    def logger_level(self) -> str:
        return self._logger_level

    @property
    def info_logger(self) -> logger:
        return self._info_logger

    @ipv6.setter
    def ipv6(self, ipv6: str) -> None:
        self._ipv6 = ipv6

    @ip.setter
    def ip(self, ip: str) -> None:
        self._ip = ip

    @mac_address.setter
    def mac_address(self, mac_address: str) -> None:
        self._mac_address = mac_address

    @iface.setter
    def iface(self, iface: str) -> None:
        self._iface = iface

    @targets_used.setter
    def targets_used(self, targets: list) -> None:
        self._targets_used = targets

    @logger_level.setter
    def logger_level(self, level) -> None:
        self._logger_level = level

    @info_logger.setter
    def info_logger(self, info_logger) -> None:
        self._info_logger = info_logger

    def _data_link_layer(self, pkt: packet) -> packet:
        """[ Add link layer to response packet ]

        Args:
            pkt (packet): [ sniffed packet ]

        Returns:
            [ packet ]: [ Package with link layer added ]
        """
        return Ether(dst=pkt[Ether].src, src=self._mac_address)

    def _network_layer(self, pkt: packet, response: packet) -> Tuple[packet.Type, str]:
        """[ Add network layer to the response packet ]

        Args:
            pkt (packet): [ sniffed packet ]
            response (packet): [ Packet to be send to the victim  ]

        Returns:
            Tuple[packet.Type, str]: [ malicious package and ip of the target ]
        """
        ip_of_the_packet = None
        if IP in pkt:
            if pkt[IP].src == self._ip:
                return
            response /= IP(dst=pkt[IP].src)
            ip_of_the_packet = pkt[IP].src
        elif IPv6 in pkt:
            if pkt[IPv6].src == self._ipv6:
                return
            response /= IPv6(dst=pkt[IPv6].src)
            ip_of_the_packet = pkt[IPv6].src
        return response, ip_of_the_packet

    def _start_cleaner(self):
        """[ Method to start the cleaner thread ]"""
        cleaner_thread = Thread(target=self.__cleaner)
        cleaner_thread.daemon = True
        cleaner_thread.start()

    def __cleaner(self) -> None:
        """[ Function to clean the list of objectives every 3 seconds ]"""
        while True:
            time.sleep(10)
            self.targets_used.clear()
