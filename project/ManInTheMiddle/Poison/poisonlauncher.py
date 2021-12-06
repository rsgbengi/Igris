#!/usr/bin/env python3
from loguru import logger
from .poisoners import MDNS, NBT_NS, LLMNR
from threading import Thread


class PoisonLauncher:
    def __init__(
        self,
        ip: str,
        ipv6: str,
        mac_address: str,
        iface: str,
        info_logger: logger,
        asynchronous: bool,
        poisoner_selector:dict

    ):
        self.__ip = ip
        self.__ipv6 = ipv6
        self.__mac_address = mac_address
        self.__iface = iface
        self.__info_logger = info_logger
        self.__asynchronous = asynchronous
        self.__poisoner_selector=poisoner_selector

        self.__create_mdns()
        self.__create_nbt_ns()
        self.__create_llmnr()

    def __create_mdns(self):
        self.__mdns_poisoner = MDNS(
            self.__ip,
            self.__ipv6,
            self.__mac_address,
            self.__iface,
            self.__info_logger,
        )

        if self.__asynchronous:
            self.__mdns_poisoner.logger_level = "DEBUG"

    def __create_nbt_ns(self):
        self.__nbt_ns_poisoner = NBT_NS(
            self.__ip,
            self.__mac_address,
            self.__iface,
            self.__info_logger,
        )
        if self.__asynchronous:
            self.__nbt_ns_poisoner.logger_level = "DEBUG"


    def __create_llmnr(self):
        self.__llmnr_poisoner = LLMNR(
            self.__ip,
            self.__ipv6,
            self.__mac_address,
            self.__iface,
            self.__info_logger,
        )
        if self.__asynchronous:
            self.__llmnr_poisoner.logger_level = "DEBUG"
    def __start_mdns(self):
        mdns_thread = Thread(target=self.__mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True
        mdns_thread.start()

    def __start_llmnr(self):
        llmnr_thread = Thread(target=self.__llmnr_poisoner.start_llmnr_poisoning)
        llmnr_thread.daemon = True
        llmnr_thread.start()
    def __start_nbt_ns(self):
        nbt_ns_thread = Thread(target=self.__nbt_ns_poisoner.start_nbt_ns_poisoning)
        nbt_ns_thread.daemon = True
        nbt_ns_thread.start()

    def start_poisoners(self):
        if self.__poisoner_selector["MDNS"] == 1:
            self.__start_mdns()
        if self.__poisoner_selector["LLMNR"]  == 1:
            self.__start_llmnr()
        if(self.__poisoner_selector["NBT_NS"]) == 1:
            self.__start_nbt_ns()

