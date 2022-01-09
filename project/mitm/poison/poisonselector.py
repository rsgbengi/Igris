#!/usr/bin/env python3
from .poisonlauncher import PoisonLauncher
import argparse
from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
from threading import Thread
from multiprocessing import Process




@with_default_category("Poisoning Attacks")
class PoisonCommand(CommandSet):
    def __init__(self):
        super().__init__()
        self.__poisoner_process = None
        self.__poison_launcher = None

    def __poison_configuration(self, args: argparse.Namespace):

        if args.mdns:
            self.__poison_launcher.activate_mdns()
        if args.nbt_ns:
            self.__poison_launcher.activate_nbt_ns()
        if args.llmnr:
            self.__poison_launcher.activate_llmnr()
        if args.dns:
            self.__poison_launcher.activate_dns()

    def __create_necessary_components(self, args: argparse.Namespace) -> None:
        """[ Method to create the necessary classes ]
        Args:
            args (argparse.Namespace): [ Arguments passed to the attack ]

        """
        self.__poison_launcher = PoisonLauncher(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
            self._cmd.info_logger,
            args.Asynchronous,
        )
        self.__poison_configuration(args)

    def __launch_poison_attack(self, args: argparse.Namespace) -> None:
        self.__create_necessary_components(args)
        self.__poison_launcher.start_poisoners()
        if not args.Asynchronous:
            self.__poison_launcher.wait_for_the_poisoners()

    def __wrapper_attack(self, args: argparse.Namespace) -> None:
        self.__poisoner_process = Process(target=self.__launch_poison_attack, args=args)
        try:
            self.__poisoner_process.start()
            if not args.Asynchronous:
                self.__poisoner_process.join()
        except KeyboardInterrupt:
            self.__poisoner_process.terminate()
            self.__poisoner_process.join()

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

    poison_options = argParser.add_argument_group(" Options to select the poisoners")
    poison_options.add_argument(
        "-L",
        "--llmnr",
        action="store_true",
        help="To use llmnr poisoning",
    )
    poison_options.add_argument(
        "-M",
        "--mdns",
        action="store_true",
        help="To use MDNS poisoning",
    )
    poison_options.add_argument(
        "-N",
        "--nbt_ns",
        action="store_true",
        help="To use NBT_NS poisoning",
    )
    poison_options.add_argument(
        "-D",
        "--domain",
        action="store_true",
        help="To use DNS poisoning",
    )


    def do_poison(self, args: argparse.Namespace) -> None:
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
            self.__wrapper_attack(args)

    def poison_postloop(self) -> None:
        """[method to stop the attack before the application is terminated]"""
        if self.__poison_process is not None and self.__poison_process:
            self.__poison_process.terminate()
            self.__poison_process.join()
