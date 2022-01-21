#!/usr/bin/env python3
import sys
import signal
from .poisonengine import PoisonLauncher
import argparse
from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
from threading import Thread
from multiprocessing import Process
from ipaddress import IPv6Network, AddressValueError


@with_default_category("Spoofing Attacks")
class DNSTakeOverCommand(CommandSet):
    def __init__(self):
        super().__init__()
        self.__dnstakeover_process = None
        self.__poison_launcher = None

    def __poison_configuration(self) -> None:
        """[ Method to configure the dhcp6 rogue attack ]"""
        self.__poison_launcher.activate_dhcp6()
        self._cmd.active_attacks_configure("DHCP6_Rogue", True)

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
            args.domain,
            args.mask,
        )
        self.__poison_configuration()

    def __async_options(self) -> None:
        """[ Configuration in case of an asynchronous attack ]"""
        sys.stdout = open("/dev/null", "w")
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def __launch_attack(self, args: argparse.Namespace) -> None:
        if args.Asynchronous:
            self.__async_options()
        self.__poison_launcher.start_poisoners()
        self.__poison_launcher.wait_for_the_poisoners()

    def __end_process_in_the_background(self) -> None:
        """[ Method to stop the attack by the user ]"""
        if (
            self.__dnstakeover_process is not None
            and self.__dnstakeover_process.is_alive
        ):
            self._cmd.info_logger.success("Finishing attack in the background ...")
            self.__dnstakeover_process.terminate()
            self.__dnstakeover_process.join()
            self.__dnstakeover_process = None

            self._cmd.active_attacks_configure("DHCP6_Rogue", False)
        else:
            self._cmd.error_logger.warning("The attack is not activated")

    def __checking_conditions_for_attack(self, args: argparse.Namespace) -> None:
        """[ Method to check if the attack cant be performed]

        Args:
            args (argparse.Namespace): [ Arguments passed to the attack ]
        """
        if args.end_attack:
            self.__end_process_in_the_background()
            return False
        if self.__dnstakeover_process is not None:
            self._cmd.error_logger.warning(
                "The attack is already running in the background"
            )
            return False
        if args.mask == None:
            self._cmd.error_logger.error(
                "Error: the following arguments are required: -M/--mask"
            )
            return False
        if args.domain == None:
            self._cmd.error_logger.error(
                "Error: the following arguments are required: -DOM/--domain"
            )
        try:
            IPv6Network(args.mask)
        except AddressValueError:
            self._cmd.error_logger.error("Mask invalid")
            return False

        return True

    def __wrapper_attack(self, args: argparse.Namespace) -> None:
        """[ Method to prepare the attack ]

        Args:
            args (argparse.Namespace): [ Arguments passed to the attack ]
        """

        self.__dnstakeover_process = Process(target=self.__launch_attack, args=(args,))
        try:
            self.__dnstakeover_process.start()
            if not args.Asynchronous:
                self.__dnstakeover_process.join()
        except KeyboardInterrupt:
            self.__dnstakeover_process.terminate()
            self.__dnstakeover_process.join()
            self.__dnstakeover_process = None
            self._cmd.active_attacks_configure("DHCP6_Rogue", False)

    argParser = Cmd2ArgumentParser(
        description="""Command to perform dns takeover over ipv6 using dhcp6 rogue.""",
        epilog = "This command is not designed to use pipes(|) or redirections( >< ) when poisoners are invoked"

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
    attack_options = argParser.add_argument_group(" Options to modify attack behavior")
    attack_options.add_argument(
        "-E",
        "--end_attack",
        action="store_true",
        help="End the attack in the background process",
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
        "-DOM",
        "--domain",
        action="store",
        type=str,
        required=False,
        help="Target domain: Ej: domain.local",
    )
    attack_options.add_argument(
        "-M",
        "--mask",
        action="store",
        type=str,
        required=False,
        help="IPv6 mask: Ej: fe80::/64",
    )

    @with_argparser(argParser)
    def do_dns_takeover(self, args: argparse.Namespace) -> None:
        """[ Command to perform dns takeover over ipv6 attack ]

        Args:
            args (argparse.Namespace): [Arguments passed to the attack ]
        """
        self._cmd.info_logger.debug(
            f"""Starting dns takeover attack using lhost: {self._cmd.LHOST} rhost:{self._cmd.RHOST} ipv6:{self._cmd.IPV6}
            interface: {self._cmd.INTERFACE} mac_address:{self._cmd.MAC_ADDRESS}"""
        )
        if not (self.__checking_conditions_for_attack(args)):
            return

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

            self.__create_necessary_components(args)
            self.__wrapper_attack(args)

    def dnstakeover_postloop(self) -> None:
        """[method to stop the attack before the application is terminated]"""
        if self.__dnstakeover_process is not None and self.__dnstakeover_process:
            self.__dnstakeover_process.terminate()
            self.__dnstakeover_process.join()
