#!/usr/bin/env python3
from .poisonengine import PoisonLauncher
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

    def __mdns_configuration(self, args: argparse.Namespace) -> None:
        if args.mdns and not self._cmd.active_attacks_status("MDNS_Poisoning"):
            self.__poison_launcher.activate_mdns()
            self._cmd.active_attacks_configure("MDNS_Poisoning", True)
        else:
            self._cmd.error_logger.warning(
                "The mdns poisoning is already being used by another process"
            )

    def __nbt_ns_configuration(self, args: argparse.Namespace) -> None:
        if args.nbt_ns and not self._cmd.active_attacks_status("NBT_NS_Poisoning"):
            self.__poison_launcher.activate_nbt_ns()
            self._cmd.active_attacks_configure("NBT_NS_Poisoning", True)
        else:
            self._cmd.error_logger.warning(
                "The nbt_ns poisoning is already being used by another process"
            )

    def __llmnr_configuration(self, args: argparse.Namespace) -> None:
        if args.llmnr and not self._cmd.active_attacks_status("LLMNR_Poisoning"):
            self.__poison_launcher.activate_llmnr()
            self._cmd.active_attacks_configure("LLMNR_Poisoning", True)
        else:
            self._cmd.error_logger.warning(
                "The llmnr poisoning is already being used by another process"
            )

    def __dns_configuration(self, args: argparse.Namespace) -> None:
        if args.dns and not self._cmd.active_attacks_status("DNS_Poisoning"):
            self.__poison_launcher.activate_dns()
            self._cmd.active_attacks_configure("DNS_Poisoning", True)
        else:
            self._cmd.error_logger.warning(
                "The dns poisoning is already being used by another process"
            )

    def __poison_configuration(self, args: argparse.Namespace):
        self.__mdns_configuration(args)
        self.__nbt_ns_configuration(args)
        self.__llmnr_configuration(args)
        self.__dns_configuration(args)

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

    def __end_process_in_the_background(self):
        """[ Method to stop the attack by the user ]"""
        if self.__poisoner_process is not None and self.__poisoner_process.is_alive:
            self._cmd.info_logger.success("Finishing attack in the background ...")
            self.__poisoner_process.terminate()
            self.__poisoner_process.join()
            self.__poisoner_process = None

    def __launch_poison_attack(self, args: argparse.Namespace) -> None:
        self.__create_necessary_components(args)
        self.__poison_launcher.start_poisoners()
        if not args.Asynchronous:
            self.__poison_launcher.wait_for_the_poisoners()

    def __checking_conditions_for_attack(self, args: argparse.Namespace):
        if args.end_attack:
            self.__end_process_in_the_background()
            return False
        if self.__poisoner_process is not None:
            self._cmd.error_logger.warning(
                "The attack is already running in the background"
            )
            return False

        return True

    def __wrapper_attack(self, args: argparse.Namespace) -> None:
        self.__poisoner_process = Process(
            target=self.__launch_poison_attack, args=(args,)
        )
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

    attack_options = argParser.add_argument_group(" Options to modify attack behavior")
    attack_options.add_argument(
        "-E",
        "--end_attack",
        action="store_true",
        help="End the attack in the background process",
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
        "--dns",
        action="store_true",
        help="To use DNS poisoning",
    )

    @with_argparser(argParser)
    def do_poison(self, args: argparse.Namespace) -> None:
        """[ Command to perform mdns poisoning attack ]

        Args:
            args (argparse.Namespace): [Arguments passed to the mdns poisoning attack ]
        """
        self._cmd.info_logger.debug(
            f"""Starting mdns poisoning attack using lhost: {self._cmd.LHOST} rhost:{self._cmd.RHOST} ipv6:{self._cmd.IPV6}
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
            self.__wrapper_attack(args)

    def poison_postloop(self) -> None:
        """[method to stop the attack before the application is terminated]"""
        if self.__poisoner_process is not None and self.__poisoner_process:
            self.__poisoner_process.terminate()
            self.__poisoner_process.join()
